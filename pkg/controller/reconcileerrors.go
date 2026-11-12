/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/client-go/util/workqueue"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
)

// ErrorCategory classifies a reconcile error into one of four recovery
// classes. Classification only inspects the error's cause chain (with
// errors.Is / errors.As); the original error is never wrapped, replaced or
// consumed.
type ErrorCategory string

const (
	// ErrorCategoryPermanent covers failures where the request itself is
	// fundamentally rejected (bad request, invalid object, unsupported
	// verb, ...). An unchanged retry cannot succeed; recovery requires the
	// object to change.
	ErrorCategoryPermanent ErrorCategory = "permanent"

	// ErrorCategoryRetryable covers transient failures (API server
	// throttling, 5xx responses, network errors, conflicts, context
	// cancellation, ...). Backing off and retrying is the expected recovery.
	ErrorCategoryRetryable ErrorCategory = "retryable"

	// ErrorCategoryDependencyWait covers failures caused by a referenced
	// object being absent or not yet observed (missing Secret, not-yet
	// created dependency, ...). The key is retried until the dependency
	// becomes available.
	ErrorCategoryDependencyWait ErrorCategory = "dependency_wait"

	// ErrorCategoryConfiguration covers failures caused by credentials,
	// RBAC or invalid data carried by the managed resources. Recovery
	// requires the user to fix the configuration rather than waiting.
	ErrorCategoryConfiguration ErrorCategory = "configuration"
)

// Machine-readable classification reasons. They stay stable so that report
// sinks (logs, metrics, alerting) can key on them.
const (
	reasonContextCanceled         = "ContextCanceled"
	reasonContextDeadlineExceeded = "ContextDeadlineExceeded"
	reasonNetworkError            = "NetworkError"
	reasonOptimisticLock          = "OptimisticLock"
	reasonConflict                = "Conflict"
	reasonNotFound                = "NotFound"
	reasonAlreadyExists           = "AlreadyExists"
	reasonUnauthorized            = "Unauthorized"
	reasonForbidden               = "Forbidden"
	reasonInvalidData             = "InvalidData"
	reasonBadRequest              = "BadRequest"
	reasonInvalid                 = "Invalid"
	reasonMethodNotSupported      = "MethodNotSupported"
	reasonNotAcceptable           = "NotAcceptable"
	reasonUnsupportedMediaType    = "UnsupportedMediaType"
	reasonRequestEntityTooLarge   = "RequestEntityTooLarge"
	reasonGone                    = "Gone"
	reasonResourceExpired         = "ResourceExpired"
	reasonTooManyRequests         = "TooManyRequests"
	reasonServiceUnavailable      = "ServiceUnavailable"
	reasonTimeout                 = "Timeout"
	reasonServerTimeout           = "ServerTimeout"
	reasonInternalError           = "InternalError"
	reasonUnexpectedServerError   = "UnexpectedServerError"
	reasonStoreReadError          = "StoreReadError"
	reasonUnknown                 = "Unknown"
)

// ClassifyError maps a reconcile error onto an ErrorCategory plus a
// machine-readable reason by walking the error's cause chain. The error is
// never modified or wrapped, so callers keep matching on it with errors.Is
// and errors.As. A nil error yields empty category and reason.
//
// The ordering of the checks is deliberate: lifecycle errors (context
// cancellation / deadline) and transport errors win over API status codes,
// and the optimistic-lock special case keeps parity with the worker's
// existing requeue handling.
func ClassifyError(err error) (ErrorCategory, string) {
	if err == nil {
		return "", ""
	}

	switch {
	case errors.Is(err, context.Canceled):
		// Controller shutdown or leader election loss: in-flight reconciles
		// return context.Canceled. The queue is shut down alongside the
		// workers, so nothing is actually retried here; the next leader
		// re-drives the key.
		return ErrorCategoryRetryable, reasonContextCanceled

	case errors.Is(err, context.DeadlineExceeded):
		return ErrorCategoryRetryable, reasonContextDeadlineExceeded
	}

	// Transport-layer failures (DNS, TCP reset, TLS handshake, ...) are
	// transient regardless of how deeply they are wrapped.
	if _, ok := errors.AsType[net.Error](err); ok {
		return ErrorCategoryRetryable, reasonNetworkError
	}

	// Keep in sync with the optimistic-lock branch in controller.worker:
	// the API server surfaces server-side apply conflicts as a plain error
	// message rather than a typed status error.
	if strings.Contains(err.Error(), genericregistry.OptimisticLockErrorMsg) {
		return ErrorCategoryRetryable, reasonOptimisticLock
	}

	switch {
	// The object (or one of its dependencies) is absent or not yet
	// observable from the informer cache.
	case apierrors.IsNotFound(err):
		return ErrorCategoryDependencyWait, reasonNotFound
	case apierrors.IsAlreadyExists(err):
		return ErrorCategoryDependencyWait, reasonAlreadyExists

	// Authentication / authorization failures point at credentials or RBAC
	// configuration rather than at a transient API server condition.
	case apierrors.IsUnauthorized(err):
		return ErrorCategoryConfiguration, reasonUnauthorized
	case apierrors.IsForbidden(err):
		return ErrorCategoryConfiguration, reasonForbidden

	// cert-manager signals malformed key material / PEM data with its own
	// invalidDataError; this is always a configuration problem.
	case cmerrors.IsInvalidData(err):
		return ErrorCategoryConfiguration, reasonInvalidData

	// Requests the API server rejects on their merits: retrying the same
	// request unchanged cannot succeed.
	case apierrors.IsBadRequest(err):
		return ErrorCategoryPermanent, reasonBadRequest
	case apierrors.IsInvalid(err):
		return ErrorCategoryPermanent, reasonInvalid
	case apierrors.IsMethodNotSupported(err):
		return ErrorCategoryPermanent, reasonMethodNotSupported
	case apierrors.IsNotAcceptable(err):
		return ErrorCategoryPermanent, reasonNotAcceptable
	case apierrors.IsUnsupportedMediaType(err):
		return ErrorCategoryPermanent, reasonUnsupportedMediaType
	case apierrors.IsRequestEntityTooLargeError(err):
		return ErrorCategoryPermanent, reasonRequestEntityTooLarge
	case apierrors.IsGone(err):
		return ErrorCategoryPermanent, reasonGone
	case apierrors.IsResourceExpired(err):
		return ErrorCategoryPermanent, reasonResourceExpired

	// Transient API server conditions: throttle, overload, timeouts and
	// internal errors are expected to clear on their own.
	case apierrors.IsTooManyRequests(err):
		return ErrorCategoryRetryable, reasonTooManyRequests
	case apierrors.IsServiceUnavailable(err):
		return ErrorCategoryRetryable, reasonServiceUnavailable
	case apierrors.IsTimeout(err):
		return ErrorCategoryRetryable, reasonTimeout
	case apierrors.IsServerTimeout(err):
		return ErrorCategoryRetryable, reasonServerTimeout
	case apierrors.IsInternalError(err):
		return ErrorCategoryRetryable, reasonInternalError
	case apierrors.IsUnexpectedServerError(err):
		return ErrorCategoryRetryable, reasonUnexpectedServerError
	case apierrors.IsStoreReadError(err):
		return ErrorCategoryRetryable, reasonStoreReadError
	case apierrors.IsConflict(err):
		// A non-optimistic-lock conflict (e.g. concurrent writers) resolves
		// itself once the informer observes the newer resource version.
		return ErrorCategoryRetryable, reasonConflict
	}

	// Preserve the historical default: unknown errors are retried.
	return ErrorCategoryRetryable, reasonUnknown
}

// KeyPriority is an advisory ranking for the next processing of a failed
// workqueue key. The Kubernetes workqueue itself stays FIFO with rate-limiter
// delays; this priority only expresses how urgently the key should be driven
// again and is consumed by report sinks.
type KeyPriority int

const (
	// KeyPriorityHigh means the key should be re-driven as soon as the
	// backoff allows (dependency appeared, controller restart / leader
	// switch).
	KeyPriorityHigh KeyPriority = 100
	// KeyPriorityNormal is the default ranking for a transient failure that
	// is still inside its exponential backoff window.
	KeyPriorityNormal KeyPriority = 50
	// KeyPriorityLow means retrying is unlikely to help on its own: the
	// failure is permanent / configuration-driven or the backoff has
	// already saturated.
	KeyPriorityLow KeyPriority = 10
)

// maxRetryableAttempts is the failure count at which a retryable key has
// reached the rate limiter's maximum delay and is deprioritised.
const maxRetryableAttempts = 10

// NextPriority computes the advisory priority of the next key processing
// from the error category, the number of requeues observed so far and whether
// the reconcile was interrupted by context cancellation (shutdown / leader
// switch).
func NextPriority(category ErrorCategory, attempts int, contextCanceled bool) KeyPriority {
	// After a restart or a leader switch the key must be re-driven promptly;
	// the queue itself is shut down in that case and performs no retry.
	if contextCanceled {
		return KeyPriorityHigh
	}

	switch category {
	case ErrorCategoryDependencyWait:
		return KeyPriorityHigh
	case ErrorCategoryPermanent, ErrorCategoryConfiguration:
		return KeyPriorityLow
	case ErrorCategoryRetryable:
		if attempts >= maxRetryableAttempts {
			return KeyPriorityLow
		}
		return KeyPriorityNormal
	default:
		return KeyPriorityNormal
	}
}

// ReconcileErrorReport is the recovery report produced for a failed
// reconcile. It deliberately carries the original error untouched so that the
// full cause chain stays available to the report sink.
type ReconcileErrorReport struct {
	// ControllerName is the name of the controller that failed the reconcile.
	ControllerName string

	// Key is the workqueue key whose reconcile failed.
	Key types.NamespacedName

	// Category is the four-way recovery class of the error.
	Category ErrorCategory

	// Reason is the stable machine-readable reason within the category.
	Reason string

	// Err is the original reconcile error including its full cause chain.
	// It is stored as-is: errors.Is / errors.As keep working against it and
	// nothing in the reporting path wraps or truncates it.
	Err error

	// Attempts is the number of times the key has already been requeued,
	// read before the current failure is re-added to the queue.
	Attempts int

	// Backoff is the delay the workqueue rate limiter will apply when the
	// key is re-added. It is a non-mutating read.
	Backoff time.Duration

	// BackoffAvailable reports whether Backoff could be computed. It is
	// false for queues whose rate limiter does not expose a non-mutating
	// backoff read; Backoff is zero in that case.
	BackoffAvailable bool

	// Priority is the advisory priority of the next key processing.
	Priority KeyPriority

	// ContextCanceled reports whether the error chain contains
	// context.Canceled, i.e. the reconcile was interrupted by controller
	// shutdown or leader election loss.
	ContextCanceled bool

	// QueueShuttingDown reports whether the workqueue was already shutting
	// down when the failure was observed.
	QueueShuttingDown bool

	// ObservedAt is when the report was built.
	ObservedAt time.Time
}

// ErrorReporter consumes reconcile recovery reports. Implementations must not
// block the worker and must not mutate the passed error.
type ErrorReporter interface {
	ReportReconcileError(ctx context.Context, report ReconcileErrorReport)
}

// loggingErrorReporter is the default ErrorReporter: it emits one structured
// debug log per failed reconcile without touching the queue or the metrics.
type loggingErrorReporter struct{}

func (loggingErrorReporter) ReportReconcileError(ctx context.Context, report ReconcileErrorReport) {
	log := logf.FromContext(ctx, report.ControllerName)
	log.V(logf.DebugLevel).Info("reconcile error classified for recovery",
		"key", report.Key.String(),
		"category", report.Category,
		"reason", report.Reason,
		"attempts", report.Attempts,
		"backoff", report.Backoff.String(),
		"backoff_available", report.BackoffAvailable,
		"priority", report.Priority,
		"context_canceled", report.ContextCanceled,
		"queue_shutting_down", report.QueueShuttingDown,
		"error", report.Err,
	)
}

// exponentialBackoff mirrors the delay computation of
// workqueue.TypedItemExponentialFailureRateLimiter.When for the given failure
// index: baseDelay * 2^attempt, capped at maxDelay. It performs no state
// changes.
func exponentialBackoff(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	backoff := float64(baseDelay.Nanoseconds()) * math.Pow(2, float64(attempt))
	if backoff > float64(math.MaxInt64) {
		return maxDelay
	}

	calculated := time.Duration(backoff)
	if calculated > maxDelay {
		return maxDelay
	}

	return calculated
}

// ExponentialBackoffRateLimiter wraps a
// workqueue.TypedItemExponentialFailureRateLimiter and adds PeekWhen, a
// non-mutating read of the delay the next AddRateLimited would apply. The
// embedded rate limiter is untouched, so queue retry behavior is identical.
type ExponentialBackoffRateLimiter struct {
	workqueue.TypedRateLimiter[types.NamespacedName]
	baseDelay time.Duration
	maxDelay  time.Duration
}

// NewExponentialBackoffRateLimiter returns an exponential failure rate
// limiter with the same semantics as
// workqueue.NewTypedItemExponentialFailureRateLimiter plus a non-mutating
// PeekWhen read.
func NewExponentialBackoffRateLimiter(baseDelay, maxDelay time.Duration) *ExponentialBackoffRateLimiter {
	return &ExponentialBackoffRateLimiter{
		TypedRateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[types.NamespacedName](baseDelay, maxDelay),
		baseDelay:        baseDelay,
		maxDelay:         maxDelay,
	}
}

// PeekWhen returns the delay that the next When(item) call would return
// without incrementing the item's failure counter. NumRequeues therefore
// stays unchanged.
func (l *ExponentialBackoffRateLimiter) PeekWhen(item types.NamespacedName) time.Duration {
	return exponentialBackoff(l.NumRequeues(item), l.baseDelay, l.maxDelay)
}

// BackoffQueue is a rate limiting workqueue whose per-key backoff can be read
// without mutating rate limiter state.
type BackoffQueue interface {
	workqueue.TypedRateLimitingInterface[types.NamespacedName]

	// BackoffFor returns the delay the next AddRateLimited(key) would apply.
	// ok is false when the queue's rate limiter does not support a
	// non-mutating backoff read.
	BackoffFor(key types.NamespacedName) (backoff time.Duration, ok bool)
}

// peekableRateLimiter is implemented by rate limiters that expose a
// non-mutating backoff read.
type peekableRateLimiter interface {
	PeekWhen(item types.NamespacedName) time.Duration
}

type backoffRateLimitingQueue struct {
	workqueue.TypedRateLimitingInterface[types.NamespacedName]
	rateLimiter workqueue.TypedRateLimiter[types.NamespacedName]
}

var _ BackoffQueue = &backoffRateLimitingQueue{}

func (q *backoffRateLimitingQueue) BackoffFor(key types.NamespacedName) (time.Duration, bool) {
	if peekable, ok := q.rateLimiter.(peekableRateLimiter); ok {
		return peekable.PeekWhen(key), true
	}
	return 0, false
}

// NewWorkQueue creates a named rate limiting workqueue. The queue behaves
// identically to one built with workqueue.NewTypedRateLimitingQueueWithConfig;
// when rateLimiter is an ExponentialBackoffRateLimiter the returned queue
// additionally implements BackoffQueue so that recovery reports can read the
// pending backoff without changing rate limiter state.
func NewWorkQueue(name string, rateLimiter workqueue.TypedRateLimiter[types.NamespacedName]) workqueue.TypedRateLimitingInterface[types.NamespacedName] {
	queue := workqueue.NewTypedRateLimitingQueueWithConfig(
		rateLimiter,
		workqueue.TypedRateLimitingQueueConfig[types.NamespacedName]{
			Name: name,
		},
	)
	return &backoffRateLimitingQueue{
		TypedRateLimitingInterface: queue,
		rateLimiter:                rateLimiter,
	}
}

// newReconcileErrorReport builds the recovery report for a failed reconcile.
// It must be called before the key is re-added with AddRateLimited so that
// NumRequeues still matches the failure index used by the next backoff
// computation.
func newReconcileErrorReport(
	controllerName string,
	key types.NamespacedName,
	err error,
	queue workqueue.TypedRateLimitingInterface[types.NamespacedName],
) ReconcileErrorReport {
	category, reason := ClassifyError(err)
	attempts := queue.NumRequeues(key)
	contextCanceled := errors.Is(err, context.Canceled)

	var backoff time.Duration
	backoffAvailable := false
	if backoffQueue, ok := queue.(BackoffQueue); ok {
		backoff, backoffAvailable = backoffQueue.BackoffFor(key)
	}

	return ReconcileErrorReport{
		ControllerName:    controllerName,
		Key:               key,
		Category:          category,
		Reason:            reason,
		Err:               err,
		Attempts:          attempts,
		Backoff:           backoff,
		BackoffAvailable:  backoffAvailable,
		Priority:          NextPriority(category, attempts, contextCanceled),
		ContextCanceled:   contextCanceled,
		QueueShuttingDown: queue.ShuttingDown(),
		ObservedAt:        time.Now(),
	}
}
