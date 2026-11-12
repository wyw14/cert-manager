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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/metrics"
	cmerrors "github.com/cert-manager/cert-manager/pkg/util/errors"
)

// testNetError implements net.Error for transport-failure classification.
type testNetError struct {
	timeout bool
}

func (e testNetError) Error() string   { return "simulated network failure" }
func (e testNetError) Timeout() bool   { return e.timeout }
func (e testNetError) Temporary() bool { return true }

var testKey = types.NamespacedName{Namespace: "test-ns", Name: "test-object"}

func TestClassifyError(t *testing.T) {
	groupResource := schema.GroupResource{Group: "cert-manager.io", Resource: "certificates"}
	groupKind := schema.GroupKind{Group: "cert-manager.io", Kind: "Certificate"}

	tests := map[string]struct {
		err          error
		wantCategory ErrorCategory
		wantReason   string
	}{
		// lifecycle / transport errors
		"context canceled is retryable": {
			err:          context.Canceled,
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonContextCanceled,
		},
		"wrapped context canceled keeps classification": {
			err:          fmt.Errorf("reconcile interrupted: %w", context.Canceled),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonContextCanceled,
		},
		"context deadline exceeded is retryable": {
			err:          context.DeadlineExceeded,
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonContextDeadlineExceeded,
		},
		"network error is retryable": {
			err:          testNetError{timeout: true},
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonNetworkError,
		},
		"wrapped network error is retryable": {
			err:          fmt.Errorf("calling webhook: %w", testNetError{}),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonNetworkError,
		},
		"optimistic lock message is retryable": {
			err:          errors.New(genericregistry.OptimisticLockErrorMsg),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonOptimisticLock,
		},

		// dependency wait
		"not found waits for a dependency": {
			err:          apierrors.NewNotFound(groupResource, "missing"),
			wantCategory: ErrorCategoryDependencyWait,
			wantReason:   reasonNotFound,
		},
		"wrapped not found waits for a dependency": {
			err:          fmt.Errorf("loading secret: %w", apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "tls")),
			wantCategory: ErrorCategoryDependencyWait,
			wantReason:   reasonNotFound,
		},
		"already exists waits for the dependency": {
			err:          apierrors.NewAlreadyExists(groupResource, "duplicate"),
			wantCategory: ErrorCategoryDependencyWait,
			wantReason:   reasonAlreadyExists,
		},

		// configuration errors
		"unauthorized is a configuration error": {
			err:          apierrors.NewUnauthorized("bad credentials"),
			wantCategory: ErrorCategoryConfiguration,
			wantReason:   reasonUnauthorized,
		},
		"forbidden is a configuration error": {
			err:          apierrors.NewForbidden(groupResource, "test-object", errors.New("RBAC denied")),
			wantCategory: ErrorCategoryConfiguration,
			wantReason:   reasonForbidden,
		},
		"invalid data is a configuration error": {
			err:          cmerrors.NewInvalidData("malformed PEM block"),
			wantCategory: ErrorCategoryConfiguration,
			wantReason:   reasonInvalidData,
		},
		"wrapped invalid data is a configuration error": {
			err:          fmt.Errorf("parsing key: %w", cmerrors.NewInvalidData("bad key")),
			wantCategory: ErrorCategoryConfiguration,
			wantReason:   reasonInvalidData,
		},

		// permanent errors
		"bad request is permanent": {
			err:          apierrors.NewBadRequest("malformed request"),
			wantCategory: ErrorCategoryPermanent,
			wantReason:   reasonBadRequest,
		},
		"invalid object is permanent": {
			err: apierrors.NewInvalid(groupKind, "test-object", field.ErrorList{
				field.Required(field.NewPath("spec", "issuerRef"), "issuerRef is required"),
			}),
			wantCategory: ErrorCategoryPermanent,
			wantReason:   reasonInvalid,
		},
		"unsupported method is permanent": {
			err:          apierrors.NewMethodNotSupported(groupResource, "PATCH"),
			wantCategory: ErrorCategoryPermanent,
			wantReason:   reasonMethodNotSupported,
		},
		"gone is permanent": {
			// apierrors.NewGone is deprecated, so build the status error
			// directly to exercise the IsGone classification branch.
			err: &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Status:  metav1.StatusFailure,
					Reason:  metav1.StatusReasonGone,
					Message: "resource has been removed",
				},
			},
			wantCategory: ErrorCategoryPermanent,
			wantReason:   reasonGone,
		},
		"resource expired is permanent": {
			err:          apierrors.NewResourceExpired("stale resource version"),
			wantCategory: ErrorCategoryPermanent,
			wantReason:   reasonResourceExpired,
		},

		// retryable API server conditions
		"too many requests is retryable": {
			err:          apierrors.NewTooManyRequests("slow down", 1),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonTooManyRequests,
		},
		"service unavailable is retryable": {
			err:          apierrors.NewServiceUnavailable("apiserver overloaded"),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonServiceUnavailable,
		},
		"server timeout is retryable": {
			err:          apierrors.NewServerTimeout(groupResource, "create", 1),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonServerTimeout,
		},
		"internal error is retryable": {
			err:          apierrors.NewInternalError(errors.New("apiserver panic")),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonInternalError,
		},
		"plain conflict is retryable": {
			err:          apierrors.NewConflict(groupResource, "test-object", errors.New("concurrent update")),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonConflict,
		},

		// default
		"unknown error defaults to retryable": {
			err:          errors.New("something unexpected happened"),
			wantCategory: ErrorCategoryRetryable,
			wantReason:   reasonUnknown,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			category, reason := ClassifyError(test.err)
			assert.Equal(t, test.wantCategory, category)
			assert.Equal(t, test.wantReason, reason)
		})
	}
}

func TestClassifyError_Nil(t *testing.T) {
	category, reason := ClassifyError(nil)
	assert.Empty(t, category)
	assert.Empty(t, reason)
}

func TestExponentialBackoff(t *testing.T) {
	const (
		baseDelay = 5 * time.Second
		maxDelay  = 5 * time.Minute
	)

	tests := map[string]struct {
		attempt int
		want    time.Duration
	}{
		"first failure uses base delay":    {attempt: 0, want: 5 * time.Second},
		"second failure doubles":           {attempt: 1, want: 10 * time.Second},
		"third failure doubles again":      {attempt: 2, want: 20 * time.Second},
		"grows exponentially":              {attempt: 5, want: 160 * time.Second},
		"is capped at max delay":           {attempt: 7, want: maxDelay},
		"far future stays at max delay":    {attempt: 100, want: maxDelay},
		"negative attempt is treated as 0": {attempt: -1, want: baseDelay},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, exponentialBackoff(test.attempt, baseDelay, maxDelay))
		})
	}
}

func TestExponentialBackoffRateLimiter_PeekWhenDoesNotMutate(t *testing.T) {
	limiter := NewExponentialBackoffRateLimiter(5*time.Second, time.Minute)

	require.Zero(t, limiter.NumRequeues(testKey))

	// Peeking must not increment the failure counter.
	firstPeek := limiter.PeekWhen(testKey)
	assert.Equal(t, 5*time.Second, firstPeek)
	assert.Equal(t, 5*time.Second, limiter.PeekWhen(testKey))
	require.Zero(t, limiter.NumRequeues(testKey))

	// The real When() must apply exactly the delay that was peeked.
	when := limiter.When(testKey)
	assert.Equal(t, firstPeek, when)
	require.Equal(t, 1, limiter.NumRequeues(testKey))
	assert.Equal(t, 10*time.Second, limiter.PeekWhen(testKey))

	// Forget resets the failure state and therefore the peeked backoff.
	limiter.Forget(testKey)
	require.Zero(t, limiter.NumRequeues(testKey))
	assert.Equal(t, 5*time.Second, limiter.PeekWhen(testKey))
}

func TestNewWorkQueue_BackoffFor(t *testing.T) {
	t.Run("peekable limiter exposes backoff", func(t *testing.T) {
		queue := NewWorkQueue("peekable", NewExponentialBackoffRateLimiter(time.Second, time.Minute))
		t.Cleanup(queue.ShutDown)

		backoffQueue, ok := queue.(BackoffQueue)
		require.True(t, ok)

		backoff, available := backoffQueue.BackoffFor(testKey)
		assert.True(t, available)
		assert.Equal(t, time.Second, backoff)

		// AddRateLimited keeps its standard behavior: the failure counter is
		// incremented immediately and the next peek reflects it.
		queue.AddRateLimited(testKey)
		require.Equal(t, 1, queue.NumRequeues(testKey))
		backoff, available = backoffQueue.BackoffFor(testKey)
		assert.True(t, available)
		assert.Equal(t, 2*time.Second, backoff)
	})

	t.Run("plain limiter reports unavailable backoff", func(t *testing.T) {
		queue := NewWorkQueue(
			"plain",
			workqueue.NewTypedItemExponentialFailureRateLimiter[types.NamespacedName](time.Second, time.Minute),
		)
		t.Cleanup(queue.ShutDown)

		backoffQueue, ok := queue.(BackoffQueue)
		require.True(t, ok)

		backoff, available := backoffQueue.BackoffFor(testKey)
		assert.False(t, available)
		assert.Zero(t, backoff)
	})
}

func TestNextPriority(t *testing.T) {
	tests := map[string]struct {
		category        ErrorCategory
		attempts        int
		contextCanceled bool
		want            KeyPriority
	}{
		"dependency wait is always high":           {category: ErrorCategoryDependencyWait, attempts: 100, want: KeyPriorityHigh},
		"permanent error is low":                   {category: ErrorCategoryPermanent, attempts: 0, want: KeyPriorityLow},
		"configuration error is low":               {category: ErrorCategoryConfiguration, attempts: 0, want: KeyPriorityLow},
		"fresh retryable error is normal":          {category: ErrorCategoryRetryable, attempts: 0, want: KeyPriorityNormal},
		"retryable error within backoff is normal": {category: ErrorCategoryRetryable, attempts: maxRetryableAttempts - 1, want: KeyPriorityNormal},
		"saturated retryable error is low":         {category: ErrorCategoryRetryable, attempts: maxRetryableAttempts, want: KeyPriorityLow},
		"context cancellation is high":             {category: ErrorCategoryRetryable, attempts: 50, contextCanceled: true, want: KeyPriorityHigh},
		"context cancellation overrides permanent": {category: ErrorCategoryPermanent, attempts: 0, contextCanceled: true, want: KeyPriorityHigh},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.want, NextPriority(test.category, test.attempts, test.contextCanceled))
		})
	}
}

func TestNewReconcileErrorReport_PreservesCauseChain(t *testing.T) {
	queue := NewWorkQueue("report-test", NewExponentialBackoffRateLimiter(time.Second, time.Minute))
	t.Cleanup(queue.ShutDown)

	sentinel := apierrors.NewTooManyRequests("slow down", 1)
	wrapped := fmt.Errorf("sync failed: %w", sentinel)

	report := newReconcileErrorReport("test-controller", testKey, wrapped, queue)

	assert.Equal(t, "test-controller", report.ControllerName)
	assert.Equal(t, testKey, report.Key)
	assert.Equal(t, ErrorCategoryRetryable, report.Category)
	assert.Equal(t, reasonTooManyRequests, report.Reason)

	// The original error and its full cause chain are carried untouched.
	assert.Same(t, wrapped, report.Err)
	var statusErr *apierrors.StatusError
	require.True(t, errors.As(report.Err, &statusErr))
	assert.True(t, apierrors.IsTooManyRequests(report.Err))

	assert.Zero(t, report.Attempts)
	assert.True(t, report.BackoffAvailable)
	assert.Equal(t, time.Second, report.Backoff)
	assert.Equal(t, KeyPriorityNormal, report.Priority)
	assert.False(t, report.ContextCanceled)
	assert.False(t, report.QueueShuttingDown)
	assert.False(t, report.ObservedAt.IsZero())
}

func TestNewReconcileErrorReport_ShuttingDownQueue(t *testing.T) {
	queue := NewWorkQueue("shutdown-test", NewExponentialBackoffRateLimiter(time.Second, time.Minute))
	queue.ShutDown()

	report := newReconcileErrorReport(
		"test-controller",
		testKey,
		fmt.Errorf("leader lost: %w", context.Canceled),
		queue,
	)

	assert.True(t, report.QueueShuttingDown)
	assert.True(t, report.ContextCanceled)
	assert.Equal(t, ErrorCategoryRetryable, report.Category)
	assert.Equal(t, reasonContextCanceled, report.Reason)
	assert.Equal(t, KeyPriorityHigh, report.Priority)
	assert.True(t, errors.Is(report.Err, context.Canceled))
}

// capturingReporter records every recovery report for worker-level assertions.
type capturingReporter struct {
	mu      sync.Mutex
	reports []ReconcileErrorReport
}

func (r *capturingReporter) ReportReconcileError(_ context.Context, report ReconcileErrorReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, report)
}

func (r *capturingReporter) snapshot() []ReconcileErrorReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ReconcileErrorReport(nil), r.reports...)
}

func newTestController(t *testing.T, syncFunc func(context.Context, types.NamespacedName) error, reporter ErrorReporter) (workqueue.TypedRateLimitingInterface[types.NamespacedName], context.CancelFunc) {
	t.Helper()

	// Small base delay keeps the requeue path fast while still exercising the
	// real exponential rate limiter.
	queue := NewWorkQueue("worker-test", NewExponentialBackoffRateLimiter(10*time.Millisecond, 100*time.Millisecond))
	t.Cleanup(queue.ShutDown)

	ctrl := NewController(
		"worker-test-controller",
		metrics.New(logf.Log, clock.RealClock{}),
		syncFunc,
		nil,
		nil,
		queue,
		WithErrorReporter(reporter),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ctrl.Run(1, ctx)
	}()

	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("controller did not shut down")
		}
	})

	return queue, cancel
}

func TestWorker_RecoveryReportAndUnchangedRetryBehavior(t *testing.T) {
	var calls atomic.Int32
	syncFunc := func(_ context.Context, _ types.NamespacedName) error {
		if calls.Add(1) == 1 {
			return apierrors.NewTooManyRequests("slow down", 1)
		}
		return nil
	}

	reporter := &capturingReporter{}
	queue, _ := newTestController(t, syncFunc, reporter)
	queue.Add(testKey)

	// The failed reconcile must produce exactly one report for the first
	// attempt.
	require.Eventually(t, func() bool {
		return len(reporter.snapshot()) == 1
	}, 5*time.Second, 10*time.Millisecond)

	report := reporter.snapshot()[0]
	assert.Equal(t, ErrorCategoryRetryable, report.Category)
	assert.Equal(t, reasonTooManyRequests, report.Reason)
	assert.Zero(t, report.Attempts)
	assert.True(t, report.BackoffAvailable)
	assert.Equal(t, 10*time.Millisecond, report.Backoff)
	assert.False(t, report.ContextCanceled)
	assert.True(t, apierrors.IsTooManyRequests(report.Err))

	// The existing retry behavior is unchanged: the failed key is re-added
	// with AddRateLimited (the rate limiter failure count is asserted
	// deterministically without a competing worker in
	// TestNewWorkQueue_BackoffFor), redelivered after the backoff and, once
	// the retry succeeds, forgotten exactly as before. Two sync calls prove
	// the key really was requeued and processed again.
	require.Eventually(t, func() bool {
		return calls.Load() == 2 && queue.NumRequeues(testKey) == 0
	}, 5*time.Second, 10*time.Millisecond)
	assert.Len(t, reporter.snapshot(), 1, "successful reconciles must not produce error reports")
}

func TestWorker_PermanentErrorIsStillRequeued(t *testing.T) {
	syncFunc := func(_ context.Context, _ types.NamespacedName) error {
		return apierrors.NewBadRequest("the spec is wrong")
	}

	reporter := &capturingReporter{}
	queue, _ := newTestController(t, syncFunc, reporter)
	queue.Add(testKey)

	require.Eventually(t, func() bool {
		return len(reporter.snapshot()) >= 1
	}, 5*time.Second, 10*time.Millisecond)

	report := reporter.snapshot()[0]
	assert.Equal(t, ErrorCategoryPermanent, report.Category)
	assert.Equal(t, reasonBadRequest, report.Reason)

	// Classification is observational only: permanent errors keep using the
	// exact same AddRateLimited retry path as every other error.
	require.Eventually(t, func() bool {
		return queue.NumRequeues(testKey) >= 1
	}, 5*time.Second, 10*time.Millisecond)
}

// TestWorker_ContextCanceledDuringReconcile simulates controller shutdown and
// leader election loss, both of which cancel the controller context while a
// reconcile is in flight. The resulting report must flag the cancellation and
// the shutting-down queue without attempting a real retry.
func TestWorker_ContextCanceledDuringReconcile(t *testing.T) {
	entered := make(chan struct{})
	syncFunc := func(ctx context.Context, _ types.NamespacedName) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}

	reporter := &capturingReporter{}
	queue, cancel := newTestController(t, syncFunc, reporter)
	queue.Add(testKey)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile was never started")
	}

	// Losing leadership (or shutting down) cancels the controller context.
	cancel()

	require.Eventually(t, func() bool {
		return len(reporter.snapshot()) == 1
	}, 5*time.Second, 10*time.Millisecond)

	report := reporter.snapshot()[0]
	assert.True(t, report.ContextCanceled, "report must mark context cancellation")
	assert.Equal(t, ErrorCategoryRetryable, report.Category)
	assert.Equal(t, reasonContextCanceled, report.Reason)
	assert.Equal(t, KeyPriorityHigh, report.Priority)
	assert.True(t, errors.Is(report.Err, context.Canceled), "cause chain must stay intact")

	// Whether the report is built before or after Run() calls ShutDown is a
	// race (both observe the same canceled context), so QueueShuttingDown is
	// asserted deterministically against a pre-shut queue in
	// TestNewReconcileErrorReport_ShuttingDownQueue. Here we only require the
	// controller to end up shutting the queue down.
	require.Eventually(t, queue.ShuttingDown, 5*time.Second, 10*time.Millisecond)

	// A shutting-down queue drops AddRateLimited, so no retry is scheduled.
	assert.Len(t, reporter.snapshot(), 1)
}
