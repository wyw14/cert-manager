/*
Copyright The cert-manager Authors.

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

// Package retrybudget provides a read-only planner that determines the next
// action of an ACME Order controller and the backoff window that must
// elapse before it runs again.
//
// The planner only consumes data that is already available locally: the
// Order status (its state, failure time and authorization states), Challenge
// resources owned by the Order as read from the controller cache, errors
// observed during previous reconciles and Retry-After / rate-limit hints.
// It never creates or updates Challenge resources and never performs ACME
// network calls.
package retrybudget

import (
	"fmt"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme"
	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
)

// Action is the next step that the Order controller should take.
type Action string

const (
	// ActionContinue means the regular reconcile flow may proceed without an
	// additional waiting period.
	ActionContinue Action = "Continue"

	// ActionWait means the Order must be requeued and no ACME request should
	// be issued before Decision.RetryAfter.
	ActionWait Action = "Wait"

	// ActionTerminal means the Order (or one of its authorizations or
	// challenges) has reached a condition that retrying cannot fix. The
	// Order should be marked failed or replaced by a new one.
	ActionTerminal Action = "Terminal"
)

// Machine-readable reasons explaining a Decision.
const (
	ReasonCompleted            = "Completed"
	ReasonReady                = "Ready"
	ReasonOrderInvalid         = "OrderInvalid"
	ReasonOrderExpired         = "OrderExpired"
	ReasonOrderErrored         = "OrderErrored"
	ReasonAuthorizationFailed  = "AuthorizationFailed"
	ReasonChallengeFailed      = "ChallengeFailed"
	ReasonPending              = "Pending"
	ReasonProcessing           = "Processing"
	ReasonRateLimited          = "RateLimited"
	ReasonServerError          = "ServerError"
	ReasonNetworkError         = "NetworkError"
	ReasonBadRequest           = "BadRequest"
	ReasonBadNonce             = "BadNonce"
	ReasonOrderNotReady        = "OrderNotReady"
	ReasonAlreadyReplaced      = "AlreadyReplaced"
	ReasonUnsupportedFeature   = "UnsupportedFeature"
	ReasonRetryBudgetExhausted = "RetryBudgetExhausted"
)

// Authorization states defined by RFC 8555 section 7.1.4 that are not part of
// the cert-manager State enumeration but may appear on raw ACME
// authorizations.
const (
	authorizationDeactivated cmacme.State = "deactivated"
	authorizationRevoked     cmacme.State = "revoked"
)

// Config tunes the retry budget. The zero value is valid and behaves as
// DefaultConfig.
type Config struct {
	// MinBackoff is the delay applied to the first retry and the floor for
	// every computed window. Zero selects the package default.
	MinBackoff time.Duration

	// MaxBackoff caps exponential growth and any server or account
	// Retry-After hint is still honoured above this value. Zero selects the
	// package default.
	MaxBackoff time.Duration

	// MaxAttempts limits the number of retries for a retryable condition.
	// Once the attempt counter reaches it, the condition is reported as
	// terminal with ReasonRetryBudgetExhausted. A zero or negative value
	// disables the cap and retries continue indefinitely with capped
	// backoff, matching the historical controller behaviour.
	MaxAttempts int
}

// DefaultConfig mirrors the orders controller work queue rate limiter: a
// five second base delay and a thirty minute maximum delay, with no attempt
// cap.
var DefaultConfig = Config{
	MinBackoff:  defaultMinBackoff,
	MaxBackoff:  defaultMaxBackoff,
	MaxAttempts: 0,
}

// AccountRateLimit describes account-wide rate limiting currently known to
// the caller, typically derived from an ACME rateLimited problem observed on
// a previous request.
type AccountRateLimit struct {
	// RetryAfter is the earliest time at which the account may issue
	// another ACME request. The zero value means "no active limit".
	RetryAfter time.Time

	// Source optionally records which ACME operation observed the limit,
	// for example "newOrder" or "newAccount". It is purely informational.
	Source string
}

// AuthorizationInput is the read-only view of an Order authorization
// (Order.status.authorizations) relevant to retry planning.
type AuthorizationInput struct {
	URL        string
	Identifier string
	State      cmacme.State
}

// ChallengeInput is the read-only view of an owned Challenge resource
// relevant to retry planning.
type ChallengeInput struct {
	Name   string
	State  cmacme.State
	Reason string
}

// Input contains every signal used by Plan. All fields are derived from
// local status data and previously observed errors; Plan never fetches
// anything itself.
type Input struct {
	// OrderState is Order.status.state.
	OrderState cmacme.State

	// FailureTime is Order.status.failureTime, if set.
	FailureTime *time.Time

	// Authorizations are the cached authorization states from
	// Order.status.authorizations.
	Authorizations []AuthorizationInput

	// Challenges are the states of the Challenge resources owned by the
	// Order, read from the controller cache.
	Challenges []ChallengeInput

	// LastError is the error returned by the most recent ACME interaction,
	// if any. It may be a wrapped *acme.Error or a plain transport error.
	LastError error

	// AccountRateLimit describes any active account-wide rate limiting.
	// Nil when the account is not currently rate limited.
	AccountRateLimit *AccountRateLimit

	// ServerRetryAfter is the strongest absolute Retry-After hint received
	// from the ACME server for the Order or its authorizations. It is the
	// zero time when no such hint has been received.
	ServerRetryAfter time.Time

	// Attempt is the zero-based number of retries already performed for the
	// current retryable condition. It drives exponential backoff and the
	// optional MaxAttempts budget.
	Attempt int

	// Now is the reference time used to compute waiting windows.
	Now time.Time
}

// Decision is the planned next action for an Order.
type Decision struct {
	// Action is the next step the controller should take.
	Action Action

	// Reason is a short machine-readable explanation.
	Reason string

	// Message is an optional human-readable explanation.
	Message string

	// Retryable reports whether the underlying condition may clear and the
	// Order should be retried. It is false for terminal and continue
	// decisions.
	Retryable bool

	// RateLimited reports that waiting is, at least in part, caused by an
	// ACME rate limit (account-wide or server-wide).
	RateLimited bool

	// RetryAfter is the earliest time at which ACME work may be attempted
	// again. It is zero for ActionContinue and ActionTerminal decisions.
	RetryAfter time.Time

	// Backoff is the time to wait from Input.Now until RetryAfter. It is
	// zero for ActionContinue and ActionTerminal decisions.
	Backoff time.Duration

	// ErrorClass classifies Input.LastError when one was provided. It is
	// empty when there was no error.
	ErrorClass ErrorClass
}

// Plan computes the next action and backoff window for an Order using only
// the read-only signals carried by in. It is a pure function: it performs no
// I/O, creates no resources and makes no ACME requests.
func Plan(in Input, cfg Config) Decision {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	cfg = withDefaults(cfg)

	// A failure state recorded on the Order itself is final.
	if acme.IsFailureState(in.OrderState) {
		return terminalDecisionForOrderState(in.OrderState)
	}

	// Final success states require no waiting.
	switch in.OrderState {
	case cmacme.Valid:
		return Decision{Action: ActionContinue, Reason: ReasonCompleted}
	case cmacme.Ready:
		return Decision{Action: ActionContinue, Reason: ReasonReady}
	default:
		// Pending, processing and unknown states fall through to the
		// authorization, challenge and error analysis below.
	}

	// A failed authorization or challenge is terminal even before the
	// Order status itself has been marked as failed.
	if d, ok := failedAuthorizationDecision(in.Authorizations); ok {
		return d
	}
	if d, ok := failedChallengeDecision(in.Challenges); ok {
		return d
	}

	// Classify the error observed on the last ACME interaction, if any.
	var classification ErrorClassification
	if in.LastError != nil {
		classification = ClassifyError(in.LastError)
		if classification.Class == ErrorClassTerminal {
			return Decision{
				Action:     ActionTerminal,
				Reason:     classification.Reason,
				Message:    in.LastError.Error(),
				ErrorClass: ErrorClassTerminal,
			}
		}
	}

	// Every remaining path is a waiting path; decide why.
	reason := waitingReason(in.OrderState, classification)

	d := waitDecision(in, cfg, reason, classification)

	// Enforce the retry budget once the window has been computed.
	if cfg.MaxAttempts > 0 && in.Attempt >= cfg.MaxAttempts {
		return Decision{
			Action:  ActionTerminal,
			Reason:  ReasonRetryBudgetExhausted,
			Message: fmt.Sprintf("retry budget of %d attempt(s) exhausted while waiting (%s)", cfg.MaxAttempts, reason),
		}
	}

	return d
}

// InputFromOrder builds the order-owned portion of an Input purely from the
// read-only status of an Order. The returned value never contains an ACME
// client or any live connection; the caller is expected to populate the
// remaining optional fields (cached challenges, the last observed error,
// rate-limit hints and the attempt counter) itself.
func InputFromOrder(order *cmacme.Order, now time.Time) Input {
	in := Input{
		OrderState: order.Status.State,
		Now:        now,
	}

	if order.Status.FailureTime != nil {
		failureTime := order.Status.FailureTime.Time
		in.FailureTime = &failureTime
	}

	in.Authorizations = make([]AuthorizationInput, 0, len(order.Status.Authorizations))
	for _, authz := range order.Status.Authorizations {
		in.Authorizations = append(in.Authorizations, AuthorizationInput{
			URL:        authz.URL,
			Identifier: authz.Identifier,
			State:      authz.InitialState,
		})
	}

	return in
}

// ChallengeInputFrom maps a cached Challenge resource to its read-only
// planner representation.
func ChallengeInputFrom(challenge *cmacme.Challenge) ChallengeInput {
	return ChallengeInput{
		Name:   challenge.Name,
		State:  challenge.Status.State,
		Reason: challenge.Status.Reason,
	}
}

func withDefaults(cfg Config) Config {
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = DefaultConfig.MinBackoff
	}
	if cfg.MaxBackoff <= 0 || cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = DefaultConfig.MaxBackoff
	}
	return cfg
}

func terminalDecisionForOrderState(state cmacme.State) Decision {
	switch state {
	case cmacme.Invalid:
		return Decision{Action: ActionTerminal, Reason: ReasonOrderInvalid, Message: "order is in an invalid state"}
	case cmacme.Expired:
		return Decision{Action: ActionTerminal, Reason: ReasonOrderExpired, Message: "order has expired"}
	case cmacme.Errored:
		return Decision{Action: ActionTerminal, Reason: ReasonOrderErrored, Message: "order has errored"}
	default:
		return Decision{Action: ActionTerminal, Reason: ReasonOrderErrored, Message: fmt.Sprintf("order is in failure state %q", state)}
	}
}

func failedAuthorizationDecision(authzs []AuthorizationInput) (Decision, bool) {
	for _, authz := range authzs {
		switch {
		case acme.IsFailureState(authz.State), authz.State == authorizationDeactivated, authz.State == authorizationRevoked:
			return Decision{
				Action:  ActionTerminal,
				Reason:  ReasonAuthorizationFailed,
				Message: fmt.Sprintf("authorization %q for identifier %q is in final failure state %q", authz.URL, authz.Identifier, authz.State),
			}, true
		}
	}
	return Decision{}, false
}

func failedChallengeDecision(challenges []ChallengeInput) (Decision, bool) {
	for _, ch := range challenges {
		if acme.IsFailureState(ch.State) {
			return Decision{
				Action:  ActionTerminal,
				Reason:  ReasonChallengeFailed,
				Message: fmt.Sprintf("challenge %q is in final failure state %q: %s", ch.Name, ch.State, ch.Reason),
			}, true
		}
	}
	return Decision{}, false
}

func waitingReason(state cmacme.State, classification ErrorClassification) string {
	if classification.Class == ErrorClassRetryable {
		return classification.Reason
	}
	switch state {
	case cmacme.Processing:
		return ReasonProcessing
	case cmacme.Pending:
		return ReasonPending
	default:
		// Unknown or empty states are treated as pending, matching the
		// ACME authorization default in the order controller.
		return ReasonPending
	}
}

func waitDecision(in Input, cfg Config, reason string, classification ErrorClassification) Decision {
	hints := make([]time.Time, 0, 3)
	if !in.ServerRetryAfter.IsZero() {
		hints = append(hints, in.ServerRetryAfter)
	}
	if in.AccountRateLimit != nil && !in.AccountRateLimit.RetryAfter.IsZero() {
		hints = append(hints, in.AccountRateLimit.RetryAfter)
	}
	if classification.RetryAfter > 0 {
		hints = append(hints, in.Now.Add(classification.RetryAfter))
	}

	retryAfter, backoff := waitWindow(in.Now, in.Attempt, cfg, hints...)

	return Decision{
		Action:      ActionWait,
		Reason:      reason,
		Retryable:   true,
		RateLimited: classification.RateLimited || in.AccountRateLimit != nil,
		RetryAfter:  retryAfter,
		Backoff:     backoff,
		ErrorClass:  classification.Class,
	}
}
