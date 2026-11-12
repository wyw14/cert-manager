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

package retrybudget

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

var testNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func testConfig() Config {
	return Config{
		MinBackoff:  5 * time.Second,
		MaxBackoff:  time.Minute,
		MaxAttempts: 0,
	}
}

func TestPlanFinalOrderStates(t *testing.T) {
	tests := []struct {
		state  cmacme.State
		reason string
	}{
		{cmacme.Invalid, ReasonOrderInvalid},
		{cmacme.Expired, ReasonOrderExpired},
		{cmacme.Errored, ReasonOrderErrored},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			// Even with a retryable error and pending challenges, a recorded
			// failure state must take precedence.
			got := Plan(Input{
				OrderState: tt.state,
				LastError:  acmeError(http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal"),
				Now:        testNow,
			}, testConfig())

			assert.Equal(t, ActionTerminal, got.Action)
			assert.Equal(t, tt.reason, got.Reason)
			assert.False(t, got.Retryable)
			assert.Zero(t, got.Backoff)
			assert.True(t, got.RetryAfter.IsZero())
		})
	}
}

func TestPlanSuccessStates(t *testing.T) {
	tests := []struct {
		state  cmacme.State
		reason string
	}{
		{cmacme.Valid, ReasonCompleted},
		{cmacme.Ready, ReasonReady},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			got := Plan(Input{OrderState: tt.state, Now: testNow}, testConfig())
			assert.Equal(t, ActionContinue, got.Action)
			assert.Equal(t, tt.reason, got.Reason)
			assert.False(t, got.Retryable)
			assert.Zero(t, got.Backoff)
		})
	}
}

func TestPlanFailedAuthorizationIsTerminal(t *testing.T) {
	tests := []struct {
		name  string
		state cmacme.State
	}{
		{"invalid authorization", cmacme.Invalid},
		{"expired authorization", cmacme.Expired},
		{"errored authorization", cmacme.Errored},
		{"deactivated authorization", authorizationDeactivated},
		{"revoked authorization", authorizationRevoked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Plan(Input{
				OrderState: cmacme.Pending,
				Authorizations: []AuthorizationInput{
					{URL: "https://acme.example/authz/1", Identifier: "example.com", State: cmacme.Valid},
					{URL: "https://acme.example/authz/2", Identifier: "www.example.com", State: tt.state},
				},
				Now: testNow,
			}, testConfig())

			assert.Equal(t, ActionTerminal, got.Action)
			assert.Equal(t, ReasonAuthorizationFailed, got.Reason)
			assert.Contains(t, got.Message, "www.example.com")
		})
	}
}

func TestPlanFailedChallengeIsTerminal(t *testing.T) {
	t.Run("failed challenge wins over a retryable error", func(t *testing.T) {
		got := Plan(Input{
			OrderState: cmacme.Pending,
			Challenges: []ChallengeInput{
				{Name: "ch-1", State: cmacme.Pending},
				{Name: "ch-2", State: cmacme.Invalid, Reason: "incorrect response"},
			},
			LastError: acmeError(http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal"),
			Now:       testNow,
		}, testConfig())

		assert.Equal(t, ActionTerminal, got.Action)
		assert.Equal(t, ReasonChallengeFailed, got.Reason)
		assert.Contains(t, got.Message, "ch-2")
	})

	t.Run("pending challenges allow waiting", func(t *testing.T) {
		got := Plan(Input{
			OrderState: cmacme.Pending,
			Challenges: []ChallengeInput{{Name: "ch-1", State: cmacme.Pending}},
			Now:        testNow,
		}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.True(t, got.Retryable)
	})
}

func TestPlanTransientStatesWaitWithExponentialBackoff(t *testing.T) {
	t.Run("pending order without error waits for the minimum backoff", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Pending, Attempt: 0, Now: testNow}, testConfig())
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, ReasonPending, got.Reason)
		assert.Equal(t, 5*time.Second, got.Backoff)
		assert.Equal(t, testNow.Add(5*time.Second), got.RetryAfter)
		assert.True(t, got.Retryable)
	})

	t.Run("processing order reports the processing reason", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Processing, Now: testNow}, testConfig())
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, ReasonProcessing, got.Reason)
	})

	t.Run("unknown state is treated as pending", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Unknown, Now: testNow}, testConfig())
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, ReasonPending, got.Reason)
	})

	t.Run("the window grows with the attempt counter", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Pending, Attempt: 3, Now: testNow}, testConfig())
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, 40*time.Second, got.Backoff)
	})

	t.Run("the window is capped at MaxBackoff", func(t *testing.T) {
		cfg := testConfig()
		got := Plan(Input{OrderState: cmacme.Pending, Attempt: 10, Now: testNow}, cfg)
		assert.Equal(t, cfg.MaxBackoff, got.Backoff)
	})
}

func TestPlanRateLimitAndRetryAfterHints(t *testing.T) {
	t.Run("rateLimited error extends the window and flags rate limiting", func(t *testing.T) {
		got := Plan(Input{
			OrderState: cmacme.Pending,
			LastError:  acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited", "120"),
			Now:        testNow,
		}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, ReasonRateLimited, got.Reason)
		assert.True(t, got.RateLimited)
		assert.Equal(t, ErrorClassRetryable, got.ErrorClass)
		assert.Equal(t, 120*time.Second, got.Backoff)
		assert.Equal(t, testNow.Add(120*time.Second), got.RetryAfter)
	})

	t.Run("rate limit without a header keeps the minimum backoff", func(t *testing.T) {
		got := Plan(Input{
			OrderState: cmacme.Pending,
			LastError:  acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited"),
			Now:        testNow,
		}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.True(t, got.RateLimited)
		assert.Equal(t, 5*time.Second, got.Backoff)
	})

	t.Run("account rate limit extends the window", func(t *testing.T) {
		limit := testNow.Add(10 * time.Minute)
		got := Plan(Input{
			OrderState:       cmacme.Pending,
			AccountRateLimit: &AccountRateLimit{RetryAfter: limit, Source: "newOrder"},
			Now:              testNow,
		}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.True(t, got.RateLimited)
		assert.Equal(t, 10*time.Minute, got.Backoff)
		assert.Equal(t, limit, got.RetryAfter)
	})

	t.Run("server Retry-After extends the window", func(t *testing.T) {
		hint := testNow.Add(45 * time.Second)
		got := Plan(Input{
			OrderState:       cmacme.Processing,
			ServerRetryAfter: hint,
			Now:              testNow,
		}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, 45*time.Second, got.Backoff)
		assert.Equal(t, hint, got.RetryAfter)
	})

	t.Run("the latest of error, server and account hints wins", func(t *testing.T) {
		serverHint := testNow.Add(30 * time.Second)
		accountHint := testNow.Add(5 * time.Minute)
		got := Plan(Input{
			OrderState:       cmacme.Pending,
			ServerRetryAfter: serverHint,
			AccountRateLimit: &AccountRateLimit{RetryAfter: accountHint},
			LastError:        acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited", "60"),
			Now:              testNow,
		}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.True(t, got.RateLimited)
		assert.Equal(t, 5*time.Minute, got.Backoff)
		assert.Equal(t, accountHint, got.RetryAfter)
	})

	t.Run("an expired account limit does not shorten the backoff", func(t *testing.T) {
		got := Plan(Input{
			OrderState:       cmacme.Pending,
			AccountRateLimit: &AccountRateLimit{RetryAfter: testNow.Add(-time.Minute)},
			Now:              testNow,
		}, testConfig())

		assert.Equal(t, 5*time.Second, got.Backoff)
	})
}

func TestPlanErrorClassification(t *testing.T) {
	t.Run("terminal ACME error produces a terminal decision", func(t *testing.T) {
		err := acmeError(http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized")
		got := Plan(Input{OrderState: cmacme.Pending, LastError: err, Now: testNow}, testConfig())

		assert.Equal(t, ActionTerminal, got.Action)
		assert.Equal(t, ReasonBadRequest, got.Reason)
		assert.Equal(t, ErrorClassTerminal, got.ErrorClass)
		assert.False(t, got.Retryable)
	})

	t.Run("server error waits with the server error reason", func(t *testing.T) {
		err := acmeError(http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal")
		got := Plan(Input{OrderState: cmacme.Pending, LastError: err, Now: testNow}, testConfig())

		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, ReasonServerError, got.Reason)
		assert.Equal(t, ErrorClassRetryable, got.ErrorClass)
	})

	t.Run("non-ACME transport error waits with the network reason", func(t *testing.T) {
		got := Plan(Input{
			OrderState: cmacme.Pending,
			LastError:  acmeapi.ErrCADoesNotSupportARI,
			Now:        testNow,
		}, testConfig())

		// ErrCADoesNotSupportARI is not in the terminal sentinel set, so it
		// follows the generic retryable path.
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, ReasonNetworkError, got.Reason)
	})
}

func TestPlanRetryBudgetExhaustion(t *testing.T) {
	cfg := Config{MinBackoff: 5 * time.Second, MaxBackoff: time.Minute, MaxAttempts: 3}

	t.Run("retries continue below the budget", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Pending, Attempt: 2, Now: testNow}, cfg)
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, 20*time.Second, got.Backoff)
	})

	t.Run("the condition becomes terminal once the budget is spent", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Pending, Attempt: 3, Now: testNow}, cfg)
		assert.Equal(t, ActionTerminal, got.Action)
		assert.Equal(t, ReasonRetryBudgetExhausted, got.Reason)
		assert.False(t, got.Retryable)
		assert.Contains(t, got.Message, ReasonPending)
	})

	t.Run("the budget also caps rate-limit retries", func(t *testing.T) {
		got := Plan(Input{
			OrderState: cmacme.Pending,
			Attempt:    3,
			LastError:  acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited", "120"),
			Now:        testNow,
		}, cfg)

		assert.Equal(t, ActionTerminal, got.Action)
		assert.Equal(t, ReasonRetryBudgetExhausted, got.Reason)
	})

	t.Run("a disabled budget retries indefinitely", func(t *testing.T) {
		got := Plan(Input{OrderState: cmacme.Pending, Attempt: 999, Now: testNow}, testConfig())
		assert.Equal(t, ActionWait, got.Action)
		assert.Equal(t, time.Minute, got.Backoff)
	})
}

func TestPlanZeroConfigUsesDefaults(t *testing.T) {
	got := Plan(Input{OrderState: cmacme.Pending, Now: testNow}, Config{})
	assert.Equal(t, ActionWait, got.Action)
	assert.Equal(t, defaultMinBackoff, got.Backoff)
}

func TestPlanZeroNowFallsBackToWallClock(t *testing.T) {
	before := time.Now()
	got := Plan(Input{OrderState: cmacme.Pending}, testConfig())
	after := time.Now()

	assert.Equal(t, ActionWait, got.Action)
	assert.False(t, got.RetryAfter.IsZero())
	assert.WithinRange(t, got.RetryAfter.Add(-got.Backoff), before, after)
}

func TestTerminalDecisionForOrderState(t *testing.T) {
	assert.Equal(t, ReasonOrderInvalid, terminalDecisionForOrderState(cmacme.Invalid).Reason)
	assert.Equal(t, ReasonOrderExpired, terminalDecisionForOrderState(cmacme.Expired).Reason)
	assert.Equal(t, ReasonOrderErrored, terminalDecisionForOrderState(cmacme.Errored).Reason)

	// Defensive default for a hypothetical future failure state.
	unknown := terminalDecisionForOrderState(cmacme.State("futureFailure"))
	assert.Equal(t, ActionTerminal, unknown.Action)
	assert.Equal(t, ReasonOrderErrored, unknown.Reason)
}

func TestInputFromOrder(t *testing.T) {
	failureTime := metav1.NewTime(testNow.Add(-time.Hour))
	order := &cmacme.Order{
		Status: cmacme.OrderStatus{
			State:       cmacme.Pending,
			FailureTime: &failureTime,
			Authorizations: []cmacme.ACMEAuthorization{
				{URL: "https://acme.example/authz/1", Identifier: "example.com", InitialState: cmacme.Pending},
				{URL: "https://acme.example/authz/2", Identifier: "www.example.com", InitialState: cmacme.Valid},
			},
		},
	}

	in := InputFromOrder(order, testNow)
	assert.Equal(t, cmacme.Pending, in.OrderState)
	require.NotNil(t, in.FailureTime)
	assert.Equal(t, testNow.Add(-time.Hour), *in.FailureTime)
	require.Len(t, in.Authorizations, 2)
	assert.Equal(t, AuthorizationInput{
		URL:        "https://acme.example/authz/1",
		Identifier: "example.com",
		State:      cmacme.Pending,
	}, in.Authorizations[0])
	assert.Equal(t, cmacme.Valid, in.Authorizations[1].State)
	assert.Equal(t, testNow, in.Now)

	// Planner-owned optional fields must remain unset: the constructor only
	// reads status data and never invents errors or rate-limit state.
	assert.Nil(t, in.AccountRateLimit)
	assert.Nil(t, in.LastError)
	assert.Zero(t, in.Attempt)
	assert.True(t, in.ServerRetryAfter.IsZero())

	t.Run("order without failure time and authorizations", func(t *testing.T) {
		empty := InputFromOrder(&cmacme.Order{}, testNow)
		assert.Nil(t, empty.FailureTime)
		assert.NotNil(t, empty.Authorizations)
		assert.Empty(t, empty.Authorizations)
	})
}

func TestChallengeInputFrom(t *testing.T) {
	challenge := &cmacme.Challenge{}
	challenge.Name = "challenge-name"
	challenge.Status.State = cmacme.Processing
	challenge.Status.Reason = "propagation check failed"

	assert.Equal(t, ChallengeInput{
		Name:   "challenge-name",
		State:  cmacme.Processing,
		Reason: "propagation check failed",
	}, ChallengeInputFrom(challenge))
}
