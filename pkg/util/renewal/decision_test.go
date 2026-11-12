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

package renewal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	fakeclock "k8s.io/utils/clock/testing"
)

var (
	notBefore = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = notBefore.Add(24 * time.Hour)
)

func TestDecide(t *testing.T) {
	const skew = time.Hour

	tests := map[string]struct {
		now             time.Time
		in              Input
		wantDecision    Decision
		wantRule        Rule
		wantRetryAfter  *time.Duration
		wantRenewalTime *time.Time
	}{
		// --- Invalid inputs: Undecidable ---
		"zero NotBefore is undecidable": {
			now:          notBefore.Add(time.Hour),
			in:           Input{NotAfter: notAfter, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleInvalidNotBefore,
		},
		"zero NotAfter is undecidable": {
			now:          notBefore.Add(time.Hour),
			in:           Input{NotBefore: notBefore, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleInvalidNotAfter,
		},
		"NotBefore equal to NotAfter is undecidable": {
			now:          notBefore,
			in:           Input{NotBefore: notAfter, NotAfter: notAfter, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleInvalidValidityOrder,
		},
		"NotBefore after NotAfter is undecidable": {
			now:          notBefore,
			in:           Input{NotBefore: notAfter, NotAfter: notBefore, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleInvalidValidityOrder,
		},
		"negative clock skew is undecidable": {
			now:          notBefore.Add(time.Hour),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: -time.Second},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleInvalidClockSkew,
		},
		"negative renewBefore is undecidable": {
			now:          notBefore.Add(time.Hour),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(-time.Hour)},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleInvalidRenewBefore,
		},
		"renewBefore equal to the lifetime is undecidable": {
			now:          notBefore.Add(time.Hour),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(24 * time.Hour)},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleRenewBeforeExceedsLifetime,
		},
		"renewBefore greater than the lifetime is undecidable": {
			now:          notBefore.Add(time.Hour),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(25 * time.Hour)},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleRenewBeforeExceedsLifetime,
		},

		// --- NotBefore boundary ---
		"now more than the skew before NotBefore is undecidable": {
			now:          notBefore.Add(-2 * time.Hour),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleCertificateNotYetValid,
		},
		"now before NotBefore beyond the skew with zero skew is undecidable": {
			now:          notBefore.Add(-time.Second),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleCertificateNotYetValid,
		},
		"now exactly one skew before NotBefore is a skew boundary": {
			now:          notBefore.Add(-skew),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleNotBeforeWithinClockSkew,
		},
		"now within the skew before NotBefore is a skew boundary": {
			now:          notBefore.Add(-30 * time.Minute),
			in:           Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew},
			wantDecision: DecisionUndecidable,
			wantRule:     RuleNotBeforeWithinClockSkew,
		},
		"now exactly at NotBefore is valid and waits for the window": {
			now:             notBefore,
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionWait,
			wantRule:        RuleBeforeRenewalWindow,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},

		// --- NotAfter boundary ---
		"now strictly after NotAfter is expired": {
			now:             notAfter.Add(time.Second),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionExpired,
			wantRule:        RuleExpired,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now exactly at NotAfter is an expired boundary": {
			now:             notAfter,
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionExpired,
			wantRule:        RuleExpiredAtBoundary,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now within the skew before NotAfter is classified as expired": {
			now:             notAfter.Add(-30 * time.Minute),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionExpired,
			wantRule:        RuleExpiryWithinClockSkew,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now exactly one skew before NotAfter is an expiry skew boundary": {
			now:             notAfter.Add(-skew),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionExpired,
			wantRule:        RuleExpiryWithinClockSkew,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now beyond the skew before NotAfter is not expired and past the renewal time": {
			now:             notAfter.Add(-2 * time.Hour),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowReached,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"one second before NotAfter with zero skew is not expired": {
			now:             notAfter.Add(-time.Second),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowReached,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},

		// --- Renewal window boundary (renewBefore 6h -> renewal at 18:00) ---
		"now exactly at the renewal time is a renewal boundary": {
			now:             notBefore.Add(18 * time.Hour),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalAtBoundary,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now after the renewal time renews now": {
			now:             notBefore.Add(18*time.Hour + time.Second),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowReached,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now within the skew before the renewal time renews early": {
			now:             notBefore.Add(17*time.Hour + 30*time.Minute),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowWithinClockSkew,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now exactly one skew before the renewal time is a renewal skew boundary": {
			now:             notBefore.Add(17 * time.Hour),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowWithinClockSkew,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"now beyond the skew before the renewal time keeps waiting": {
			now:             notBefore.Add(16 * time.Hour),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionWait,
			wantRule:        RuleBeforeRenewalWindow,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"one second before the renewal time with zero skew waits": {
			now:             notBefore.Add(18*time.Hour - time.Second),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour)},
			wantDecision:    DecisionWait,
			wantRule:        RuleBeforeRenewalWindow,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},

		// --- Default renewBefore: one third of a 24h lifetime -> renewal at 16:00 ---
		"nil renewBefore defaults to one third of the lifetime": {
			now:             notBefore.Add(16 * time.Hour),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: skew},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalAtBoundary,
			wantRenewalTime: new(notBefore.Add(16 * time.Hour)),
		},
		"nil renewBefore waits before the default renewal time": {
			now:             notBefore.Add(16*time.Hour - time.Second),
			in:              Input{NotBefore: notBefore, NotAfter: notAfter},
			wantDecision:    DecisionWait,
			wantRule:        RuleBeforeRenewalWindow,
			wantRenewalTime: new(notBefore.Add(16 * time.Hour)),
		},

		// --- Failure back-off ---
		"active back-off before the renewal window waits": {
			now: notBefore.Add(12 * time.Hour),
			in: Input{
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				RenewBefore: new(6 * time.Hour),
				Backoff:     &BackoffSummary{NextRetry: notBefore.Add(13 * time.Hour)},
			},
			wantDecision:    DecisionWait,
			wantRule:        RuleBackoffActive,
			wantRetryAfter:  new(time.Hour),
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"active back-off inside the renewal window still waits": {
			now: notBefore.Add(19 * time.Hour),
			in: Input{
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				RenewBefore: new(6 * time.Hour),
				Backoff:     &BackoffSummary{NextRetry: notBefore.Add(20 * time.Hour)},
			},
			wantDecision:    DecisionWait,
			wantRule:        RuleBackoffActive,
			wantRetryAfter:  new(time.Hour),
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"elapsed back-off does not delay renewal": {
			now: notBefore.Add(19 * time.Hour),
			in: Input{
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				RenewBefore: new(6 * time.Hour),
				Backoff:     &BackoffSummary{NextRetry: notBefore.Add(18 * time.Hour)},
			},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowReached,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"back-off with zero NextRetry is ignored": {
			now: notBefore.Add(19 * time.Hour),
			in: Input{
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				RenewBefore: new(6 * time.Hour),
				Backoff:     &BackoffSummary{},
			},
			wantDecision:    DecisionRenewNow,
			wantRule:        RuleRenewalWindowReached,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
		"expiry takes precedence over active back-off": {
			now: notAfter.Add(time.Hour),
			in: Input{
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				RenewBefore: new(6 * time.Hour),
				Backoff:     &BackoffSummary{NextRetry: notAfter.Add(2 * time.Hour)},
			},
			wantDecision:    DecisionExpired,
			wantRule:        RuleExpired,
			wantRenewalTime: new(notBefore.Add(18 * time.Hour)),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := Decide(test.now, test.in)

			assert.Equal(t, test.wantDecision, got.Decision, "unexpected decision")
			assert.Equal(t, test.wantRule, got.Rule, "unexpected rule")
			assert.NotEmpty(t, got.Message, "every result must explain the triggering rule")

			if test.wantRetryAfter == nil {
				assert.Zero(t, got.RetryAfter)
			} else {
				assert.Equal(t, *test.wantRetryAfter, got.RetryAfter)
			}

			if test.wantRenewalTime == nil {
				assert.True(t, got.RenewalTime.IsZero(), "undecidable inputs must not yield a renewal time, got %s", got.RenewalTime)
			} else {
				assert.Equal(t, *test.wantRenewalTime, got.RenewalTime)
			}
		})
	}
}

func TestDecideRenewalTimeIsTruncatedToTheSecond(t *testing.T) {
	renewBefore := 6*time.Hour + 500*time.Millisecond
	got := Decide(notBefore.Add(12*time.Hour), Input{
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		RenewBefore: &renewBefore,
	})

	want := notAfter.Add(-renewBefore).Truncate(time.Second)
	assert.Equal(t, want, got.RenewalTime)
	assert.Equal(t, 0, got.RenewalTime.Nanosecond())
}

// TestDecideIsReproducible guarantees that the pure Decide function never
// depends on wall-clock time, randomness or hidden state: repeated evaluation
// of identical inputs must return identical results.
func TestDecideIsReproducible(t *testing.T) {
	now := notBefore.Add(17*time.Hour + 30*time.Minute)
	inputs := []Input{
		{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: time.Hour},
		{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour), ClockSkew: time.Hour},
		{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour), Backoff: &BackoffSummary{NextRetry: notBefore.Add(20 * time.Hour)}},
		{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(-time.Hour)},
	}

	for i, in := range inputs {
		first := Decide(now, in)
		for range 10 {
			assert.Equal(t, first, Decide(now, in), "input %d: decision is not reproducible", i)
		}
	}
}

// TestDecideNowWithInjectedClock verifies that sourcing time exclusively from
// an injected clock makes the decision reproducible across a deterministic
// fake-clock timeline.
func TestDecideNowWithInjectedClock(t *testing.T) {
	fakeClock := fakeclock.NewFakeClock(notBefore.Add(17 * time.Hour))
	in := Input{
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		RenewBefore: new(6 * time.Hour),
		ClockSkew:   time.Hour,
	}

	// DecideNow must be exactly equivalent to Decide with the clock's time.
	assert.Equal(t, Decide(fakeClock.Now(), in), DecideNow(fakeClock, in))

	// Stepping the fake clock must transition the rules deterministically and
	// every repeated evaluation at the same instant must stay identical.
	wantTimeline := []struct {
		step     time.Duration
		decision Decision
		rule     Rule
	}{
		{step: 0, decision: DecisionRenewNow, rule: RuleRenewalWindowWithinClockSkew},
		{step: time.Hour, decision: DecisionRenewNow, rule: RuleRenewalAtBoundary},
		{step: time.Second, decision: DecisionRenewNow, rule: RuleRenewalWindowReached},
		// 18:00:01 + 5h59m59s lands exactly on NotAfter (00:00:00 the next day).
		{step: 5*time.Hour + 59*time.Minute + 59*time.Second, decision: DecisionExpired, rule: RuleExpiredAtBoundary},
	}

	for i, point := range wantTimeline {
		if i > 0 {
			fakeClock.Step(point.step)
		}

		got := DecideNow(fakeClock, in)
		assert.Equal(t, point.decision, got.Decision, "timeline step %d", i)
		assert.Equal(t, point.rule, got.Rule, "timeline step %d", i)
		assert.Equal(t, got, DecideNow(fakeClock, in), "timeline step %d: repeated evaluation differs", i)
		assert.Equal(t, got, Decide(fakeClock.Now(), in), "timeline step %d: DecideNow diverges from Decide", i)
	}
}

// TestEveryRuleIsExercised guards against rules being added without a
// classified scenario covering them.
func TestEveryRuleIsExercised(t *testing.T) {
	allRules := []Rule{
		RuleInvalidNotBefore,
		RuleInvalidNotAfter,
		RuleInvalidValidityOrder,
		RuleInvalidClockSkew,
		RuleInvalidRenewBefore,
		RuleRenewBeforeExceedsLifetime,
		RuleCertificateNotYetValid,
		RuleNotBeforeWithinClockSkew,
		RuleExpired,
		RuleExpiredAtBoundary,
		RuleExpiryWithinClockSkew,
		RuleBackoffActive,
		RuleRenewalWindowReached,
		RuleRenewalAtBoundary,
		RuleRenewalWindowWithinClockSkew,
		RuleBeforeRenewalWindow,
	}

	scenarios := []struct {
		rule Rule
		now  time.Time
		in   Input
	}{
		{rule: RuleInvalidNotBefore, now: notBefore, in: Input{NotAfter: notAfter}},
		{rule: RuleInvalidNotAfter, now: notBefore, in: Input{NotBefore: notBefore}},
		{rule: RuleInvalidValidityOrder, now: notBefore, in: Input{NotBefore: notAfter, NotAfter: notBefore}},
		{rule: RuleInvalidClockSkew, now: notBefore, in: Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: -1}},
		{rule: RuleInvalidRenewBefore, now: notBefore, in: Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(-time.Nanosecond)}},
		{rule: RuleRenewBeforeExceedsLifetime, now: notBefore, in: Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(24 * time.Hour)}},
		{rule: RuleCertificateNotYetValid, now: notBefore.Add(-2 * time.Hour), in: Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: time.Hour}},
		{rule: RuleNotBeforeWithinClockSkew, now: notBefore.Add(-time.Minute), in: Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: time.Hour}},
		{rule: RuleExpired, now: notAfter.Add(time.Second), in: Input{NotBefore: notBefore, NotAfter: notAfter}},
		{rule: RuleExpiredAtBoundary, now: notAfter, in: Input{NotBefore: notBefore, NotAfter: notAfter}},
		{rule: RuleExpiryWithinClockSkew, now: notAfter.Add(-time.Minute), in: Input{NotBefore: notBefore, NotAfter: notAfter, ClockSkew: time.Hour}},
		{rule: RuleBackoffActive, now: notBefore.Add(12 * time.Hour), in: Input{NotBefore: notBefore, NotAfter: notAfter, Backoff: &BackoffSummary{NextRetry: notBefore.Add(13 * time.Hour)}}},
		{rule: RuleRenewalWindowReached, now: notBefore.Add(19 * time.Hour), in: Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour)}},
		{rule: RuleRenewalAtBoundary, now: notBefore.Add(18 * time.Hour), in: Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour)}},
		{rule: RuleRenewalWindowWithinClockSkew, now: notBefore.Add(17*time.Hour + 30*time.Minute), in: Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour), ClockSkew: time.Hour}},
		{rule: RuleBeforeRenewalWindow, now: notBefore, in: Input{NotBefore: notBefore, NotAfter: notAfter, RenewBefore: new(6 * time.Hour)}},
	}

	seen := map[Rule]bool{}
	for _, scenario := range scenarios {
		got := Decide(scenario.now, scenario.in)
		assert.Equal(t, scenario.rule, got.Rule)
		seen[got.Rule] = true
	}

	for _, rule := range allRules {
		assert.True(t, seen[rule], "rule %s has no classified test scenario", rule)
	}
}
