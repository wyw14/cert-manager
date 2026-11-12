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

// Package renewal provides an offline decision-maker for the certificate
// renewal window.
//
// The decision-maker only consumes plain values (NotBefore, NotAfter,
// renewBefore, an allowed clock skew and a failure back-off summary) and an
// injectable clock. It never creates or parses a CSR, reads a private key,
// decodes a certificate or performs any I/O, including ACME calls. Given the
// same evaluated time and Input, Decide always returns the same Result, which
// makes the decision fully deterministic and reproducible.
package renewal

import (
	"fmt"
	"time"

	"k8s.io/utils/clock"
)

// Decision is the outcome of an offline renewal-window evaluation.
type Decision string

const (
	// DecisionRenewNow means the certificate is still valid but its renewal
	// window has been reached (or is within the allowed clock skew of it), so
	// a renewal should be attempted unless failure back-off applies.
	DecisionRenewNow Decision = "RenewNow"
	// DecisionWait means the certificate is still valid and its renewal
	// window has not been reached, or renewal is currently delayed by failure
	// back-off.
	DecisionWait Decision = "Wait"
	// DecisionExpired means the certificate has expired, or is within the
	// allowed clock skew of expiry in which case a peer clock may already
	// consider it expired.
	DecisionExpired Decision = "Expired"
	// DecisionUndecidable means the Input does not describe a state in which
	// a sound renewal decision can be made offline: malformed validity bounds,
	// an invalid renewBefore extension, or a certificate that is not yet valid.
	DecisionUndecidable Decision = "Undecidable"
)

// Rule identifies the single rule that produced a Decision. Rule values are
// stable identifiers intended for logs, events and metrics; their strings
// must not be parsed by callers.
type Rule string

const (
	// RuleInvalidNotBefore fires when NotBefore is the zero time.
	RuleInvalidNotBefore Rule = "InvalidNotBefore"
	// RuleInvalidNotAfter fires when NotAfter is the zero time.
	RuleInvalidNotAfter Rule = "InvalidNotAfter"
	// RuleInvalidValidityOrder fires when NotBefore is not strictly before
	// NotAfter.
	RuleInvalidValidityOrder Rule = "InvalidValidityOrder"
	// RuleInvalidClockSkew fires when the allowed clock skew is negative.
	RuleInvalidClockSkew Rule = "InvalidClockSkew"
	// RuleInvalidRenewBefore fires when renewBefore is negative.
	RuleInvalidRenewBefore Rule = "InvalidRenewBefore"
	// RuleRenewBeforeExceedsLifetime fires when renewBefore is at least as
	// long as the certificate lifetime, which would open the renewal window
	// at or before NotBefore.
	RuleRenewBeforeExceedsLifetime Rule = "RenewBeforeExceedsLifetime"
	// RuleCertificateNotYetValid fires when the evaluated time is more than
	// the allowed clock skew before NotBefore: the certificate has not become
	// valid yet, so its renewal window cannot be evaluated.
	RuleCertificateNotYetValid Rule = "CertificateNotYetValid"
	// RuleNotBeforeWithinClockSkew fires when the evaluated time is before
	// NotBefore but within the allowed clock skew. The validity boundary
	// cannot be resolved offline and the decision is left undecidable.
	RuleNotBeforeWithinClockSkew Rule = "NotBeforeWithinClockSkew"
	// RuleExpired fires when the evaluated time is strictly after NotAfter.
	RuleExpired Rule = "Expired"
	// RuleExpiredAtBoundary fires when the evaluated time equals NotAfter
	// exactly. X.509 validity is the half-open interval [NotBefore, NotAfter),
	// so the certificate is expired at that instant.
	RuleExpiredAtBoundary Rule = "ExpiredAtBoundary"
	// RuleExpiryWithinClockSkew fires when the evaluated time is within the
	// allowed clock skew before NotAfter: a peer clock that is ahead may
	// already consider the certificate expired, so it is classified as
	// expired rather than merely due for renewal.
	RuleExpiryWithinClockSkew Rule = "ExpiryWithinClockSkew"
	// RuleBackoffActive fires while a previous failed issuance is still being
	// backed off: the certificate remains valid but renewal must wait until
	// NextRetry.
	RuleBackoffActive Rule = "BackoffActive"
	// RuleRenewalWindowReached fires when the evaluated time is strictly after
	// the computed renewal time.
	RuleRenewalWindowReached Rule = "RenewalWindowReached"
	// RuleRenewalAtBoundary fires when the evaluated time equals the computed
	// renewal time exactly.
	RuleRenewalAtBoundary Rule = "RenewalAtBoundary"
	// RuleRenewalWindowWithinClockSkew fires when the evaluated time is within
	// the allowed clock skew before the renewal time: renewing early prevents
	// a peer clock that is ahead from missing the renewal window.
	RuleRenewalWindowWithinClockSkew Rule = "RenewalWindowWithinClockSkew"
	// RuleBeforeRenewalWindow fires when the evaluated time is more than the
	// allowed clock skew before the renewal time: the certificate should keep
	// waiting.
	RuleBeforeRenewalWindow Rule = "BeforeRenewalWindow"
)

// BackoffSummary is the offline view of the failure back-off state. It is a
// plain summary rather than a Kubernetes or controller object, so that the
// decision stays reproducible without API access, request listers or private
// key material.
type BackoffSummary struct {
	// NextRetry is the earliest time at which a renewal may be attempted.
	// The zero time means that no back-off is active.
	NextRetry time.Time
}

// Input holds the values required to evaluate the renewal window offline.
type Input struct {
	// NotBefore and NotAfter are the certificate validity bounds.
	NotBefore time.Time
	NotAfter  time.Time

	// RenewBefore is how long before NotAfter the renewal window opens. A nil
	// value selects the default of one third of the certificate lifetime
	// (i.e. renewal two thirds through the certificate's lifetime).
	RenewBefore *time.Duration

	// ClockSkew is the maximum tolerated difference between this node's clock
	// and the clocks of peers. It must be zero or positive.
	ClockSkew time.Duration

	// Backoff summarizes previous failed issuance attempts. A nil value (or a
	// BackoffSummary with a zero NextRetry) means no back-off is active.
	Backoff *BackoffSummary
}

// Result is the outcome of evaluating the renewal window.
type Result struct {
	// Decision is the renewal decision.
	Decision Decision
	// Rule is the single rule that produced the Decision.
	Rule Rule
	// Message is a human-readable description of why the rule fired.
	Message string
	// RenewalTime is the computed renewal instant. It is zero when the Input
	// could not be validated.
	RenewalTime time.Time
	// RetryAfter is the remaining back-off delay. It is non-zero only when
	// Rule is RuleBackoffActive.
	RetryAfter time.Duration
}

// Decide evaluates the renewal window at the given time. It is a pure
// function: it performs no I/O, uses no randomness and never reads the wall
// clock, so identical arguments always produce an identical result.
//
// The rules are evaluated in this precedence order:
//  1. input validation (invalid bounds, skew or renewBefore) -> Undecidable;
//  2. the NotBefore boundary, including the clock-skew zone -> Undecidable;
//  3. the NotAfter boundary, including the clock-skew zone -> Expired;
//  4. failure back-off, while the certificate is still valid -> Wait;
//  5. the renewal window, including the clock-skew zone -> RenewNow or Wait.
func Decide(now time.Time, in Input) Result {
	// 1. Validate the inputs. Invalid state can never yield a sound decision.
	if in.NotBefore.IsZero() {
		return undecidable(RuleInvalidNotBefore, "certificate NotBefore is not set")
	}
	if in.NotAfter.IsZero() {
		return undecidable(RuleInvalidNotAfter, "certificate NotAfter is not set")
	}
	if !in.NotBefore.Before(in.NotAfter) {
		return undecidable(RuleInvalidValidityOrder, fmt.Sprintf(
			"invalid certificate validity bounds: NotBefore %s is not before NotAfter %s",
			in.NotBefore.UTC().Format(time.RFC3339), in.NotAfter.UTC().Format(time.RFC3339)))
	}
	if in.ClockSkew < 0 {
		return undecidable(RuleInvalidClockSkew, fmt.Sprintf(
			"clock skew must be zero or positive, got %s", in.ClockSkew))
	}

	lifetime := in.NotAfter.Sub(in.NotBefore)
	if in.RenewBefore != nil {
		switch {
		case *in.RenewBefore < 0:
			return undecidable(RuleInvalidRenewBefore, fmt.Sprintf(
				"renewBefore must be zero or positive, got %s", *in.RenewBefore))
		case *in.RenewBefore >= lifetime:
			return undecidable(RuleRenewBeforeExceedsLifetime, fmt.Sprintf(
				"renewBefore %s is not shorter than the certificate lifetime of %s",
				*in.RenewBefore, lifetime))
		}
	}

	// 2. Classify the NotBefore boundary. A certificate that is not yet valid
	// has no meaningful renewal window; within the clock-skew zone the boundary
	// is ambiguous and is reported with a dedicated rule rather than guessed.
	if now.Before(in.NotBefore) {
		if distance := in.NotBefore.Sub(now); distance > in.ClockSkew {
			return undecidable(RuleCertificateNotYetValid, fmt.Sprintf(
				"certificate is not valid before %s, which is more than the allowed clock skew of %s away",
				in.NotBefore.UTC().Format(time.RFC3339), in.ClockSkew))
		}
		return undecidable(RuleNotBeforeWithinClockSkew, fmt.Sprintf(
			"current time %s is before NotBefore %s but within the allowed clock skew of %s",
			now.UTC().Format(time.RFC3339), in.NotBefore.UTC().Format(time.RFC3339), in.ClockSkew))
	}

	// 3. Compute the renewal time from the validated inputs. Truncation to the
	// nearest second mirrors the renewal time persisted on Certificate status
	// by the controllers.
	renewBefore := lifetime / 3
	if in.RenewBefore != nil {
		renewBefore = *in.RenewBefore
	}
	renewalTime := in.NotAfter.Add(-renewBefore).Truncate(time.Second)

	// 4. Classify the NotAfter boundary. The X.509 validity interval excludes
	// NotAfter itself, and the clock-skew zone before it is treated as expired
	// because a peer clock may already be past expiry.
	switch {
	case now.After(in.NotAfter):
		return Result{
			Decision:    DecisionExpired,
			Rule:        RuleExpired,
			Message:     fmt.Sprintf("certificate expired at %s", in.NotAfter.UTC().Format(time.RFC3339)),
			RenewalTime: renewalTime,
		}
	case now.Equal(in.NotAfter):
		return Result{
			Decision:    DecisionExpired,
			Rule:        RuleExpiredAtBoundary,
			Message:     fmt.Sprintf("current time equals the NotAfter boundary %s, at which the certificate is no longer valid", in.NotAfter.UTC().Format(time.RFC3339)),
			RenewalTime: renewalTime,
		}
	case in.NotAfter.Sub(now) <= in.ClockSkew:
		return Result{
			Decision:    DecisionExpired,
			Rule:        RuleExpiryWithinClockSkew,
			Message:     fmt.Sprintf("certificate expires at %s, within the allowed clock skew of %s", in.NotAfter.UTC().Format(time.RFC3339), in.ClockSkew),
			RenewalTime: renewalTime,
		}
	}

	// 5. Apply failure back-off while the certificate is still valid. Expiry
	// takes precedence over back-off so that an expired certificate is never
	// reported as merely waiting.
	if in.Backoff != nil && !in.Backoff.NextRetry.IsZero() && in.Backoff.NextRetry.After(now) {
		return Result{
			Decision:    DecisionWait,
			Rule:        RuleBackoffActive,
			Message:     fmt.Sprintf("renewal is backed off until %s", in.Backoff.NextRetry.UTC().Format(time.RFC3339)),
			RenewalTime: renewalTime,
			RetryAfter:  in.Backoff.NextRetry.Sub(now),
		}
	}

	// 6. Classify the renewal window. The clock-skew zone before the renewal
	// time renews early so that a faster peer clock does not miss the window.
	switch {
	case now.Equal(renewalTime):
		return Result{
			Decision:    DecisionRenewNow,
			Rule:        RuleRenewalAtBoundary,
			Message:     fmt.Sprintf("current time equals the renewal time %s", renewalTime.UTC().Format(time.RFC3339)),
			RenewalTime: renewalTime,
		}
	case now.After(renewalTime):
		return Result{
			Decision:    DecisionRenewNow,
			Rule:        RuleRenewalWindowReached,
			Message:     fmt.Sprintf("renewal time %s has been reached", renewalTime.UTC().Format(time.RFC3339)),
			RenewalTime: renewalTime,
		}
	case renewalTime.Sub(now) <= in.ClockSkew:
		return Result{
			Decision:    DecisionRenewNow,
			Rule:        RuleRenewalWindowWithinClockSkew,
			Message:     fmt.Sprintf("renewal time %s is within the allowed clock skew of %s", renewalTime.UTC().Format(time.RFC3339), in.ClockSkew),
			RenewalTime: renewalTime,
		}
	default:
		return Result{
			Decision:    DecisionWait,
			Rule:        RuleBeforeRenewalWindow,
			Message:     fmt.Sprintf("renewal window opens at %s", renewalTime.UTC().Format(time.RFC3339)),
			RenewalTime: renewalTime,
		}
	}
}

// DecideNow evaluates the renewal window using the current time read from the
// given clock. Injecting a clock (for example a fake clock in tests) is the
// only way the evaluated time is sourced, which keeps the decision
// deterministic and reproducible.
func DecideNow(c clock.Clock, in Input) Result {
	return Decide(c.Now(), in)
}

func undecidable(rule Rule, message string) Result {
	return Result{
		Decision: DecisionUndecidable,
		Rule:     rule,
		Message:  message,
	}
}
