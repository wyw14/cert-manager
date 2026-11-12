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
	"errors"
	"net/http"
	"strings"
	"time"

	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

// ErrorClass classifies an error observed while reconciling an ACME Order.
type ErrorClass string

const (
	// ErrorClassRetryable marks errors that may clear on their own and for
	// which retrying after a backoff window is appropriate.
	ErrorClassRetryable ErrorClass = "Retryable"

	// ErrorClassTerminal marks errors that retrying the same Order cannot
	// resolve. A new Order (or a human intervention) is required instead.
	ErrorClassTerminal ErrorClass = "Terminal"
)

// ErrorClassification is the result of ClassifyError. The zero value
// represents the absence of an error.
type ErrorClassification struct {
	// Class states whether the error may be retried.
	Class ErrorClass

	// Reason is a short, machine-readable explanation of the classification.
	Reason string

	// RateLimited is true when the error is caused by an ACME rate limit
	// (either a rateLimited problem or an HTTP 429 response).
	RateLimited bool

	// RetryAfter is the waiting period requested by the server through a
	// Retry-After header. It is zero when the server did not provide one.
	RetryAfter time.Duration

	// StatusCode is the HTTP status code carried by an ACME problem, or zero
	// for errors that did not originate from an ACME response.
	StatusCode int

	// ProblemType is the ACME problem URN as returned by the server. It is
	// empty for non-ACME errors.
	ProblemType string
}

// terminalProblemTypes lists ACME problem suffixes (RFC 8555 section 6.7 and
// common server-specific extensions) describing a condition that retrying the
// same Order cannot resolve. Matching is case-insensitive and ignores the
// problem URN namespace so that both the RFC 8555 and legacy namespaces are
// handled.
var terminalProblemTypes = map[string]struct{}{
	"accountdoesnotexist":           {},
	"malformed":                     {},
	"unauthorized":                  {},
	"badsignaturealgorithm":         {},
	"unsupportedsignaturealgorithm": {},
	"invalidsignature":              {},
	"invalidcontact":                {},
	"unsupportedcontact":            {},
	"rejectedidentifier":            {},
	"unsupportedidentifier":         {},
	"unsupportedchallenge":          {},
	"agreementrequired":             {},
	"useractionrequired":            {},
	"incorrectresponse":             {},
	"caa":                           {},
	"invalidcsr":                    {},
	"externalaccountrequired":       {},
	"badrevocationreason":           {},
	"alreadyrevoked":                {},
}

// ClassifyError decides whether an error observed while interacting with an
// ACME server should be retried or treated as terminal. It never performs any
// network or API access: it only inspects the error handed to it.
//
// A nil error produces the zero ErrorClassification. Errors that do not carry
// an ACME problem (for example local network failures) are assumed to be
// transient and are classified as retryable.
func ClassifyError(err error) ErrorClassification {
	if err == nil {
		return ErrorClassification{}
	}

	// Local sentinel errors explicitly mean that the current Order cannot
	// proceed and must not be retried as-is.
	for _, sentinel := range []error{
		acmeapi.ErrCADoesNotSupportProfiles,
		acmeapi.ErrProfileNotInSetOfSupportedProfiles,
	} {
		if errors.Is(err, sentinel) {
			return ErrorClassification{
				Class:  ErrorClassTerminal,
				Reason: ReasonUnsupportedFeature,
			}
		}
	}

	acmeErr, ok := errors.AsType[*acmeapi.Error](err)
	if !ok {
		// Not an ACME server problem: treat local and transport failures as
		// transient rather than failing the Order permanently.
		return ErrorClassification{
			Class:  ErrorClassRetryable,
			Reason: ReasonNetworkError,
		}
	}

	c := ErrorClassification{
		StatusCode:  acmeErr.StatusCode,
		ProblemType: acmeErr.ProblemType,
	}

	// Rate limiting is always retryable regardless of the HTTP status code;
	// servers signal it with both 400 and 429 responses.
	if d, limited := acmeapi.RateLimit(err); limited {
		c.Class = ErrorClassRetryable
		c.Reason = ReasonRateLimited
		c.RateLimited = true
		c.RetryAfter = d
		return c
	}

	// An HTTP 429 without a recognised rateLimited problem type still means
	// "too many requests" and must be retried after the indicated delay.
	if acmeErr.StatusCode == http.StatusTooManyRequests {
		c.Class = ErrorClassRetryable
		c.Reason = ReasonRateLimited
		c.RateLimited = true
		c.RetryAfter = headerRetryAfter(acmeErr)
		return c
	}

	switch problemSuffix(acmeErr.ProblemType) {
	case "badnonce":
		c.Class = ErrorClassRetryable
		c.Reason = ReasonBadNonce
	case "ordernotready":
		c.Class = ErrorClassRetryable
		c.Reason = ReasonOrderNotReady
	case "alreadyreplaced":
		// The caller is expected to retry the newOrder request without the
		// ARI "replaces" field; the condition clears on the next attempt.
		c.Class = ErrorClassRetryable
		c.Reason = ReasonAlreadyReplaced
	case "serverinternal":
		c.Class = ErrorClassRetryable
		c.Reason = ReasonServerError
		c.RetryAfter = headerRetryAfter(acmeErr)
	case "connection", "tls":
		c.Class = ErrorClassRetryable
		c.Reason = ReasonNetworkError
		c.RetryAfter = headerRetryAfter(acmeErr)
	default:
		c = classifyByStatusCode(c, acmeErr)
	}

	return c
}

// classifyByStatusCode falls back to the HTTP status code for problem types
// that are not listed explicitly, preserving the controller's historical
// behaviour: 4xx responses are terminal while everything else is retryable.
func classifyByStatusCode(c ErrorClassification, acmeErr *acmeapi.Error) ErrorClassification {
	if _, terminal := terminalProblemTypes[problemSuffix(acmeErr.ProblemType)]; terminal {
		c.Class = ErrorClassTerminal
		c.Reason = ReasonBadRequest
		return c
	}

	switch {
	case acmeErr.StatusCode >= 500:
		c.Class = ErrorClassRetryable
		c.Reason = ReasonServerError
		c.RetryAfter = headerRetryAfter(acmeErr)
	case acmeErr.StatusCode >= 400 && acmeErr.StatusCode < 500:
		c.Class = ErrorClassTerminal
		c.Reason = ReasonBadRequest
	default:
		c.Class = ErrorClassRetryable
		c.Reason = ReasonNetworkError
		c.RetryAfter = headerRetryAfter(acmeErr)
	}

	return c
}

// headerRetryAfter extracts the Retry-After waiting period, if any, from an
// ACME error response. A missing or invalid header yields zero.
func headerRetryAfter(acmeErr *acmeapi.Error) time.Duration {
	if acmeErr == nil || acmeErr.Header == nil {
		return 0
	}
	d, ok := ParseRetryAfter(acmeErr.Header.Get("Retry-After"), time.Now())
	if !ok {
		return 0
	}
	return d
}

// problemSuffix returns the final colon-separated component of an ACME
// problem URN in lower case (for example "ratelimited"), or the whole lower
// cased string when it does not contain a colon.
func problemSuffix(problemType string) string {
	pt := strings.ToLower(strings.TrimSpace(problemType))
	if _, suffix, ok := strings.CutLast(pt, ":"); ok {
		return suffix
	}
	return pt
}
