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
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmeapi "github.com/cert-manager/cert-manager/third_party/forked/acme"
)

func acmeError(statusCode int, problemType string, retryAfter ...string) *acmeapi.Error {
	e := &acmeapi.Error{
		StatusCode:  statusCode,
		ProblemType: problemType,
		Detail:      "test problem",
	}
	if len(retryAfter) > 0 {
		e.Header = http.Header{}
		e.Header.Set("Retry-After", retryAfter[0])
	}
	return e
}

func TestClassifyError(t *testing.T) {
	rateLimitedURN := "urn:ietf:params:acme:error:rateLimited"

	tests := []struct {
		name string
		err  error
		want ErrorClassification
	}{
		{
			name: "nil error produces zero classification",
			err:  nil,
			want: ErrorClassification{},
		},
		{
			name: "plain transport error is retryable",
			err:  errors.New("dial tcp: connection refused"),
			want: ErrorClassification{Class: ErrorClassRetryable, Reason: ReasonNetworkError},
		},
		{
			name: "wrapped transport error is retryable",
			err:  fmt.Errorf("GetOrder failed: %w", errors.New("i/o timeout")),
			want: ErrorClassification{Class: ErrorClassRetryable, Reason: ReasonNetworkError},
		},
		{
			name: "unsupported profiles sentinel is terminal",
			err:  acmeapi.ErrCADoesNotSupportProfiles,
			want: ErrorClassification{Class: ErrorClassTerminal, Reason: ReasonUnsupportedFeature},
		},
		{
			name: "wrapped unsupported profile sentinel is terminal",
			err:  fmt.Errorf("authorize order: %w", acmeapi.ErrProfileNotInSetOfSupportedProfiles),
			want: ErrorClassification{Class: ErrorClassTerminal, Reason: ReasonUnsupportedFeature},
		},
		{
			name: "rateLimited problem with Retry-After is retryable and honours the header",
			err:  acmeError(http.StatusTooManyRequests, rateLimitedURN, "120"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonRateLimited,
				RateLimited: true,
				RetryAfter:  120 * time.Second,
				StatusCode:  http.StatusTooManyRequests,
				ProblemType: rateLimitedURN,
			},
		},
		{
			name: "rateLimited problem with 400 status is still retryable",
			err:  acmeError(http.StatusBadRequest, rateLimitedURN),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonRateLimited,
				RateLimited: true,
				StatusCode:  http.StatusBadRequest,
				ProblemType: rateLimitedURN,
			},
		},
		{
			name: "rateLimited problem with legacy URN namespace is recognised",
			err:  acmeError(http.StatusTooManyRequests, "urn:acme:error:rateLimited"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonRateLimited,
				RateLimited: true,
				StatusCode:  http.StatusTooManyRequests,
				ProblemType: "urn:acme:error:rateLimited",
			},
		},
		{
			name: "HTTP 429 with unknown problem type is treated as rate limiting",
			err:  acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:unknown", "30"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonRateLimited,
				RateLimited: true,
				RetryAfter:  30 * time.Second,
				StatusCode:  http.StatusTooManyRequests,
				ProblemType: "urn:ietf:params:acme:error:unknown",
			},
		},
		{
			name: "badNonce 400 is retryable",
			err:  acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:badNonce"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonBadNonce,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:badNonce",
			},
		},
		{
			name: "orderNotReady is retryable",
			err:  acmeError(http.StatusForbidden, "urn:ietf:params:acme:error:orderNotReady"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonOrderNotReady,
				StatusCode:  http.StatusForbidden,
				ProblemType: "urn:ietf:params:acme:error:orderNotReady",
			},
		},
		{
			name: "alreadyReplaced is retryable",
			err:  acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:alreadyReplaced"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonAlreadyReplaced,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:alreadyReplaced",
			},
		},
		{
			name: "serverInternal 500 is retryable",
			err:  acmeError(http.StatusInternalServerError, "urn:ietf:params:acme:error:serverInternal", "15"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonServerError,
				RetryAfter:  15 * time.Second,
				StatusCode:  http.StatusInternalServerError,
				ProblemType: "urn:ietf:params:acme:error:serverInternal",
			},
		},
		{
			name: "connection problem is retryable network error",
			err:  acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:connection"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonNetworkError,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:connection",
			},
		},
		{
			name: "tls problem is retryable network error",
			err:  acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:tls"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonNetworkError,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:tls",
			},
		},
		{
			name: "plain 503 without problem type is retryable",
			err:  acmeError(http.StatusServiceUnavailable, ""),
			want: ErrorClassification{
				Class:      ErrorClassRetryable,
				Reason:     ReasonServerError,
				StatusCode: http.StatusServiceUnavailable,
			},
		},
		{
			name: "malformed 400 is terminal",
			err:  acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:malformed"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:malformed",
			},
		},
		{
			name: "unauthorized 403 is terminal",
			err:  acmeError(http.StatusForbidden, "urn:ietf:params:acme:error:unauthorized"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusForbidden,
				ProblemType: "urn:ietf:params:acme:error:unauthorized",
			},
		},
		{
			name: "userActionRequired is terminal",
			err:  acmeError(http.StatusForbidden, "urn:ietf:params:acme:error:userActionRequired"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusForbidden,
				ProblemType: "urn:ietf:params:acme:error:userActionRequired",
			},
		},
		{
			name: "caa problem is terminal",
			err:  acmeError(http.StatusForbidden, "urn:ietf:params:acme:error:caa"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusForbidden,
				ProblemType: "urn:ietf:params:acme:error:caa",
			},
		},
		{
			name: "invalidCSR problem is terminal",
			err:  acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:invalidCSR"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:invalidCSR",
			},
		},
		{
			name: "rejectedIdentifier problem is terminal",
			err:  acmeError(http.StatusForbidden, "urn:ietf:params:acme:error:rejectedIdentifier"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusForbidden,
				ProblemType: "urn:ietf:params:acme:error:rejectedIdentifier",
			},
		},
		{
			name: "unknown 404 problem is terminal by status code",
			err:  acmeError(http.StatusNotFound, "urn:ietf:params:acme:error:somethingNew"),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusNotFound,
				ProblemType: "urn:ietf:params:acme:error:somethingNew",
			},
		},
		{
			name: "unrecognised problem without a 4xx/5xx status defaults to retryable",
			err:  acmeError(0, "urn:ietf:params:acme:error:somethingNew"),
			want: ErrorClassification{
				Class:       ErrorClassRetryable,
				Reason:      ReasonNetworkError,
				StatusCode:  0,
				ProblemType: "urn:ietf:params:acme:error:somethingNew",
			},
		},
		{
			name: "wrapped ACME error is still classified",
			err:  fmt.Errorf("failed to fetch order: %w", acmeError(http.StatusBadRequest, "urn:ietf:params:acme:error:malformed")),
			want: ErrorClassification{
				Class:       ErrorClassTerminal,
				Reason:      ReasonBadRequest,
				StatusCode:  http.StatusBadRequest,
				ProblemType: "urn:ietf:params:acme:error:malformed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyError(tt.err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProblemSuffix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"urn:ietf:params:acme:error:rateLimited", "ratelimited"},
		{"urn:acme:error:BadNonce", "badnonce"},
		{"rateLimited", "ratelimited"},
		{"  urn:ietf:params:acme:error:CAA  ", "caa"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, problemSuffix(tt.input))
		})
	}
}

func TestHeaderRetryAfter(t *testing.T) {
	t.Run("nil error returns zero", func(t *testing.T) {
		assert.Zero(t, headerRetryAfter(nil))
	})

	t.Run("error without headers returns zero", func(t *testing.T) {
		assert.Zero(t, headerRetryAfter(&acmeapi.Error{}))
	})

	t.Run("delta seconds are parsed", func(t *testing.T) {
		e := acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited", "45")
		assert.Equal(t, 45*time.Second, headerRetryAfter(e))
	})

	t.Run("invalid header returns zero", func(t *testing.T) {
		e := acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited", "not-a-date")
		assert.Zero(t, headerRetryAfter(e))
	})

	t.Run("absolute HTTP date is parsed relative to now", func(t *testing.T) {
		date := time.Now().Add(60 * time.Second).UTC().Format(http.TimeFormat)
		e := acmeError(http.StatusTooManyRequests, "urn:ietf:params:acme:error:rateLimited", date)
		require.InDelta(t, 60*time.Second, headerRetryAfter(e), float64(2*time.Second))
	})
}
