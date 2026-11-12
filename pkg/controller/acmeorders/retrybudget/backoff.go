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
	"strconv"
	"time"
)

const (
	// defaultMinBackoff is the delay used for the first retry and the floor
	// for every computed window. It matches the base delay of the orders
	// controller work queue rate limiter.
	defaultMinBackoff = 5 * time.Second

	// defaultMaxBackoff caps the exponential growth of the retry window.
	// It matches the maximum delay of the orders controller rate limiter.
	defaultMaxBackoff = 30 * time.Minute
)

// ExponentialBackoff returns the waiting duration for the given zero-based
// attempt, growing as minBackoff * 2^attempt and saturating at maxBackoff.
// Non-positive minBackoff/maxBackoff values are replaced by the package
// defaults; a negative attempt is treated as zero. The function never
// overflows and always returns a positive duration.
func ExponentialBackoff(attempt int, minBackoff, maxBackoff time.Duration) time.Duration {
	if minBackoff <= 0 {
		minBackoff = defaultMinBackoff
	}
	if maxBackoff <= 0 || maxBackoff < minBackoff {
		maxBackoff = defaultMaxBackoff
	}
	if attempt < 0 {
		attempt = 0
	}

	delay := minBackoff
	for range attempt {
		next := delay * 2
		// Stop doubling on saturation or once the cap is reached.
		if next <= 0 || next < delay || next >= maxBackoff {
			delay = maxBackoff
			break
		}
		delay = next
	}

	return delay
}

// ParseRetryAfter parses an HTTP Retry-After header value (RFC 9110
// section 10.2.3) relative to now. Both the delta-seconds form and the
// absolute HTTP-date form are supported. A negative delta is normalised to
// zero. The boolean result is false when the header is empty or invalid.
func ParseRetryAfter(header string, now time.Time) (time.Duration, bool) {
	if header == "" {
		return 0, false
	}

	if seconds, err := strconv.Atoi(header); err == nil {
		if seconds < 0 {
			return 0, true
		}
		return time.Duration(seconds) * time.Second, true
	}

	date, err := http.ParseTime(header)
	if err != nil {
		return 0, false
	}

	d := date.Sub(now)
	if d < 0 {
		return 0, true
	}
	return d, true
}

// waitWindow determines the earliest time at which the Order may be
// reconciled again and the duration to wait from now. The exponential
// backoff always applies; every non-zero absolute hint (server Retry-After,
// account rate limit, error Retry-After) may only extend the window.
func waitWindow(now time.Time, attempt int, cfg Config, hints ...time.Time) (time.Time, time.Duration) {
	earliest := now.Add(ExponentialBackoff(attempt, cfg.MinBackoff, cfg.MaxBackoff))
	for _, hint := range hints {
		if hint.After(earliest) {
			earliest = hint
		}
	}
	return earliest, earliest.Sub(now)
}
