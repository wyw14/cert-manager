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
)

func TestExponentialBackoff(t *testing.T) {
	const minBackoff = 5 * time.Second
	const maxBackoff = time.Minute

	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{"attempt zero uses the minimum", 0, minBackoff},
		{"attempt one doubles", 1, 10 * time.Second},
		{"attempt two quadruples", 2, 20 * time.Second},
		{"attempt three", 3, 40 * time.Second},
		{"growth saturates at the maximum", 4, maxBackoff},
		{"large attempts stay saturated", 100, maxBackoff},
		{"negative attempts are treated as zero", -7, minBackoff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExponentialBackoff(tt.attempt, minBackoff, maxBackoff))
		})
	}

	t.Run("zero configuration falls back to defaults", func(t *testing.T) {
		assert.Equal(t, defaultMinBackoff, ExponentialBackoff(0, 0, 0))
		assert.Equal(t, defaultMaxBackoff, ExponentialBackoff(100, 0, 0))
	})

	t.Run("maximum smaller than minimum is replaced by the default maximum", func(t *testing.T) {
		assert.Equal(t, defaultMaxBackoff, ExponentialBackoff(10, minBackoff, time.Second))
	})
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

	t.Run("empty header", func(t *testing.T) {
		d, ok := ParseRetryAfter("", now)
		assert.False(t, ok)
		assert.Zero(t, d)
	})

	t.Run("delta seconds", func(t *testing.T) {
		d, ok := ParseRetryAfter("30", now)
		require.True(t, ok)
		assert.Equal(t, 30*time.Second, d)
	})

	t.Run("zero delta seconds", func(t *testing.T) {
		d, ok := ParseRetryAfter("0", now)
		require.True(t, ok)
		assert.Zero(t, d)
	})

	t.Run("negative delta is normalised to zero", func(t *testing.T) {
		d, ok := ParseRetryAfter("-10", now)
		require.True(t, ok)
		assert.Zero(t, d)
	})

	t.Run("invalid value", func(t *testing.T) {
		_, ok := ParseRetryAfter("not-a-header", now)
		assert.False(t, ok)
	})

	t.Run("absolute HTTP date in the future", func(t *testing.T) {
		date := now.Add(90 * time.Second).UTC().Format(http.TimeFormat)
		d, ok := ParseRetryAfter(date, now)
		require.True(t, ok)
		assert.Equal(t, 90*time.Second, d)
	})

	t.Run("absolute HTTP date in the past normalises to zero", func(t *testing.T) {
		date := now.Add(-90 * time.Second).UTC().Format(http.TimeFormat)
		d, ok := ParseRetryAfter(date, now)
		require.True(t, ok)
		assert.Zero(t, d)
	})
}

func TestWaitWindow(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cfg := Config{MinBackoff: 5 * time.Second, MaxBackoff: time.Minute}

	t.Run("exponential backoff applies without hints", func(t *testing.T) {
		retryAfter, backoff := waitWindow(now, 2, cfg)
		assert.Equal(t, 20*time.Second, backoff)
		assert.Equal(t, now.Add(20*time.Second), retryAfter)
	})

	t.Run("an earlier hint does not shorten the backoff", func(t *testing.T) {
		hint := now.Add(time.Second)
		retryAfter, backoff := waitWindow(now, 0, cfg, hint)
		assert.Equal(t, 5*time.Second, backoff)
		assert.Equal(t, now.Add(5*time.Second), retryAfter)
	})

	t.Run("a later hint extends the window", func(t *testing.T) {
		hint := now.Add(time.Hour)
		retryAfter, backoff := waitWindow(now, 0, cfg, hint)
		assert.Equal(t, time.Hour, backoff)
		assert.Equal(t, hint, retryAfter)
	})

	t.Run("the latest of several hints wins", func(t *testing.T) {
		earlier := now.Add(30 * time.Second)
		later := now.Add(2 * time.Hour)
		retryAfter, backoff := waitWindow(now, 1, cfg, earlier, later)
		assert.Equal(t, 2*time.Hour, backoff)
		assert.Equal(t, later, retryAfter)
	})

	t.Run("zero hints are ignored", func(t *testing.T) {
		retryAfter, backoff := waitWindow(now, 0, cfg, time.Time{})
		assert.Equal(t, 5*time.Second, backoff)
		assert.Equal(t, now.Add(5*time.Second), retryAfter)
	})
}
