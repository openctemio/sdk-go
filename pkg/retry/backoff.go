// Package retry provides persistent retry queue functionality for failed API operations.
package retry

import (
	"math"
	"math/rand"
	"time"
)

// BackoffStrategy defines how to calculate the next retry time.
type BackoffStrategy int

const (
	// BackoffExponential uses exponential backoff: base * 2^attempt
	BackoffExponential BackoffStrategy = iota

	// BackoffLinear uses linear backoff: base * attempt
	BackoffLinear

	// BackoffConstant uses constant backoff: base (no increase)
	BackoffConstant
)

// BackoffConfig configures the backoff behavior.
type BackoffConfig struct {
	// Strategy is the backoff strategy to use.
	// Default is BackoffExponential.
	Strategy BackoffStrategy

	// BaseInterval is the base interval for backoff calculation.
	// Default is DefaultRetryInterval (5 minutes).
	BaseInterval time.Duration

	// MaxInterval is the maximum interval between retries.
	// Default is 48 hours.
	MaxInterval time.Duration

	// Jitter adds randomness to prevent thundering herd.
	// Value between 0.0 (no jitter) and 1.0 (full jitter).
	// Default is 0.1 (10% jitter).
	Jitter float64
}

// DefaultBackoffConfig returns a BackoffConfig with default values.
func DefaultBackoffConfig() *BackoffConfig {
	return &BackoffConfig{
		Strategy:     BackoffExponential,
		BaseInterval: DefaultRetryInterval,
		MaxInterval:  48 * time.Hour,
		Jitter:       0.1,
	}
}

// CalculateNextRetry calculates the next retry time based on the number of attempts.
// This is a convenience function that uses the default exponential backoff.
//
// Backoff schedule with default 5-minute base:
//
//	attempt 1: 5 minutes
//	attempt 2: 10 minutes
//	attempt 3: 20 minutes
//	attempt 4: 40 minutes
//	attempt 5: 80 minutes (~1.3 hours)
//	attempt 6: 160 minutes (~2.6 hours)
//	attempt 7: 320 minutes (~5.3 hours)
//	attempt 8: 640 minutes (~10.6 hours)
//	attempt 9: 1280 minutes (~21 hours)
//	attempt 10: 2560 minutes (~42 hours) - capped at maxInterval
func CalculateNextRetry(attempts int, baseInterval time.Duration) time.Time {
	cfg := DefaultBackoffConfig()
	cfg.BaseInterval = baseInterval
	return cfg.NextRetry(attempts)
}

// NextRetry calculates the next retry time based on the configuration.
func (c *BackoffConfig) NextRetry(attempts int) time.Time {
	interval := c.calculateInterval(attempts)
	return time.Now().Add(interval)
}

// NextRetryFrom calculates the next retry time from a specific base time.
func (c *BackoffConfig) NextRetryFrom(from time.Time, attempts int) time.Time {
	interval := c.calculateInterval(attempts)
	return from.Add(interval)
}

// calculateInterval calculates the backoff interval for the given attempt.
func (c *BackoffConfig) calculateInterval(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}

	var interval time.Duration

	switch c.Strategy {
	case BackoffExponential:
		// Exponential: base * 2^(attempts-1)
		// attempts 1 -> 1x, attempts 2 -> 2x, attempts 3 -> 4x, etc.
		multiplier := math.Pow(2, float64(attempts-1))
		interval = time.Duration(float64(c.BaseInterval) * multiplier)

	case BackoffLinear:
		// Linear: base * attempts
		interval = c.BaseInterval * time.Duration(attempts)

	case BackoffConstant:
		// Constant: always base
		interval = c.BaseInterval

	default:
		// Default to exponential
		multiplier := math.Pow(2, float64(attempts-1))
		interval = time.Duration(float64(c.BaseInterval) * multiplier)
	}

	// Cap at max interval
	if c.MaxInterval > 0 && interval > c.MaxInterval {
		interval = c.MaxInterval
	}

	// Apply jitter
	if c.Jitter > 0 {
		interval = c.applyJitter(interval)
	}

	return interval
}

// applyJitter adds randomness to the interval to prevent thundering herd.
func (c *BackoffConfig) applyJitter(interval time.Duration) time.Duration {
	if c.Jitter <= 0 {
		return interval
	}

	// Clamp jitter to [0, 1]
	jitter := c.Jitter
	if jitter > 1 {
		jitter = 1
	}

	// Calculate jitter range: [1-jitter, 1+jitter]
	// For jitter=0.1, range is [0.9, 1.1]
	jitterRange := float64(interval) * jitter
	jitterValue := (rand.Float64()*2 - 1) * jitterRange //nolint:gosec // math/rand is acceptable for jitter, not security-sensitive

	return time.Duration(float64(interval) + jitterValue)
}

// RetrySchedule returns a slice of retry times for a given number of attempts.
// Useful for displaying or logging the expected retry schedule.
func (c *BackoffConfig) RetrySchedule(maxAttempts int) []time.Duration {
	if maxAttempts <= 0 {
		return nil
	}

	schedule := make([]time.Duration, maxAttempts)
	for i := range maxAttempts {
		// Don't apply jitter for schedule preview
		origJitter := c.Jitter
		c.Jitter = 0
		schedule[i] = c.calculateInterval(i + 1)
		c.Jitter = origJitter
	}
	return schedule
}

// TotalBackoffTime calculates the total time for all retry attempts.
// Useful for estimating how long before an item is marked as permanently failed.
func (c *BackoffConfig) TotalBackoffTime(maxAttempts int) time.Duration {
	schedule := c.RetrySchedule(maxAttempts)
	var total time.Duration
	for _, d := range schedule {
		total += d
	}
	return total
}

// IsReadyForRetry checks if enough time has passed since the last attempt.
func IsReadyForRetry(lastAttempt time.Time, attempts int, cfg *BackoffConfig) bool {
	if cfg == nil {
		cfg = DefaultBackoffConfig()
	}
	nextRetry := cfg.NextRetryFrom(lastAttempt, attempts)
	return time.Now().After(nextRetry)
}
