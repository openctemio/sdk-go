package core

import (
	"fmt"
	"math"
)

// MaxScanLimit bounds any value of a scan's rate_limit, bulk_size or
// concurrency config key. Sensors cap the values far lower (their
// configured ceilings); this only rejects nonsense early.
const MaxScanLimit = 1_000_000

// ScanLimitKeys are the scan-command config keys the executor reads into
// ScanOptions.RateLimit, BulkSize and Concurrency.
var ScanLimitKeys = []string{"rate_limit", "bulk_size", "concurrency"}

// applyScanLimits sets opts' rate limit, bulk size and concurrency from a
// scan command's config. A key that is absent leaves the scanner's own
// value. A present key must be a whole number from 1 to MaxScanLimit:
// anything else fails the command instead of being ignored, so a limit the
// platform asked for is never silently dropped.
func applyScanLimits(opts *ScanOptions, config map[string]interface{}) error {
	for _, key := range ScanLimitKeys {
		raw, ok := config[key]
		if !ok || raw == nil {
			continue
		}
		n, err := scanLimitValue(raw)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", key, err)
		}
		switch key {
		case "rate_limit":
			opts.RateLimit = n
		case "bulk_size":
			opts.BulkSize = n
		case "concurrency":
			opts.Concurrency = n
		}
	}
	return nil
}

func scanLimitValue(raw interface{}) (int, error) {
	var f float64
	switch v := raw.(type) {
	case float64:
		f = v
	case int:
		f = float64(v)
	case int64:
		f = float64(v)
	default:
		return 0, fmt.Errorf("%v is not a number", raw)
	}
	if math.IsNaN(f) || f != math.Trunc(f) || f < 1 || f > MaxScanLimit {
		return 0, fmt.Errorf("%v is not a whole number from 1 to %d", raw, MaxScanLimit)
	}
	return int(f), nil
}

// CapScanLimit returns the limit a scanner runs with: requested when set
// (above 0), else own (the scanner's setting), and never above ceiling when
// one is set (above 0); with a ceiling and nothing else set, the ceiling.
// Scanners use it so a scan can ask for any limit up to the sensor's
// ceiling and never past it.
func CapScanLimit(requested, own, ceiling int) int {
	v := own
	if requested > 0 {
		v = requested
	}
	if ceiling > 0 && (v <= 0 || v > ceiling) {
		v = ceiling
	}
	return v
}
