package core

import "fmt"

// applyJobConfig applies the config keys every scan job may carry
// (out-of-band callbacks, scope limits, exclusions) to the scan options.
func applyJobConfig(opts *ScanOptions, config map[string]interface{}, local *LocalPolicy) error {
	if config == nil {
		return nil
	}
	// Out-of-band callbacks only when the command says so, as a boolean:
	// anything else ("true", 1) leaves them off; and only when the local
	// policy allows them.
	if allow, ok := config["allow_interactsh"].(bool); ok && allow {
		if !local.AllowsInteractsh() {
			return refuse("allow_interactsh", "the job asks for out-of-band callbacks (interactsh); this sensor's policy does not allow them")
		}
		opts.AllowInteractsh = true
	}
	if err := applyScanLimits(opts, config); err != nil {
		return err
	}
	if exclude, ok := config["exclude"].([]interface{}); ok {
		for _, ex := range exclude {
			if s, ok := ex.(string); ok {
				if err := validateScanArgValue(s); err != nil {
					return fmt.Errorf("invalid exclude pattern: %w", err)
				}
				opts.Exclude = append(opts.Exclude, s)
			}
		}
	}
	return nil
}
