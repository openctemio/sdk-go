package core

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/ctis/capability"
)

// newScanOptions are the scan options of a job, before its config is read:
// the target and, for a capability job, its capability, params and tier.
func (e *DefaultCommandExecutor) newScanOptions(target string, targets []string, scanner Scanner, p *ScanCommandPayload) (*ScanOptions, error) {
	if e.verbose.Load() {
		fmt.Printf("[executor] Running scanner %s on %s\n", p.Scanner, strings.Join(targets, ", "))
	}
	opts := &ScanOptions{TargetDir: target, Verbose: e.verbose.Load()}
	if err := applyCapabilityJob(opts, scanner, p); err != nil {
		return nil, err
	}
	return opts, nil
}

// Bounds of a capability job.
const (
	maxCapabilityJobParams = 64
	maxCapabilityParamSize = 16 << 10
)

// applyCapabilityJob copies a capability job's capability, standard params
// and tier ceiling into the scan options, after checking their shape. A job
// that carries them for a scanner that cannot take them fails: dropping
// them would run the scan with settings the workflow did not ask for.
// Whether the tool implements the capability and supports each value is
// checked by the tool runtime (tool.Manifest.ApplyParams).
func applyCapabilityJob(opts *ScanOptions, scanner Scanner, p *ScanCommandPayload) error {
	if p.Capability == "" && len(p.Params) == 0 && p.MaxTier == "" {
		return nil
	}
	if cs, ok := scanner.(CapabilityScanner); !ok || !cs.TakesCapabilityJobs() {
		return fmt.Errorf("scanner %s does not run capability jobs (capability, params, max_tier); update the sensor", p.Scanner)
	}
	if p.Capability != "" {
		if _, major, ok := capability.ParseRef(p.Capability); !ok || major == 0 {
			return fmt.Errorf("invalid capability %q: want id@major", truncateBytes(p.Capability, 64))
		}
	} else if len(p.Params) > 0 {
		return fmt.Errorf("standard params need the job's capability")
	}
	if p.MaxTier != "" && !slices.Contains([]string{"T0", "T1", "T2"}, p.MaxTier) {
		return fmt.Errorf("invalid max_tier %q", truncateBytes(p.MaxTier, 16))
	}
	if len(p.Params) > maxCapabilityJobParams {
		return fmt.Errorf("%d standard params, at most %d", len(p.Params), maxCapabilityJobParams)
	}
	for k, v := range p.Params {
		if len(k) > 64 || len(v) > maxCapabilityParamSize {
			return fmt.Errorf("standard param %q is too large", truncateBytes(k, 64))
		}
	}
	opts.Capability, opts.MaxTier = p.Capability, p.MaxTier
	opts.Params = p.Params
	return nil
}
