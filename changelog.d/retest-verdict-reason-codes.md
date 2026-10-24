### Added: a retest verdict says why an item could not be verified

- `tool.VerdictReport.Code` (and `tool.RetestVerdict.Code`, the wire verdict's `code`) is an optional reason of an unverifiable verdict from a closed set: `template_not_found`, `excluded_by_policy`, `target_unreachable`, `egress_refused`, `no_verdict`. An unknown code, a code on a conclusive verdict, or `egress_refused` from the tool (only the runtime sees the confinement) is dropped by the runtime.

### Fixed: an item the tool never judged is no longer a bare "no verdict"

- When a retest item gets no verdict, the runtime now says what it knows: its target did not answer or was refused by the network confinement (`target_unreachable`, `egress_refused`), the target was skipped or never reached, or the run stopped (`no_verdict` with the error class in the detail).
- A retest item on a target the sensor's network confinement refused every connection toward is now unverifiable (`egress_refused`) whatever the tool concluded: a tool that never reached the target cannot call a finding fixed or still present.
