### Fixed: the config report no longer asks a signed-jobs sensor for template keys

- A sensor that requires signed jobs trusts custom templates through the verified job statement, so the `policy.template_keys` check now reports `not_needed` for it instead of warning `missing` (and blocking custom templates in the platform's view). A sensor that verifies signed jobs only when present still needs `SENSOR_TEMPLATE_SIGNING_KEYS` for unsigned jobs, and is still warned.
