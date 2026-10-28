### Fixed

- `pkg/analyst`: a run's job deadline is measured on the run's own clock. It was applied as a wall-clock context deadline while the refusal check used the injected clock, so the harness tests failed for good once the wall clock passed their fixed test time, and a run with an injected clock could end early.
