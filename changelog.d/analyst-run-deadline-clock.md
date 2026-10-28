### Fixed: an analyst run measures its job deadline on its own clock

- `pkg/analyst` applied the job deadline as a wall-clock context deadline while the refusal check used the run's injected clock, so a run with an injected clock could end early, and the harness tests failed for good once the wall clock passed their fixed test time. The context now uses the time left on the run's own clock.
