### Removed: `pkg/edgeprotect` moved to ctis

- The edge protection detector now lives in `github.com/openctemio/ctis/edgeprotect` (ctis v1.6.3), so a platform can use it without depending on the sensor SDK. Import that package in place of `pkg/edgeprotect`; the API is unchanged. `adapt.Event.Edge`, `adapt.HostRate.ReportResponse` and the egress signals use the ctis types.
- Raises `github.com/openctemio/ctis` to v1.6.3.
