### Removed: pkg/adapters (deprecated)

- The deprecated tool adapters `pkg/adapters` and `pkg/adapters/{betterleaks,nuclei,sarif,semgrep,trivy,vuls}` are removed (about 3,600 lines), together with the internal `importbridge` that ran them. Neither the sensor, the platform nor the asset collector imported them. Every tool output is now parsed by one library, `github.com/openctemio/ctis/importer` (OpenCTEM Tool Contract v1, decision TC5).

### Upgrade notes

- Replace `adapters/<tool>.NewAdapter().Convert(ctx, data, opts)` with `importer.Parse(ctx, bytes.NewReader(data), importer.Options{Format: importer.Format<Tool>, ...})` from `github.com/openctemio/ctis/importer`. The result is the same CTIS, with the importer limits applied. `core.SARIFParser` already uses it. For a tool you run, prefer the exec profile with `run.output.format: <tool>` (no code).
- `examples/custom-adapter` now shows the importer.
