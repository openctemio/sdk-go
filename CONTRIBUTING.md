# Contributing to OpenCTEM SDK

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone: `git clone https://github.com/YOUR_USERNAME/sdk.git`
3. Install Go 1.25+
4. Run tests: `go test ./...`
5. Create branch: `git checkout -b feature/your-feature`
6. Make changes
7. Commit and push
8. Open a Pull Request

## Code Style

- Use `gofmt` for formatting
- Follow Go best practices
- Write meaningful commit messages
- Add tests for new features
- Update documentation

## Adding a New Scanner

1. Create package in `pkg/scanners/`
2. Implement `Scanner` interface
3. Add tests
4. Add example in `examples/`
5. Update README

## License

By contributing, you agree to license your contributions under Apache 2.0.
