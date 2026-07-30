# =============================================================================
# OpenCTEM SDK Makefile
# =============================================================================
# Go library for building security scanning integrations
# =============================================================================

.PHONY: all test lint fmt clean help pre-commit-install pre-commit-run dev-tools security-scan

# Variables
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')

# Default target
all: lint test

# =============================================================================
# Test
# =============================================================================

# pkg/httpsec.SafeHTTPClient blocks loopback by default, which breaks
# httptest.NewServer-based unit tests. The env var tells the SDK
# dialer to allow 127.0.0.0/8 + ::1/128 for the duration of the
# test run; the httpsec package's own tests reset it via TestMain so
# the prod posture is still asserted.
TEST_ENV := OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK=1

test: ## Run tests
	$(TEST_ENV) go test -v -race ./...

test-coverage: ## Run tests with coverage
	$(TEST_ENV) go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# =============================================================================
# Lint & Format
# =============================================================================

lint: ## Run linters
	@echo "Running golangci-lint..."
	@golangci-lint run --config .golangci.yml ./...

fmt: ## Format code
	go fmt ./...
	gofmt -s -w $(GO_FILES)

# =============================================================================
# Security & Pre-commit
# =============================================================================

pre-commit-install: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		echo "pre-commit already installed"; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Installing via brew..."; \
		brew install pre-commit; \
	elif command -v pipx >/dev/null 2>&1; then \
		echo "Installing via pipx..."; \
		pipx install pre-commit; \
	else \
		echo "Please install pre-commit: brew install pre-commit"; \
		exit 1; \
	fi
	@pre-commit install
	@echo "Pre-commit hooks installed!"

pre-commit-run: ## Run all pre-commit hooks
	@pre-commit run --all-files

security-scan: ## Run security scan
	@echo "Running security scan..."
	@echo ""
	@echo "=== Gitleaks (Secret Detection) ==="
	@gitleaks detect --config .gitleaks.toml --source . --verbose || true
	@echo ""
	@echo "=== Golangci-lint (Code Security) ==="
	@golangci-lint run --config .golangci.yml ./... || true
	@echo ""
	@echo "Security scan complete!"

# =============================================================================
# Development
# =============================================================================

dev-tools: ## Install development tools
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

# =============================================================================
# Clean
# =============================================================================

clean: ## Clean build artifacts
	rm -f coverage.out coverage.html
	go clean -cache

# =============================================================================
# Help
# =============================================================================

help: ## Show this help
	@echo "OpenCTEM SDK - Make targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make test           # Run tests"
	@echo "  make lint           # Run linters"
	@echo "  make fmt            # Format code"
	@echo "  make security-scan  # Run security scan"
