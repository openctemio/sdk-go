#!/bin/bash
# Install development tools for sdk

set -e

echo "Installing development tools..."

# Install golangci-lint
echo "Installing golangci-lint..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install staticcheck
echo "Installing staticcheck..."
go install honnef.co/go/tools/cmd/staticcheck@latest

# Install mockgen for testing
echo "Installing mockgen..."
go install go.uber.org/mock/mockgen@latest

echo "Development tools installed!"
