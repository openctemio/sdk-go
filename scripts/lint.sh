#!/bin/bash
# Lint script for sdk

set -e

echo "Running linters..."

# Run go vet
echo "Running go vet..."
go vet ./...

# Run staticcheck if available
if command -v staticcheck &> /dev/null; then
    echo "Running staticcheck..."
    staticcheck ./...
fi

# Run golangci-lint if available
if command -v golangci-lint &> /dev/null; then
    echo "Running golangci-lint..."
    golangci-lint run ./...
fi

echo "Lint completed!"
