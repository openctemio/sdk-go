#!/bin/bash
# Test script for sdk

set -e

echo "Running tests..."

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...

# Show coverage summary
go tool cover -func=coverage.out | tail -1

echo "Tests completed!"
