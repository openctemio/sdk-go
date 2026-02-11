# syntax=docker/dockerfile:1.7
# =============================================================================
# OpenCTEM SDK - Development & Test Dockerfile
# =============================================================================
# Targets:
#   - test:     Run all SDK tests
#   - dev:      Development environment with all tools
#   - examples: Build example programs
#
# Build examples:
#   docker build --target test -t openctemio/sdk:test .
#   docker build --target dev -t openctemio/sdk:dev .
#   docker build --target examples -t openctemio/sdk:examples .
#
# Run tests:
#   docker run --rm openctemio/sdk:test
#
# Run integration test:
#   docker run --rm openctemio/sdk:examples integration-test -api-key=$API_KEY -url=$API_URL
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Base builder
# -----------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26-alpine AS base

# hadolint ignore=DL3018
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /sdk

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies with cache mount
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source
COPY . .

# -----------------------------------------------------------------------------
# Target: TEST - Run all SDK tests
# -----------------------------------------------------------------------------
FROM base AS test

ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Run tests with cache mounts
CMD ["sh", "-c", "go test -v -race -cover ./pkg/..."]

# -----------------------------------------------------------------------------
# Target: DEV - Development environment
# -----------------------------------------------------------------------------
FROM base AS dev

# hadolint ignore=DL3018
RUN apk add --no-cache \
    bash \
    curl \
    make \
    protobuf \
    protobuf-dev

# Install Go tools
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.2 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1 && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.63.4

ENV PATH="/go/bin:${PATH}"

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

USER appuser

HEALTHCHECK --interval=30s --timeout=3s \
    CMD go version || exit 1

CMD ["/bin/bash"]

# -----------------------------------------------------------------------------
# Target: EXAMPLES - Build example programs
# -----------------------------------------------------------------------------
FROM base AS examples-builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64

# Build all example programs
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-w -s" -o /out/integration-test ./examples/integration-test && \
    go build -trimpath -ldflags="-w -s" -o /out/custom-scanner ./examples/custom-scanner && \
    go build -trimpath -ldflags="-w -s" -o /out/custom-connector ./examples/custom-connector && \
    go build -trimpath -ldflags="-w -s" -o /out/custom-adapter ./examples/custom-adapter && \
    go build -trimpath -ldflags="-w -s" -o /out/custom-provider ./examples/custom-provider

# Final examples image
FROM gcr.io/distroless/static-debian12:nonroot AS examples

LABEL org.opencontainers.image.title="OpenCTEM SDK Examples"
LABEL org.opencontainers.image.description="Example programs built with OpenCTEM SDK"
LABEL org.opencontainers.image.source="https://github.com/openctemio/sdk-go"

COPY --from=examples-builder /out/* /usr/local/bin/
COPY --from=examples-builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=examples-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app

# Default to integration test
ENTRYPOINT ["/usr/local/bin/integration-test"]
CMD ["--help"]
