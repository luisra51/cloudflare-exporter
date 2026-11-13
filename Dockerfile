# syntax=docker/dockerfile:1

# Build stage: runs on the build host's architecture and cross-compiles,
# so multi-arch builds do not need to emulate the Go toolchain.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" \
      -o /out/cloudflare-exporter ./cmd/cloudflare-exporter

# Runtime stage: static distroless image, runs as non-root (uid 65532).
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/cloudflare-exporter /cloudflare-exporter

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/cloudflare-exporter"]
