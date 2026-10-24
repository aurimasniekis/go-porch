# syntax=docker/dockerfile:1.7
#
# Demo-only images (deploy/demo): the fake Google OpenID provider (test/fakegoogle, TEST FIXTURE: it signs in whoever
# clicks a name) and the demo relying party (examples/demo-app). Never deploy either for real users.
# Build context: the repository root (the root .dockerignore allowlists both directories).
#
#   docker build -f deploy/demo/tools.Dockerfile --target fakegoogle -t porch-demo-fakegoogle:local .
#   docker build -f deploy/demo/tools.Dockerfile --target demo-app   -t porch-demo-app:local .
#
# The runtime is Alpine (not distroless) so the compose health checks can use busybox wget; both run as UID 65532.

ARG GO_IMAGE=docker.io/library/golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4
ARG RUNTIME_IMAGE=docker.io/library/alpine:3.22.7@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY internal/ internal/
COPY test/fakegoogle/ test/fakegoogle/
COPY examples/demo-app/ examples/demo-app/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/fakegoogle ./test/fakegoogle && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/demo-app ./examples/demo-app

FROM ${RUNTIME_IMAGE} AS base
RUN addgroup -S -g 65532 nonroot && adduser -S -D -H -u 65532 -G nonroot -s /sbin/nologin nonroot
USER 65532:65532

FROM base AS fakegoogle
COPY --from=build --chown=0:0 --chmod=0555 /out/fakegoogle /usr/local/bin/fakegoogle
EXPOSE 9000/tcp
ENTRYPOINT ["/usr/local/bin/fakegoogle"]

FROM base AS demo-app
COPY --from=build --chown=0:0 --chmod=0555 /out/demo-app /usr/local/bin/demo-app
ENV DEMO_LISTEN=0.0.0.0:9090
EXPOSE 9090/tcp
ENTRYPOINT ["/usr/local/bin/demo-app"]
