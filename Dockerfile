# syntax=docker/dockerfile:1.7
#
# Porch container image.
# Adapted from HallPass Dockerfile and pulse Dockerfile (Apache-2.0, same author).
#
#   web    : builds the SPA into internal/webui/dist with the locked pnpm dependency tree (pnpm build = typecheck +
#            vite build + CSP/dev-code leak check).
#   build  : static Go binary (CGO_ENABLED=0, -trimpath), cross-compiled on the build platform (no emulation).
#   final  : distroless static (Debian 13), non-root UID/GID 65532, no shell, no package manager.
#
# Every base image is pinned by digest. Update a digest with:
#   docker buildx imagetools inspect <image>:<tag>      # use the index "Digest:" line
#
# Runtime layout (deploy/README.md):
#   /usr/local/bin/porch         binary (root-owned, read-only)
#   /etc/porch/porch.yaml        configuration; a container default is baked in (deploy/porch.container.yaml),
#                                mount your own read-only over it. PORCH_CONFIG points here.
#   /var/lib/porch               data volume (SQLite, snapshots), 0700 65532:65532
#   /run/secrets/porch_kek       KEK (kek.file in the default config); mount it as a secret, never inside the data volume
#   /var/lib/porch-kek           optional 0700 65532:65532 mount point for a named volume holding the KEK
#                                (outside data_dir; used by deploy/demo, or by `keys init` into a volume)
#
# Build:  docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT=$(git rev-parse HEAD) \
#           --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t porch:local .

ARG NODE_IMAGE=docker.io/library/node:24.22.0-trixie-slim@sha256:a6155384446670e9719bdc4fd0ebe4d4b29fb32a8d6aa523da3547a6cfbcf22c
ARG GO_IMAGE=docker.io/library/golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

# ---------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
ENV CI=true \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH
WORKDIR /src/web
# pnpm version comes from "packageManager" in web/package.json (corepack verifies the download signature).
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && corepack install
RUN --mount=type=cache,id=porch-pnpm-store,target=/pnpm/store \
    pnpm config set store-dir /pnpm/store && \
    pnpm install --frozen-lockfile
COPY web/ ./
# vite writes to ../internal/webui/dist (emptyOutDir; public/README.txt keeps the go:embed placeholder).
RUN mkdir -p /src/internal/webui/dist && pnpm build

# ---------------------------------------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
ARG BUILD_DATE=
# go.mod requires go 1.27.3; the pinned toolchain satisfies it, so never download another one.
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd/ cmd/
COPY internal/ internal/
# The build context excludes internal/webui/dist (.dockerignore); the UI comes only from the web stage.
COPY --from=web /src/internal/webui/dist/ internal/webui/dist/
# -buildvcs=false: the build context deliberately excludes .git; version metadata comes from build args instead.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= \
        -X github.com/aurimasniekis/go-porch/internal/buildinfo.Version=${VERSION} \
        -X github.com/aurimasniekis/go-porch/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/aurimasniekis/go-porch/internal/buildinfo.Date=${BUILD_DATE}" \
      -o /out/porch ./cmd/porch
# Directory skeleton for the final image (it has no shell, so ownership and modes are prepared here).
# A named volume mounted on one of these directories inherits its ownership and mode on first use.
RUN install -d -m 0700 -o 65532 -g 65532 /rootfs/var/lib/porch /rootfs/var/lib/porch-kek && \
    install -d -m 0755 -o 0 -g 0 /rootfs/etc/porch
COPY --chmod=0444 deploy/porch.container.yaml /rootfs/etc/porch/porch.yaml

# ---------------------------------------------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
ARG COMMIT=
LABEL org.opencontainers.image.title="porch" \
      org.opencontainers.image.description="Porch: self-hosted identity provider and single sign-on" \
      org.opencontainers.image.source="https://github.com/aurimasniekis/go-porch" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --chown=0:0 --chmod=0444 LICENSE NOTICE /usr/share/doc/porch/
COPY --from=build --chown=0:0 --chmod=0555 /out/porch /usr/local/bin/porch
COPY --from=build /rootfs/ /
ENV PORCH_CONFIG=/etc/porch/porch.yaml
USER 65532:65532
WORKDIR /var/lib/porch
VOLUME ["/var/lib/porch"]
# Public listener (http.listen in the container config). The management listener (metrics, /healthz, /readyz) stays
# on 127.0.0.1:9464 inside the container; the health check below runs inside the container and reaches it there.
EXPOSE 8080/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/porch", "healthcheck", "--url", "http://127.0.0.1:9464/readyz"]
ENTRYPOINT ["/usr/local/bin/porch"]
CMD ["serve"]
