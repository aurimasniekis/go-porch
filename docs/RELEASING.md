# Releasing Porch

Adapted from HallPass docs/RELEASING.md (Apache-2.0, same author).

This is the maintainer procedure for publishing a version. Version numbers follow [VERSIONING.md](VERSIONING.md).
A release is cut from `main` by pushing a `vX.Y.Z` tag; the [release workflow](../.github/workflows/release.yaml) does
the rest and stops at a **draft** GitHub release that a maintainer reviews and publishes.

> **Not externally reviewed.** Porch has had no external security review. Every release keeps the "Not externally
> reviewed" note in its CHANGELOG section until one has been done and its findings are resolved.

## What the release workflow does

Triggers: a pushed `v*` tag, or a manual dispatch. A dispatch from a branch builds, scans and uploads workflow
artifacts (version `v0.0.0-dev+<sha>`) but publishes nothing. Pull requests never run it. Every action is pinned by
full commit SHA.

| Job | What it does | Fails the release when |
|---|---|---|
| `meta` | Checks the tag is `vMAJOR.MINOR.PATCH[-PRERELEASE]` and that `CHANGELOG.md` has a `## [X.Y.Z] - YYYY-MM-DD` section; derives the version, commit time (`SOURCE_DATE_EPOCH`) and image name | bad tag, missing changelog section |
| `test` | `make vet race` with `PORCH_TEST_TX_MAX=500ms` (race-detector overhead on shared runners) | any vet finding or test failure |
| `web` | `pnpm install --frozen-lockfile && pnpm build` in `web/` (typecheck, Vite build into `internal/webui/dist`, `check-dist`) | build or dist check fails |
| `binaries` | `scripts/release-build.sh` builds static (`CGO_ENABLED=0`, `-trimpath`, empty build ID) archives for linux/amd64, linux/arm64 and darwin/arm64 with the UI embedded; runs the linux/amd64 binary's `version --json` and checks it is static; syft SPDX SBOMs of the shipped binaries and of the source tree (Go modules and pnpm lockfiles); `SHA256SUMS` over archives and SBOMs | build, version mismatch, dynamic binary, empty SBOM |
| `image-scan` | Builds the image per architecture (amd64, arm64) to a local archive; Trivy fails on **fixable** HIGH/CRITICAL findings and prints unfixed ones; on amd64 runs `scripts/container-smoke.sh` | fixable HIGH/CRITICAL, smoke test failure |
| `image-publish` | Tag runs only. Pushes one multi-arch manifest (with BuildKit provenance and SBOM) to `ghcr.io/aurimasniekis/go-porch` and, if `DOCKERHUB_TOKEN` is set, to `docker.io/aurimasniekis/porch`; Trivy on the pushed digest; build provenance attestation per registry | push or Trivy failure |
| `attest-binaries` | Tag runs only. Build provenance attestation over every file in `SHA256SUMS` | attestation failure |
| `github-release` | Tag runs only. Draft release with the CHANGELOG section, image digest(s), archives, SBOMs and `SHA256SUMS`; `-rc.N` and other suffixes are marked pre-release | — |

Archive contents: `porch`, `porch.container.yaml` (the container's production config, a starting point for your own),
`porch.service` (systemd unit), `LICENSE`, `NOTICE`, `CHANGELOG.md`.

The container smoke test (`scripts/container-smoke.sh IMAGE`) checks the image metadata (user 65532:65532, only
`EXPOSE 8080`, `VOLUME /var/lib/porch`, a HEALTHCHECK, no shell), `porch version`, `porch keys init` into a separate
volume (0400, 65532, no overwrite), `porch config check` and `porch migrate` with the baked-in production config on a
read-only root filesystem with no capabilities, refusal of a missing `public_url`, of a KEK inside `data_dir` and of a
KEK with group/other bits, and that `porch serve` passes `porch healthcheck` and the Docker health check, serves OIDC
discovery with the configured issuer and exits 0 on SIGTERM.

## One-time setup

| What | Where |
|---|---|
| GHCR package `ghcr.io/aurimasniekis/go-porch` | Created by the first push as **private**. Make it public once (package settings → visibility) so it can be pulled anonymously. |
| Docker Hub (optional) | A Docker Hub access token with **Read & Write** scope for `aurimasniekis/porch` in the repository secret `DOCKERHUB_TOKEN` (`gh secret set DOCKERHUB_TOKEN`); the user is `DOCKERHUB_USER` in the workflow. Without the secret the workflow publishes to GHCR only, warns, and the release notes list only GHCR. |
| Private vulnerability reporting | Repository settings → Security → enable "Private vulnerability reporting" ([SECURITY.md](../SECURITY.md) points reporters there). |
| GitHub Actions artifact storage | Jobs pass the web build, archives and image archives as artifacts. Keep the account under its storage quota. |

## Checklist

1. **Release criteria.** Before calling a version stable (1.0 or later), all of these must hold: every planned
   milestone done and reachable ([PLAN.md](PLAN.md)); CI green; the acceptance script (M7) passing; every fuzz target
   run for at least 10 minutes without crashers; `make test-fault` passing; a backup → clean-instance restore drill
   (`scripts/backup-drill.sh`); an internal security review with every HIGH and MEDIUM finding fixed or accepted; an
   external review, or the "Not externally reviewed" note; [IMPLEMENTATION_MATRIX.md](IMPLEMENTATION_MATRIX.md) honest
   and current. A version below 1.0 may ship with criteria unmet only when the CHANGELOG lists them as known
   limitations.
2. **CI.** `main` is green on GitHub for the commit to be tagged: the `ci` workflow including the browser e2e job. Run
   the slower local suites as well: `make test-fault`, `make test-oidc-interop`, `scripts/backup-drill.sh`, and the
   release checks below.
3. **Changelog.** Move the `[Unreleased]` entries into `## [X.Y.Z] - YYYY-MM-DD` in [CHANGELOG.md](../CHANGELOG.md),
   add comparison links at the bottom, state whether the release contains database migrations, and keep the
   "Not externally reviewed" note. The release workflow refuses a tag without this section and uses it as the release
   notes.
4. **Version references.** Update install examples and status tables that name a version or milestone, for example
   `git grep -nF 0.1.0 -- README.md site deploy docs`, and the status table in `README.md`.
5. **Local release checks** (no network access to registries needed):

   ```sh
   (cd web && pnpm install --frozen-lockfile && pnpm build)
   scripts/release-build.sh -o /tmp/porch-dist                 # all three platforms
   (cd /tmp/porch-dist && shasum -a 256 -c SHA256SUMS)
   docker build -t porch:release-smoke . && scripts/container-smoke.sh porch:release-smoke
   actionlint .github/workflows/*.yaml && shellcheck scripts/*.sh
   ```

6. **Commit** these changes on `main` (`docs: prepare vX.Y.Z release`) and push. Wait for CI.
7. **Tag** the exact commit CI tested and push the tag:

   ```sh
   git tag -a vX.Y.Z -m "Porch vX.Y.Z"
   git push origin vX.Y.Z
   ```

8. **Watch the release workflow** (table above).
9. **Review and publish the draft.** Check the notes, the "Not externally reviewed" note, the attached archives,
   `SHA256SUMS`, both SBOMs, and any unfixed HIGH/CRITICAL findings in the `image-scan` logs. Pre-releases
   (`vX.Y.Z-rc.N`) do not move the `latest` image tag.
10. **Verify what was published** from a clean machine:

    ```sh
    V=X.Y.Z
    gh release download v$V --repo aurimasniekis/go-porch --pattern "porch_${V}_linux_amd64.tar.gz" --pattern SHA256SUMS
    sha256sum --check --ignore-missing SHA256SUMS
    gh attestation verify "porch_${V}_linux_amd64.tar.gz" --repo aurimasniekis/go-porch
    gh attestation verify "oci://ghcr.io/aurimasniekis/go-porch:$V" --repo aurimasniekis/go-porch
    docker run --rm "ghcr.io/aurimasniekis/go-porch:$V" version
    # only when Docker Hub publishing is configured:
    gh attestation verify "oci://docker.io/aurimasniekis/porch:$V" --repo aurimasniekis/go-porch
    ```

11. **After the release**, add an empty `## [Unreleased]` section to the CHANGELOG if it is missing.

## What has been verified

| Part | Status | Evidence |
|---|---|---|
| `scripts/release-build.sh` (three platforms, `SHA256SUMS`, static linux binaries, embedded UI, `version`) | tested locally | macOS arm64, Go 1.27.3, GNU tar, 2026-10-24 |
| `scripts/container-smoke.sh` against a locally built image | tested locally | Docker Desktop 29.8.2 (arm64), 2026-10-24 |
| `actionlint` (workflows), `shellcheck` (scripts) | tested locally | actionlint 1.7.12, ShellCheck 0.11.0 |
| syft SBOM and Trivy scan | tested locally with the same tool versions as the workflow | syft v1.54.0, Trivy 0.70.0 (container images) |
| Release workflow on GitHub-hosted runners, GHCR/Docker Hub push, attestations, draft release | **not verified** | nothing has been pushed or tagged yet |
| Reproducibility of archives byte-for-byte across machines | **not verified** | same inputs give the same binaries by construction (`-trimpath`, empty build ID, `SOURCE_DATE_EPOCH`); not compared across hosts |

## If something goes wrong

- **The workflow fails before publishing** (tests, Trivy, smoke test): fix on `main`, delete the tag
  (`git push --delete origin vX.Y.Z && git tag -d vX.Y.Z`) and tag the fixed commit. Nothing was published.
- **A published release is broken:** never move or reuse a published tag or image tag. Publish `vX.Y.(Z+1)` with the
  fix and mark the broken GitHub release as such in its notes. Re-tagging would invalidate checksums and attestations
  that users may already have verified.
- **Fixable HIGH/CRITICAL in the base image:** refresh the pinned digest in the `Dockerfile`
  (`docker buildx imagetools inspect <image>:<tag>`) in a normal commit, then tag again.
