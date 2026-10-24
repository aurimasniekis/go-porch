#!/usr/bin/env bash
# Regenerates the documentation screenshots in site/public/screenshots (README and website). Everything shown is
# fictional: a fresh, throwaway development `porch serve` with the fake Google provider (scripts/e2e.sh), the invented
# Smith and Jones families, and invented applications, roles and policies. web/e2e/m2-login.spec.ts sets the
# installation up, then web/e2e/screenshots.spec.ts seeds the rest through the management API and captures each page.
# The output directory reaches the spec as SCREENSHOTS_OUT (not PORCH_*: porch refuses unknown PORCH_* variables).
# Never point this at a real instance.
#
# Usage: scripts/screenshots.sh [OUT_DIR]   (default site/public/screenshots)
#   E2E_SKIP_BUILD=1  reuse bin/ and the built web UI
#
# Needs Go, pnpm and the Playwright browsers (cd web && pnpm exec playwright install chromium); pngquant is used when
# installed. Review every image before committing it.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=$(mkdir -p "${1:-$root/site/public/screenshots}" && cd "${1:-$root/site/public/screenshots}" && pwd)

SCREENSHOTS_OUT="$out" "$root/scripts/e2e.sh" e2e/m2-login.spec.ts e2e/screenshots.spec.ts
if command -v pngquant >/dev/null; then
  pngquant --force --skip-if-larger --quality 80-95 --strip --ext .png "$out"/*.png || true
fi
echo "screenshots written to $out"
