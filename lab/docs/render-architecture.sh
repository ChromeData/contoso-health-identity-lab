#!/usr/bin/env bash
# Render architecture.mmd to architecture.svg (repo / slides) and
# architecture.png (2x scale, ~7680x5760, for slides and 16:9 video crops).
# Uses the pinned Mermaid CLI from npm (downloads a headless Chromium on
# first run).
# The PNG's browser viewport (-w) must be >= the SVG's natural width, or
# the PNG is downscaled (without -w, -s 2 renders into the default 800 px
# viewport). So -w is read from the SVG just rendered (its viewBox width,
# ~3840 px since the 2026-10-20 top-down layout) plus a margin, with 4800
# as the fallback.
set -euo pipefail
cd "$(dirname "$0")"
MMDC="npx --yes @mermaid-js/mermaid-cli@11.17.0"
$MMDC -i architecture.mmd -o architecture.svg -b white
natural=$(grep -o 'viewBox="[^"]*"' architecture.svg | head -n 1 | tr -d '"' | awk '{print int($3)}')
viewport=$(( ${natural:-0} > 0 ? natural + 64 : 4800 ))
$MMDC -i architecture.mmd -o architecture.png -b white -w "$viewport" -s 2
echo "rendered architecture.svg (natural width ${natural:-unknown} px) + architecture.png (viewport ${viewport} px, 2x)"
