#!/usr/bin/env bash
# Regenerate the zoomable vector PDFs the README links to, from their SVGs.
# The PDFs are what a reader opens on click (GitHub's PDF viewer has zoom, and
# works on a private repo); the SVGs stay the inline images. Re-run this
# whenever you edit a diagram SVG so the two never drift.
#   deps: librsvg  (macOS: brew install librsvg)
set -euo pipefail
cd "$(dirname "$0")"
for f in architecture agent-flow server-catalog; do
  rsvg-convert -f pdf -o "$f.pdf" "$f.svg"
  echo "rendered $f.pdf"
done
