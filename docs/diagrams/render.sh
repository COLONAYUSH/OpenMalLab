#!/usr/bin/env bash
# Reproducibly render every MalAnalyzer architecture diagram from committed
# Graphviz source. Fully air-gapped: uses only the local `dot` binary — no
# network, no external fonts, no cloud service. This is the canonical build.
#
#   ./render.sh          # render every src/*.dot to render/<name>.{svg,png}
#   ./render.sh 03       # render only sources whose name contains "03"
#
# SVG is the primary artifact (crisp, diff-reviewable-adjacent, scales); PNG is
# a universal fallback rendered at 144 dpi. Both are committed so the diagrams
# are viewable offline with zero toolchain.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
out="$here/render"
mkdir -p "$out"

command -v dot >/dev/null || { echo "ERROR: graphviz 'dot' not on PATH (brew install graphviz)" >&2; exit 1; }
echo "graphviz: $(dot -V 2>&1)"

filter="${1:-}"
shopt -s nullglob
count=0
for f in "$src"/*.dot; do
  base="$(basename "$f" .dot)"
  [[ -n "$filter" && "$base" != *"$filter"* ]] && continue
  # Any syntax error aborts the whole build (set -e) rather than shipping a
  # stale or half-rendered image — a diagram that lies is worse than none.
  dot -Tsvg           "$f" -o "$out/$base.svg"
  dot -Tpng -Gdpi=144 "$f" -o "$out/$base.png"
  echo "  rendered  $base  ->  render/$base.{svg,png}"
  count=$((count + 1))
done
echo "done: $count diagram(s) rendered"
