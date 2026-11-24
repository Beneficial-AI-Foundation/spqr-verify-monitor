#!/usr/bin/env bash
# Draw the trace figures of docs/monitor-slides from a run of scripts/monitor-mutants.sh.
#
# Usage: scripts/monitor-figures.sh [OUT_DIR]
#
# OUT_DIR is the output directory of scripts/monitor-mutants.sh (default
# /tmp/spqr-monitor-mutants), with the cases honest, m1-skip-verify-ct, r2-mac-le-epoch and
# r4-verify-result-dropped. The script writes the PDF figures to docs/monitor-slides/fig/.
#
# Prerequisites: python3 and rsvg-convert.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
out=$(realpath -m "${1:-/tmp/spqr-monitor-mutants}")
fig=docs/monitor-slides/fig
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# draw NAME VIEW CASE TRACE [VIEWER OPTION ...]: draw fig/NAME.pdf from a trace of case CASE.
draw() {
  local name=$1 view=$2 case=$3 trace=$4
  shift 4
  python3 -I scripts/trace-viewer.py "$view" "$out/$case/traces/$trace" \
    --report "$out/$case/report.txt" "$@" -o "$work/$name.svg"
  rsvg-convert -f pdf -o "$fig/$name.pdf" "$work/$name.svg"
}

draw honest-seq seq honest v1.test.chaos.jsonl --compact --max-rows 24 --title ""
draw honest-overview overview honest v1.test.chaos.jsonl
draw m1-seq-a seq m1-skip-verify-ct v1.test.chaos.jsonl --around-reject A --compact --radius 200 --title ""
draw r2-seq-b seq r2-mac-le-epoch v1.test.chaos.jsonl --around-reject B --compact --radius 200 --title ""
# the R2 overview ends 100 operations after the later rejection of session 1
to=$(awk -v t=v1.test.chaos.jsonl '/^[^ ]/ { blk = index($0, t) > 0 }
  blk && /session 1 party [AB]: REJECTED: operation/ {
    match($0, /operation [0-9]+/); n = substr($0, RSTART + 10, RLENGTH - 10) + 0
    if (n > m) m = n }
  END { print m + 0 }' "$out/r2-mac-le-epoch/report.txt")
[ "$to" -gt 0 ] || { echo "no rejection of session 1 in the R2 chaos report" >&2; exit 1; }
draw r2-overview overview r2-mac-le-epoch v1.test.chaos.jsonl --to $((to + 100))
draw r4-seq-a seq r4-verify-result-dropped v1.test.tamper_chaos.jsonl --around-reject A --compact --radius 200 --title ""
