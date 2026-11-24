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
# The largest rejected operation of session 1 of TRACE in the report of CASE, of PARTY if given,
# or 0.
last_reject() {
  python3 -I scripts/spqr_trace.py last-reject "$out/$1/report.txt" "$out/$1/traces/$2" ${3:+"$3"}
}

# A figure around a rejection needs that rejection; a run that did not reach the changed step
# has none, and the figure keeps its old file.
skipped=()
draw_reject() {
  local name=$1 case=$2 trace=$3 party=$4
  if [ "$(last_reject "$case" "$trace" "$party")" -gt 0 ]; then
    draw "$name" seq "$case" "$trace" --around-reject "$party" --compact --radius 200 --title ""
  else
    skipped+=("$name")
  fi
}

draw_reject m1-seq-a m1-skip-verify-ct v1.test.chaos.jsonl A
draw_reject r2-seq-b r2-mac-le-epoch v1.test.chaos.jsonl B
# the R2 overview ends 100 operations after the later rejection of session 1
to=$(last_reject r2-mac-le-epoch v1.test.chaos.jsonl)
if [ "$to" -gt 0 ]; then
  draw r2-overview overview r2-mac-le-epoch v1.test.chaos.jsonl --to $((to + 100))
else
  skipped+=(r2-overview)
fi
draw_reject r4-seq-a r4-verify-result-dropped v1.test.tamper_chaos.jsonl A
if [ ${#skipped[@]} -gt 0 ]; then
  echo "not drawn, no rejection in the report (the old files stay): ${skipped[*]}" >&2
  exit 1
fi
