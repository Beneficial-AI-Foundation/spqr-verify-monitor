#!/usr/bin/env bash
# Compare where the Lean monitor, the UPPAAL replay and the Veil replay reject a mutant.
#
# Usage: scripts/viz-compare.sh [OUT_DIR]
#
# OUT_DIR is the output directory of scripts/monitor-mutants.sh (default
# /tmp/spqr-monitor-mutants). It must hold <mutant>/traces/*.jsonl and <mutant>/report.txt
# (the Lean monitor report) for honest, m1-skip-verify-ct, r2-mac-le-epoch, r3-mac-ct2-only
# and r4-verify-result-dropped.
#
# For each case and party, the script prints the operation and trace line where each tool
# rejects session 1, or "accepted".
#
# Prerequisites:
#   - python3.
#   - UPPAAL verifyta. Set VERIFYTA (default /opt/uppaal/lib/app/bin/verifyta).
#   - Optional: set VEIL_DIR to a built Veil checkout (see viz/veil/README.md) to run Veil
#     too. Veil runs `lake lean` under a 12 GB memory cap, 2 queries at a time, and takes
#     about 25 minutes for all cases.
#
# UPPAAL replays one party (`--party`) up to MARGIN operations past the Lean rejection.
# Veil replays both parties of the session together, so it finds only the first rejection
# in trace order. Its steps stop a few steps past that rejection.
# The honest run uses the largest bounds of the mutant runs and must be accepted.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR=$(realpath -m "${1:-/tmp/spqr-monitor-mutants}")
export VERIFYTA=${VERIFYTA:-/opt/uppaal/lib/app/bin/verifyta}
VEIL_DIR=${VEIL_DIR:-}
WORK=/tmp/viz-compare
MARGIN=50

UPPAAL=$REPO/scripts/uppaal/spqr_uppaal.py
VEIL=$REPO/viz/veil/trace2veil.py

CASES=(
  "m1-skip-verify-ct v1.test.chaos.jsonl"
  "r2-mac-le-epoch v1.test.chaos.jsonl"
  "r3-mac-ct2-only v1.test.chaos.jsonl"
  "r4-verify-result-dropped v1.test.tamper_chaos.jsonl"
)

[ -x "$VERIFYTA" ] || { echo "verifyta not found at $VERIFYTA" >&2; exit 1; }
[ -z "$VEIL_DIR" ] || [ -d "$VEIL_DIR" ] || { echo "VEIL_DIR $VEIL_DIR not found" >&2; exit 1; }

# lean_verdict MUTANT TRACE PARTY: "OP LINE" from the Lean report, or "accepted".
lean_verdict() {
  local report=$OUT_DIR/$1/report.txt trace=$OUT_DIR/$1/traces/$2
  [ -f "$report" ] || { echo "missing $report" >&2; exit 1; }
  awk -v hdr="$trace:" -v p="$3" '
    index($0, hdr) == 1 { on = 1; next }
    on && !/^ / { on = 0 }
    on && $0 ~ "^  session 1 party " p ": " {
      if (match($0, /operation [0-9]+ \(line [0-9]+\)/)) {
        split(substr($0, RSTART, RLENGTH), w, /[ ()]+/); print w[2], w[4]
      } else if (/ACCEPTED/) print "accepted"
      else print "unknown"
      exit
    }' "$report"
}

# fail MESSAGE: stop the whole script. The helpers run in command substitutions, where
# `set -e` does not stop the script.
fail() { echo "viz-compare: $*" >&2; kill -TERM $$; exit 1; }

# uppaal_verdict MUTANT TRACE PARTY MAX_OPS: "OP LINE" or "accepted".
uppaal_verdict() {
  local out v
  out=$(python3 -I "$UPPAAL" check "$OUT_DIR/$1/traces/$2" --party "$3" --max-ops "$4" \
          --workdir "$WORK/uppaal/$1") || fail "UPPAAL failed on $1 $2 party $3"
  if grep -q 'E<> Obs.done satisfied' <<<"$out"; then echo accepted; return; fi
  v=$(sed -n 's/^  rejected step [0-9]*: op \([0-9]*\) (line \([0-9]*\)).*/\1 \2/p' <<<"$out")
  [ -n "$v" ] || fail "no UPPAAL verdict for $1 $2 party $3:"$'\n'"$out"
  echo "$v"
}

# veil_steps TRACE OP: the number of kept Veil steps up to 3 steps past the first step at or
# after operation OP.
veil_steps() {
  python3 -I - "$REPO/viz/veil" "$1" "$2" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import trace2veil as t
sts = t.compress(list(t.steps(sys.argv[2], 1)))
op = int(sys.argv[3])
i = next((i for i, s in enumerate(sts) if s["op"] >= op), len(sts) - 1)
print(min(i + 3, len(sts)))
EOF
}

# veil_verdict MUTANT TRACE STEPS: "OP LINE PARTY" or "accepted".
veil_verdict() {
  local out v
  out=$(python3 -I "$VEIL" search "$OUT_DIR/$1/traces/$2" --veil "$VEIL_DIR" --steps "$3" \
          --jobs 2 --keep "$WORK/veil/$1") || fail "Veil failed on $1 $2"
  if grep -q '^all .* steps satisfiable' <<<"$out"; then echo accepted; return; fi
  v=$(sed -n 's/^first step with no model: step [0-9]*, line \([0-9]*\), party \([AB]\), op \([0-9]*\),.*/\3 \1 \2/p' <<<"$out")
  [ -n "$v" ] || fail "no Veil verdict for $1 $2:"$'\n'"$out"
  echo "$v"
}

fmt() {  # "OP LINE" -> "op OP (line LINE)"
  if [ "$1" = accepted ] || [ -z "$1" ]; then echo "${1:-none}"; return; fi
  set -- $1
  echo "op $1 (line $2)"
}

printf '%-26s %-27s %-5s %-20s %-32s %-24s %s\n' \
  case trace party Lean UPPAAL Veil seconds
row() { printf '%-26s %-27s %-5s %-20s %-32s %-24s %s\n' "$@"; }

max_ops=0
max_steps=0
for c in "${CASES[@]}"; do
  read -r mut trace <<<"$c"
  first_op=""; first_party=""
  declare -A lean=()
  case_ops=0
  for p in A B; do
    lean[$p]=$(lean_verdict "$mut" "$trace" "$p")
    [ "${lean[$p]}" != accepted ] || continue
    op=${lean[$p]%% *}
    if (( op + MARGIN > case_ops )); then case_ops=$((op + MARGIN)); fi
    if [ -z "$first_op" ] || (( op < first_op )); then first_op=$op; first_party=$p; fi
  done
  if (( case_ops > max_ops )); then max_ops=$case_ops; fi
  for p in A B; do
    # A party that Lean accepts is replayed with the bound of the other party.
    if [ "${lean[$p]}" = accepted ]; then n=$case_ops; else n=$(( ${lean[$p]%% *} + MARGIN )); fi
    t0=$(date +%s)
    up=$(uppaal_verdict "$mut" "$trace" "$p" "$n")
    secs=$(( $(date +%s) - t0 ))
    veil=-
    if [ -n "$VEIL_DIR" ]; then veil="(next row)"; fi
    row "$mut" "$trace" "$p" "$(fmt "${lean[$p]}")" "$(fmt "$up") ($n ops)" "$veil" \
      "uppaal $secs"
  done
  unset lean
  if [ -n "$VEIL_DIR" ] && [ -n "$first_op" ]; then
    steps=$(veil_steps "$OUT_DIR/$mut/traces/$trace" "$first_op")
    if (( steps > max_steps )); then max_steps=$steps; fi
    t0=$(date +%s)
    v=$(veil_verdict "$mut" "$trace" "$steps")
    secs=$(( $(date +%s) - t0 ))
    if [ "$v" = accepted ] || [ -z "$v" ]; then
      row "$mut" "$trace" "$first_party" "-" "-" "${v:-none} ($steps steps)" "veil $secs"
    else
      read -r vop vline vparty <<<"$v"
      row "$mut" "$trace" "$vparty" "-" "-" "op $vop (line $vline)" "veil $secs"
    fi
  fi
done

# The honest code must be accepted with the same bounds.
for p in A B; do
  lean=$(lean_verdict honest v1.test.chaos.jsonl "$p")
  t0=$(date +%s)
  up=$(uppaal_verdict honest v1.test.chaos.jsonl "$p" "$max_ops")
  secs=$(( $(date +%s) - t0 ))
  row honest v1.test.chaos.jsonl "$p" "$(fmt "$lean")" "$(fmt "$up") ($max_ops ops)" - \
    "uppaal $secs"
done
if [ -n "$VEIL_DIR" ]; then
  t0=$(date +%s)
  v=$(veil_verdict honest v1.test.chaos.jsonl "$max_steps")
  secs=$(( $(date +%s) - t0 ))
  row honest v1.test.chaos.jsonl AB - - "${v:-none} ($max_steps steps)" "veil $secs"
fi
