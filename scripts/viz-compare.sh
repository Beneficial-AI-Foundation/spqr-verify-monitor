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
# For each case and party, the script prints the operation and trace line where the Lean
# monitor and UPPAAL reject session 1, or "accepted". Veil gets one row per case, for both
# parties: the party and operation of the first rejection in trace order, or "windows
# satisfiable" with the party column AB.
#
# Prerequisites:
#   - python3.
#   - UPPAAL verifyta. Set VERIFYTA (default /opt/uppaal/lib/app/bin/verifyta).
#   - Optional: set VEIL_DIR to a built Veil checkout (see viz/veil/README.md) to run Veil
#     too. Veil runs `lake lean` under a 12 GB memory cap, 2 queries at a time, and takes
#     about 30 minutes for all cases.
#
# UPPAAL replays one party (`--party`) up to MARGIN operations past the Lean rejection.
# Veil replays both parties of the session together, so it finds only the first rejection
# in trace order. Its steps stop two kept steps past the first Lean rejection.
# The honest run uses the largest bounds of the mutant runs and must be accepted.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR=$(realpath -m "${1:-/tmp/spqr-monitor-mutants}")
export VERIFYTA=${VERIFYTA:-/opt/uppaal/lib/app/bin/verifyta}
VEIL_DIR=${VEIL_DIR:-}
WORK=$(mktemp -d /tmp/viz-compare.XXXXXX)
echo "queries and witnesses: $WORK" >&2
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

# fail MESSAGE: stop the whole script. The helpers run in command substitutions, where
# `set -e` does not stop the script.
fail() { echo "viz-compare: $*" >&2; kill -TERM $$; exit 1; }

# lean_verdict MUTANT TRACE PARTY: "OP LINE" from the Lean report, or "accepted".
lean_verdict() {
  local report=$OUT_DIR/$1/report.txt trace=$OUT_DIR/$1/traces/$2 v
  [ -f "$report" ] || fail "missing $report"
  v=$(python3 -I "$REPO/scripts/spqr_trace.py" verdict "$report" "$trace" "$3") ||
    fail "cannot read $report"
  [ -n "$v" ] || fail "no Lean verdict for $trace party $3 in $report"
  echo "$v"
}

# uppaal_verdict MUTANT TRACE PARTY MAX_OPS: "OP LINE" or "accepted".
uppaal_verdict() {
  local out v
  out=$(python3 -I "$UPPAAL" check "$OUT_DIR/$1/traces/$2" --session 1 --party "$3" --max-ops "$4" \
          --workdir "$WORK/uppaal/$1") || fail "UPPAAL failed on $1 $2 party $3"
  if grep -q 'E<> Obs.done satisfied' <<<"$out"; then echo accepted; return; fi
  v=$(sed -n 's/^  rejected step [0-9]*: op \([0-9]*\) (line \([0-9]*\)).*/\1 \2/p' <<<"$out")
  [ -n "$v" ] || fail "no UPPAAL verdict for $1 $2 party $3:"$'\n'"$out"
  echo "$v"
}

# veil_steps TRACE OP: the number of kept Veil steps up to the first kept step at or after
# operation OP and two more steps.
veil_steps() {
  python3 -I - "$REPO/viz/veil" "$1" "$2" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
import trace2veil as t
op = int(sys.argv[3])
n, stop = 0, None
for n, s in enumerate(t.compress(t.steps(sys.argv[2], 1)), 1):
    if stop is None and s["op"] >= op:
        stop = n + 2
    if n == stop:
        break
print(n)
EOF
}

# veil_verdict MUTANT TRACE STEPS: "OP LINE PARTY", or "accepted N" with the N steps checked.
# One Veil row: AB and "windows satisfiable", or the party and operation of the first rejection.
veil_row() {
  local vop vline vparty
  if [[ $3 == accepted* ]]; then
    row "$1" "$2" AB - - "windows satisfiable (${3#accepted } steps)" "veil $5"
  else
    read -r vop vline vparty <<<"$3"
    row "$1" "$2" "$vparty" - - "op $vop (line $vline)" "veil $5"
  fi
}

veil_verdict() {
  local out v
  out=$(python3 -I "$VEIL" search "$OUT_DIR/$1/traces/$2" --veil "$VEIL_DIR" --steps "$3" \
          --jobs 2 --keep "$WORK/veil/$1") || fail "Veil failed on $1 $2"
  v=$(sed -n 's/^all \([0-9]*\) steps satisfiable.*/\1/p' <<<"$out")
  if [ -n "$v" ]; then echo "accepted $v"; return; fi
  v=$(sed -n 's/^first step with no model: step [0-9]*, line \([0-9]*\), party \([AB]\), op \([0-9]*\),.*/\3 \1 \2/p' <<<"$out")
  [ -n "$v" ] || fail "no Veil verdict for $1 $2:"$'\n'"$out"
  echo "$v"
}

fmt() {  # "OP LINE" -> "op OP (line LINE)"
  if [ "$1" = accepted ] || [ -z "$1" ]; then echo "${1:-none}"; return; fi
  if [ "$1" = rejected ]; then echo "rejected, no operation"; return; fi
  set -- $1
  if [ "$2" = - ]; then echo "op $1"; else echo "op $1 (line $2)"; fi
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
    [ "${lean[$p]}" != accepted ] && [ "${lean[$p]}" != rejected ] || continue
    op=${lean[$p]%% *}
    if (( op + MARGIN > case_ops )); then case_ops=$((op + MARGIN)); fi
    if [ -z "$first_op" ] || (( op < first_op )); then first_op=$op; first_party=$p; fi
  done
  if (( case_ops == 0 )); then
    # no rejected operation (the run did not reach the changed step, or the rejection names
    # none): no replay bound, so the replays do not run
    for p in A B; do
      row "$mut" "$trace" "$p" "$(fmt "${lean[$p]}")" "not run (no rejected operation)" - -
    done
    unset lean
    continue
  fi
  if (( case_ops > max_ops )); then max_ops=$case_ops; fi
  for p in A B; do
    # A party that Lean accepts is replayed with the bound of the other party.
    if [ "${lean[$p]}" = accepted ] || [ "${lean[$p]}" = rejected ]; then n=$case_ops; else n=$(( ${lean[$p]%% *} + MARGIN )); fi
    t0=$(date +%s)
    up=$(uppaal_verdict "$mut" "$trace" "$p" "$n")
    secs=$(( $(date +%s) - t0 ))
    veil=-
    if [ -n "$VEIL_DIR" ]; then veil="(next row)"; fi
    row "$mut" "$trace" "$p" "$(fmt "${lean[$p]}")" "$(fmt "$up") (op limit $n)" "$veil" \
      "uppaal $secs"
  done
  unset lean
  if [ -n "$VEIL_DIR" ] && [ -n "$first_op" ]; then
    steps=$(veil_steps "$OUT_DIR/$mut/traces/$trace" "$first_op")
    if (( steps > max_steps )); then max_steps=$steps; fi
    t0=$(date +%s)
    v=$(veil_verdict "$mut" "$trace" "$steps")
    secs=$(( $(date +%s) - t0 ))
    veil_row "$mut" "$trace" "$v" "$steps" "$secs"
  fi
done

# The honest code must be accepted with the same bounds.
honest_ok=true
for p in A B; do
  lean=$(lean_verdict honest v1.test.chaos.jsonl "$p")
  t0=$(date +%s)
  up=$(uppaal_verdict honest v1.test.chaos.jsonl "$p" "$max_ops")
  secs=$(( $(date +%s) - t0 ))
  row honest v1.test.chaos.jsonl "$p" "$(fmt "$lean")" "$(fmt "$up") (op limit $max_ops)" - \
    "uppaal $secs"
  [ "$lean" = accepted ] && [ "$up" = accepted ] || honest_ok=false
done
if [ -n "$VEIL_DIR" ]; then
  t0=$(date +%s)
  v=$(veil_verdict honest v1.test.chaos.jsonl "$max_steps")
  secs=$(( $(date +%s) - t0 ))
  [[ $v == accepted* ]] || honest_ok=false
  veil_row honest v1.test.chaos.jsonl "$v" "$max_steps" "$secs"
fi
$honest_ok || { echo "viz-compare: a tool rejects the honest trace" >&2; exit 1; }
