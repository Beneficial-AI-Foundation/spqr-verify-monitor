#!/usr/bin/env bash
# Run the runtime monitor on the honest code and on each demo mutant.
#
# Usage: scripts/monitor-mutants.sh [OUT_DIR] [NAME ...]
#
# NAME is `honest` or the base name of a patch in mutants/ (for example `r2-mac-le-epoch`).
# Without names, the script runs `honest` and every patch. For each name it:
#   1. copies the committed tree (git archive HEAD) to OUT_DIR/NAME/src-tree,
#   2. applies mutants/NAME.patch there (not for `honest`),
#   3. runs `cargo test` and `cargo test --features monitor` with the traces written to
#      OUT_DIR/NAME/traces,
#   4. runs the monitor from this checkout on those traces and writes OUT_DIR/NAME/report.txt.
# OUT_DIR/NAME must not exist. OUT_DIR/summary.txt has one line per name of this run: "pass" or
# "FAIL" per test run, and "ERROR" when a build or the monitor did not complete; then the script
# exits 1. Run it from the repository root, after `lake build Monitor`. Uncommitted changes are
# not part of the copy.
#
# Prerequisites: git, cargo with the toolchain in SPQR_RUST_TOOLCHAIN (default +1.99.1), protoc,
# and lake.
# The monitor runs under `systemd-run --user --scope -p MemoryMax=16G` when systemd-run is
# available; set SPQR_MONITOR_MEMCAP=0 to run it without a cap.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
out=${1:-/tmp/spqr-monitor-mutants}
shift || true
mkdir -p "$out"
out=$(cd "$out" && pwd)
if [ $# -eq 0 ]; then
  set -- honest $(ls mutants/*.patch | xargs -n1 basename | sed 's/\.patch$//')
fi
# Check every name, that it occurs once, and that its output directory does not exist yet.
if [ "$(printf '%s\n' "$@" | sort | uniq -d)" ]; then
  echo "a name occurs twice" >&2
  exit 1
fi
for name in "$@"; do
  if [ "$name" != honest ] && { [[ $name == */* ]] || [ ! -f "mutants/$name.patch" ]; }; then
    echo "unknown name: $name (use honest or a base name in mutants/)" >&2
    exit 1
  fi
  if [ -e "$out/$name" ]; then
    echo "$out/$name exists; remove it or choose another OUT_DIR" >&2
    exit 1
  fi
done
toolchain=${SPQR_RUST_TOOLCHAIN:-+1.99.1}
memcap=()
if [ "${SPQR_MONITOR_MEMCAP:-1}" != 0 ] && command -v systemd-run > /dev/null; then
  memcap=(systemd-run --user --scope --quiet -p MemoryMax=16G -p MemorySwapMax=0)
  # Stop before the tests if the user service manager cannot run a capped scope.
  "${memcap[@]}" true || {
    echo "systemd-run cannot run a capped scope here; set SPQR_MONITOR_MEMCAP=0" >&2
    exit 1
  }
fi
: > "$out/summary.txt"
# tests STATUS LOG: "pass" (exit 0), "FAIL" (a test failed) or "ERROR" (for example a build error).
tests() {
  if [ "$1" = 0 ]; then echo pass
  elif grep -q '^test result: FAILED' "$2"; then echo FAIL
  else echo ERROR; fi
}
errors=0
for name in "$@"; do
  dir=$out/$name
  mkdir -p "$dir/src-tree" "$dir/traces"
  git archive HEAD | tar -x -C "$dir/src-tree"
  if [ "$name" != honest ]; then
    git -C "$dir/src-tree" init --quiet
    git -C "$dir/src-tree" apply "$root/mutants/$name.patch"
  fi
  # A separate target directory per run: a shared one lets parallel runs swap binaries.
  export CARGO_TARGET_DIR=$dir/target
  set +e
  (cd "$dir/src-tree" && cargo $toolchain test --quiet) > "$dir/cargo-test.txt" 2>&1
  plain=$(tests $? "$dir/cargo-test.txt")
  (cd "$dir/src-tree" && SPQR_MONITOR_DIR=$dir/traces cargo $toolchain test --quiet --features monitor) \
    > "$dir/cargo-test-monitor.txt" 2>&1
  feat=$(tests $? "$dir/cargo-test-monitor.txt")
  shopt -s nullglob
  files=("$dir"/traces/*.jsonl)
  shopt -u nullglob
  traces=${#files[@]}
  if [ "$traces" = 0 ]; then
    : > "$dir/report.txt"
    code=none
  else
    "${memcap[@]+"${memcap[@]}"}" lake env lean --run Monitor/Main.lean "${files[@]}" \
      > "$dir/report.txt" 2>&1
    code=$?
  fi
  set -e
  # The monitor ends with exit 0 and ALL CHECKS PASSED, or exit 1 and SOME CHECKS FAILED.
  verdict=$(tail -n 1 "$dir/report.txt")
  if { [ $code = 0 ] && [ "$verdict" = "ALL CHECKS PASSED" ]; } ||
     { [ $code = 1 ] && [ "$verdict" = "SOME CHECKS FAILED" ]; }; then
    monitor="monitor exit $code"
  else
    monitor="monitor ERROR (exit $code)"
  fi
  if [ "$plain" = ERROR ] || [ "$feat" = ERROR ] || [ "$traces" = 0 ] || [[ $monitor == *ERROR* ]]
  then
    errors=$((errors + 1))
  fi
  accepted=$(grep -cE '^  session [0-9]+ party [AB]: ACCEPTED' "$dir/report.txt" || true)
  rejected=$(grep -cE '^  session [0-9]+ party [AB]: REJECTED:' "$dir/report.txt" || true)
  failed=$(grep -cE '^  session [0-9]+ [a-z ()A-Z]+: FAILED:' "$dir/report.txt" || true)
  line="$name: cargo test $plain, with monitor feature $feat, $traces traces, $monitor, $accepted parties accepted, $rejected rejected, $failed cross-party checks failed"
  echo "$line" | tee -a "$out/summary.txt"
  rm -rf "$dir/target"
done
if [ $errors -gt 0 ]; then
  echo "$errors run(s) did not complete; see ERROR in $out/summary.txt" >&2
  exit 1
fi
