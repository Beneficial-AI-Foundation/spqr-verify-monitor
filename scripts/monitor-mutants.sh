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
# OUT_DIR/summary.txt gets one line per name. Run it from the repository root, after
# `lake build Monitor`. Uncommitted changes are not part of the copy.
#
# Prerequisites: git, cargo with the toolchain in SPQR_RUST_TOOLCHAIN (default +1.99.1), and lake.
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
for name in "$@"; do
  dir=$out/$name
  rm -rf "$dir"
  mkdir -p "$dir/src-tree" "$dir/traces"
  git archive HEAD | tar -x -C "$dir/src-tree"
  if [ "$name" != honest ]; then
    git -C "$dir/src-tree" init --quiet
    git -C "$dir/src-tree" apply "$root/mutants/$name.patch"
  fi
  # A separate target directory per run: a shared one lets parallel runs swap binaries.
  export CARGO_TARGET_DIR=$dir/target
  (cd "$dir/src-tree" && cargo $toolchain test --quiet) > "$dir/cargo-test.txt" 2>&1 \
    && plain=pass || plain=FAIL
  (cd "$dir/src-tree" && SPQR_MONITOR_DIR=$dir/traces cargo $toolchain test --quiet --features monitor) \
    > "$dir/cargo-test-monitor.txt" 2>&1 && feat=pass || feat=FAIL
  set +e
  "${memcap[@]+"${memcap[@]}"}" lake env lean --run Monitor/Main.lean "$dir"/traces/*.jsonl > "$dir/report.txt" 2>&1
  code=$?
  set -e
  traces=$(ls "$dir"/traces/*.jsonl | wc -l)
  accepted=$(grep -c ': ACCEPTED' "$dir/report.txt" || true)
  rejected=$(grep -c ': REJECTED:' "$dir/report.txt" || true)
  failed=$(grep -c ': FAILED:' "$dir/report.txt" || true)
  line="$name: cargo test $plain, with monitor feature $feat, $traces traces, monitor exit $code, $accepted parties accepted, $rejected rejected, $failed cross-party checks failed"
  echo "$line" | tee -a "$out/summary.txt"
  rm -rf "$dir/target"
done
