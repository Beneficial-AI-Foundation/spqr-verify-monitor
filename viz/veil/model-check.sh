#!/usr/bin/env bash
# Model check SpqrBraid with a property that fails once Alice reaches epoch 3, and write the
# counterexample (a shortest run of two epochs) as JSON for panel.html.
#
# Usage: model-check.sh VEIL_DIR OUT.json
# VEIL_DIR is a built Veil checkout (`lake build Veil`).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
veil=$1
out=$(realpath -m "$2")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 -I - "$here/SpqrBraid.lean" "$work/mc.lean" <<'EOF'
import sys
m = open(sys.argv[1]).read()
m = m.replace("#gen_spec", """/- Fails once Alice reaches epoch 3. -/
safety [alice_below_epoch_3] ep pA < 3

#gen_spec

set_option veil.modelChecker.buildOnly true in
#model_check { } { }""")
open(sys.argv[2], "w").write(m)
EOF
# The build takes about 1 minute and 2 GB. The cap keeps a runaway build from taking the machine.
log=$(cd "$veil" && systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 \
  lake lean "$work/mc.lean" 2>&1 || true)
binary=$(printf '%s\n' "$log" | sed -n 's/^VEIL_BUILD_ONLY .*"binary":"\([^"]*\)".*/\1/p')
if [ -z "$binary" ]; then printf '%s\n' "$log" >&2; exit 1; fi
# The checker stops when its stdin closes, so keep stdin open while it runs. A process
# substitution, unlike a pipe from `sleep`, does not make the shell wait for `sleep`. The
# checker writes its progress to stderr and the result to stdout.
"$binary" > "$out" 2> /dev/null < <(sleep 600)
echo "wrote $out"
