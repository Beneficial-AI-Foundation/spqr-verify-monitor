#!/bin/bash
# R4 mutant on a scratch copy of the tamper branch: cargo test, traces, monitor.
WT=/home/lacra/git_repos/baif/SparsePostQuantumRatchet-verify/.claude/worktrees/spqr-monitor-tamper-8a6172
S=/tmp/spqr-r4
rm -rf $S/src && mkdir -p $S && cp -r $WT/src $WT/Cargo.toml $WT/Cargo.lock $WT/build.rs $WT/benches $S/ 2>/dev/null
export CARGO_TARGET_DIR=$S/target
cd $S
sed -i 's|        auth.verify_ct(epoch, &ct1, &mac)?;|        let _ = auth.verify_ct(epoch, \&ct1, \&mac);|' src/v1/unchunked/send_ek.rs
diff $WT/src/v1/unchunked/send_ek.rs src/v1/unchunked/send_ek.rs
echo "== cargo test (default features)"; cargo +1.99.1 test 2>&1 | grep -E "^test result|FAILED|panicked" | head -3
rm -rf /tmp/spqr-traces-R4
echo "== cargo test --features monitor"; SPQR_MONITOR_DIR=/tmp/spqr-traces-R4 cargo +1.99.1 test --features monitor 2>&1 | grep -E "^test result|FAILED|panicked|^Error" | head -6
cd $WT
echo "== monitor"; lake env lean --run Monitor/Main.lean /tmp/spqr-traces-R4/*.jsonl | grep -E "jsonl|REJECTED|FAILED|PASSED" | cut -c1-330
