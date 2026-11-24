# Demo mutants for the runtime monitor

Each patch makes one small change to `src/`. `cargo test` still passes with each patch.

| Patch | Change |
|-------|--------|
| `m1-skip-verify-ct.patch` | deletes the `verify_ct` call in `recv_ct2` |
| `m2-skip-verify-hdr.patch` | deletes the `verify_hdr` call in `recv_header` |
| `m5-keygen-randomness-fixed.patch` | `generate` uses all-zero KeyGen randomness |
| `m6-header-mac-label.patch` | `mac_hdr` uses the ciphertext label |
| `r1-mac-root-key.patch` | `mac_ct` keys the HMAC with `root_key` |
| `r2-mac-le-epoch.patch` | `mac_ct` encodes the epoch little-endian |
| `r3-mac-ct2-only.patch` | both parties MAC `ct2` only, not `ct1 ‖ ct2` |
| `r4-verify-result-dropped.patch` | drops the result of `verify_ct` |

To run all of them, use `scripts/monitor-mutants.sh` from the repository root, after
`lake build Monitor`. The script needs `cargo +1.99.1` and `protoc`. Each case takes about 6 minutes:

```bash
O=$(mktemp -d)
scripts/monitor-mutants.sh "$O"
```

When `systemd-run` exists, the script runs the monitor under
`systemd-run --user --scope -p MemoryMax=16G`, which needs a user service manager. Without one,
run `SPQR_MONITOR_MEMCAP=0 scripts/monitor-mutants.sh "$O"`.
`$O/summary.txt` has one line per case, and `$O/<name>/report.txt` has the monitor report.

Result of a run on 2026-11-21. "Standard" is the eleven standard traces (22 parties). "Tamper"
is the two tamper traces, which exist only with the feature `monitor`. When a tamper test fails
before its last session starts, its trace has fewer parties.

| Patch | Feature run | Standard: rejected | Tamper: rejected / parties | Failed cross-party checks |
|-------|-------------|--------------------|----------------------------|---------------------------|
| `m1-skip-verify-ct` | both tamper tests fail | 22/22 | 2/6 | key agreement (tamper) |
| `m2-skip-verify-hdr` | both tamper tests fail | 22/22 | 3/4 | none |
| `m5-keygen-randomness-fixed` | 59 passed | 0/22 | 0/14 | randomness reuse, 12 sessions |
| `m6-header-mac-label` | 59 passed | 22/22 | 14/14 | none |
| `r1-mac-root-key` | 59 passed | 22/22 | 8/14 | none |
| `r2-mac-le-epoch` | 59 passed | 22/22 | 8/14 | none |
| `r3-mac-ct2-only` | 59 passed | 22/22 | 8/14 | none |
| `r4-verify-result-dropped` | both tamper tests fail | 0/22 | 2/6 | key agreement (tamper) |

The standard tests draw their randomness from `OsRng`. A run finds a mutant only if it reaches
the changed step, and the rejected operations change from run to run. The two tamper tests use a
fixed seed. To try one patch
by hand, apply it to a clean checkout:

```bash
git apply mutants/r2-mac-le-epoch.patch
```

If several checkouts share one cargo target directory, set `CARGO_TARGET_DIR` per run. Two runs
that share a target directory can run each other's test binaries.
