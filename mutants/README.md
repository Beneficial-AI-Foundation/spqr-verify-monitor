# Demo mutants for the runtime monitor

Each patch changes `src/` in one way. With the patch applied, `cargo test` still passes, and the
monitor rejects the traces. Apply one patch at a time:

```
git apply mutants/r2-mac-le-epoch.patch
```

| Patch | Change | Monitor |
|-------|--------|---------|
| `m1-skip-verify-ct.patch` | deletes the `verify_ct` call | rejects 22/22 parties |
| `r1-mac-root-key.patch` | `mac_ct` keys the HMAC with `root_key` | rejects 22/22 parties |
| `r2-mac-le-epoch.patch` | `mac_ct` encodes the epoch little-endian | rejects 22/22 parties |
| `r3-mac-ct2-only.patch` | both parties MAC `ct2` only, not `ct1 ‖ ct2` | rejects 22/22 parties |
| `r4-verify-result-dropped.patch` | drops the result of `verify_ct` | accepts honest traces, rejects the tamper tests |

The traces come from `cargo +1.99.1 test --features monitor` with `SPQR_MONITOR_DIR` set. Use
your own `CARGO_TARGET_DIR` for each run. `~/.cargo/config.toml` shares one target directory
between worktrees, so two runs at the same time can use each other's binaries.
