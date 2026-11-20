# Demo mutants for the runtime monitor

Each patch makes one small change to `src/`. `cargo test` still passes with each patch. The
monitor results are in `docs/monitor.md`, section 5.

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

To run all of them, use `scripts/monitor-mutants.sh` from the repository root. To try one patch
by hand, apply it to a clean checkout:

```bash
git apply mutants/r2-mac-le-epoch.patch
```

If several checkouts share one cargo target directory, set `CARGO_TARGET_DIR` per run. Two runs
that share a target directory can run each other's test binaries.
