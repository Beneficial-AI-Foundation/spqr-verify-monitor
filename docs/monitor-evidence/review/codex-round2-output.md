# Codex review, round 2

1. HIGH — [scripts/monitor-mutants.sh:32]: The memory-cap fix still permits broken reproduction. Checking that `systemd-run` exists does not establish that a user service manager is available or supports the requested properties. On systems with the executable but no usable user manager, the documented command runs the expensive Rust tests and then fails every monitor invocation. Fix: probe the actual capped runner before starting the tests, with an explicit fallback or early diagnostic. Document `SPQR_MONITOR_MEMCAP=0` in `docs/monitor.md`, where the reproduction command appears.

2. HIGH — [docs/monitor.md:189]: The comparison table presents prefix acceptance as session acceptance. `viz-compare.sh` bounds UPPAAL by the mutant rejection operations plus 50, and bounds Veil near the first rejection. It uses those bounds for the honest trace too. In the available run, UPPAAL checks only operations through 1,183 of 84,596 honest operations; Veil checks 144 of 25,240 retained steps. The table omits these limits and places “accepted” beside the Lean monitor’s complete-session verdict. Fix: describe the comparison as bounded replay, label these cells “checked prefix accepted,” and include the bounds. Alternatively, run complete sessions before claiming complete-session acceptance.

3. HIGH — [viz/veil/trace2veil.py:249]: A relative `--keep` directory breaks both execution modes. With `--keep results`, the script writes `results/check_N.lean` relative to the caller’s directory, then passes that relative filename to Lean with `cwd=veil`. Lean consequently looks under the Veil checkout instead of where the file was written. Fix: resolve `a.keep` to an absolute path before creating directories or constructing query filenames.

4. HIGH — [scripts/viz-compare.sh:89]: Solver failures are swallowed by the comparison helpers. `veil_verdict` runs inside command substitution, where Bash normally disables `errexit`. If Python fails, the function continues to its successful `sed` command, returns an empty result, and the script prints `none` while exiting successfully. Redirecting stderr to `/dev/null` also hides the cause. `uppaal_verdict` has the same status-propagation problem; its Python checker additionally returns normally when no verification result can be parsed. Fix: explicitly propagate subprocess failures, preserve their diagnostics, and reject output that contains neither a recognized acceptance nor a rejection. Make the Python checker return nonzero on verification-tool or output-parsing errors.

5. MEDIUM — [viz/veil/trace2veil.py:209]: The snapshot fix retains growing-history duplication. The trace is now scanned once, but every window copies and sorts the entire accumulated `sent` set, and all snapshots are retained before checking any window. As epochs accumulate, this still gives quadratic storage and repeated sorting work. The available honest trace produces 949,491 stored message references across 2,104 snapshots, although the final set contains only 902 facts. Fix: discard sent facts older than both parties’ current epochs, since this model does not check delivery of older messages, and construct snapshots lazily for each batch. Retain the failing window’s snapshot for bisection.

VERDICT: CHANGES NEEDED

## Resolution

1. Fixed. `scripts/monitor-mutants.sh` runs `systemd-run ... true` before the tests and stops
   with a message that names `SPQR_MONITOR_MEMCAP=0`. Section 5 documents the variable.
2. Fixed. Section 7 says that both replays check a prefix, gives the bounds, and labels the
   cells "prefix accepted". A full honest session did not finish in UPPAAL in 6 minutes.
3. Fixed. `--keep` is made absolute. Tested with `--keep results` from another directory.
4. Fixed. The helpers in `viz-compare.sh` stop the script when a tool fails or prints no
   verdict. `spqr_uppaal.py` exits nonzero when verifyta fails or prints no result.
5. Fixed. A snapshot keeps only the sent facts at or above the smaller epoch. On the honest
   trace the snapshots hold 8,946 facts instead of 949,491. The R3 search still stops at op 275.
