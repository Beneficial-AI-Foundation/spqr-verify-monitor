# Runtime monitor for SPQR

This branch adds a runtime monitor for the SPQR test harness, in the style of SpecMon. The
instrumented Rust tests write an event log. A Lean program replays each party's events through
`BraidModel`, the executable model of ML-KEM Braid §2.5 that `run_refines` relates to the
extracted code. This document lists the results, what each result means, and how to reproduce
it.

## 1. Results

| # | Result | Evidence |
|---|--------|----------|
| 1 | If the monitor accepts a party, then the party's logged steps are a `BraidModel` run for every primitive function that agrees with the logged primitive calls. | Lean theorems (section 2) |
| 2 | On the unmodified code, the monitor accepts every party of every test trace, and the cross-party checks pass. | `honest` run (section 4) |
| 3 | Six one-line changes to `src/` pass `cargo test`. On the eleven standard traces, the monitor rejects all 22 parties for each change, and names the operation and the missing primitive value. | mutants M1, M2, M6, R1, R2, R3 (section 5) |
| 4 | A dropped verification result (R4) passes `cargo test`, and the monitor accepts R4 on the standard traces. A test driver that tampers with messages in transit exposes it: the monitor rejects the first party that accepts a tampered chunk. The tamper tests also fail on their own key check. | mutant R4, tests `tamper_early` and `tamper_chaos` |
| 5 | Fixed KeyGen randomness (M5) is a valid model run. A separate check, outside the theorems, rejects it. | mutant M5 |

The other material on the branch illustrates these results and adds no detection power:

- `scripts/trace-viewer.py` draws a trace as an SVG figure.
- `scripts/uppaal/` and `viz/veil/` replay a trace in an UPPAAL model and in a Veil model of the
  braid. Both models see an abstraction of the trace: a MAC check reaches them only as a
  good/bad token that a Python script computes from the logged bytes. Section 7 compares the
  operations where they reject with the Lean monitor.
- `docs/monitor-slides/` is a Beamer talk (`latexmk -lualatex -cd docs/monitor-slides/slides.tex`).
- `docs/monitor-demo.md`, `docs/monitor-plan.md`, `docs/monitor-plan-reviews.md` and
  `docs/monitor-evidence/` are the run log, the plan, the plan reviews and the raw evidence of
  the development sessions. Commands and paths in them refer to branches and `/tmp` files of
  that time. Use this document to reproduce the results.

## 2. What is proved, and what is trusted

`Spqr/Specs/Braid/StateMachine/PartialModel.lean` defines partial primitives `OPrims` (a table
of the primitive values that one operation logged) and the steps `sendO` and `receiveO` over
them. `Agrees P Q` says that the total primitives `P` extend the table `Q`.
`Spqr/Specs/Braid/StateMachine/Monitor.lean` defines the checker `checkRun` and proves:

- `checkRun_sound`: if `checkRun σ steps = some σ'`, then for every `P` that extends the table of
  each step, the observations are model steps from `σ` to `σ'` (`Explains`).
- `Explains.run`: such observations give a `BraidModel.Run` that emits the observed keys.
- `accepted_alice`, `accepted_bob`: the same from `InitAlice` and `InitBob`.

The proofs have no `sorry`. The following parts are trusted, not proved:

- the instrumentation hooks in `src/` and the event writer `src/monitor.rs`;
- the executable in `Monitor/`: the JSON reader, the construction of each table from the logged
  calls, and the pass that adds decoder results to the tables;
- the cross-party checks in `Monitor/Check.lean`: delivery (every received message was sent by
  the peer, or is a logged tampered copy of such a message), key agreement (each party logs at most one key per epoch, and
  when both parties log a key for an epoch, the keys are equal; an epoch with a key from one
  party only is listed as incomplete, not as a failure), and randomness reuse (no two `mlkem.generate` or `mlkem.encaps1`
  calls of a session get the same randomness).

Scope: the monitor observes the chunked `States` machine as the orchestrator tests drive it
(`src/test/v1_impls.rs`). It does not observe the public API in `src/lib.rs`, the `chain.rs`
layer, or the state serialization. It checks test executions, not a deployed client.

## 3. Setup

- Rust: `cargo +1.99.1`. The default stable toolchain does not compile `std::assert_matches` in
  `src/lib.rs`.
- Lean: the toolchain in `lean-toolchain`. Build the theorems and the monitor:

  ```bash
  lake build Spqr.Specs.Braid.StateMachine.Monitor Monitor
  ```

- If several checkouts share one cargo target directory (for example through
  `~/.cargo/config.toml`), set `CARGO_TARGET_DIR` per checkout. Two runs that share a target
  directory can run each other's test binaries.

With the feature `monitor` off, the instrumentation compiles to nothing. To make sure that the
code that Charon extracts does not change, compare the expanded crate with the base commit:

```bash
cargo +nightly-2025-09-24 rustc --lib --quiet -- -Zunpretty=expanded > /tmp/expanded-branch.rs
```

Run the same command in a copy of `main` and compare the two files with `diff`. They must be
identical.

## 4. Run the monitor on the unmodified code

```bash
cargo +1.99.1 test
SPQR_MONITOR_DIR=/tmp/spqr-traces cargo +1.99.1 test --features monitor
lake env lean --run Monitor/Main.lean /tmp/spqr-traces/*.jsonl
```

The second command writes one JSONL file per test that uses the orchestrator. The monitor prints
one line per party (`ACCEPTED` or `REJECTED` with the operation and the reason) and one line per
cross-party check, and ends with `ALL CHECKS PASSED` (exit 0) or `SOME CHECKS FAILED` (exit 1).
The interpreted run takes about 4 minutes for all traces. Run the monitor under a memory cap if
the machine has little memory.

Result on the branch (2026-11-20): `cargo test` 57 passed, the feature run 59 passed, 13
traces (the eleven standard tests and the two tamper tests), 18 sessions. The monitor accepts all
36 parties, and every cross-party check passes. In 15 of the 18 sessions, the last epoch has a key
from one party only, because the test stops in the middle of an epoch; the report lists it as
incomplete.

## 5. Reproduce the mutant results

Each file in `mutants/` is a one-line change to `src/`. `scripts/monitor-mutants.sh` copies the
committed tree, applies one patch, runs both test commands with a separate target directory, and
runs the monitor on the new traces:

```bash
scripts/monitor-mutants.sh /tmp/spqr-monitor-mutants
```

It takes about 6 minutes per patch. `/tmp/spqr-monitor-mutants/summary.txt` has one line per
patch, and `/tmp/spqr-monitor-mutants/<name>/report.txt` has the full monitor report.

Result on the branch (2026-11-20). "Standard" is the eleven standard traces (22 parties).
"Tamper" is the two tamper traces. A tamper test that fails stops early, so its trace has fewer
sessions.

| Patch | `cargo test` | Feature run | Standard: rejected | Tamper: rejected / parties | Failed cross-party checks |
|-------|--------------|-------------|--------------------|----------------------------|---------------------------|
| M1 `m1-skip-verify-ct` | 57 passed | both tamper tests fail | 22/22 | 3/6 | key agreement (tamper) |
| M2 `m2-skip-verify-hdr` | 57 passed | `tamper_chaos` fails | 22/22 | 8/14 | none |
| M5 `m5-keygen-randomness-fixed` | 57 passed | 59 passed | 0/22 | 0/14 | randomness reuse, 12 sessions |
| M6 `m6-header-mac-label` | 57 passed | 59 passed | 22/22 | 14/14 | none |
| R1 `r1-mac-root-key` | 57 passed | 59 passed | 22/22 | 8/14 | none |
| R2 `r2-mac-le-epoch` | 57 passed | 59 passed | 22/22 | 8/14 | none |
| R3 `r3-mac-ct2-only` | 57 passed | 59 passed | 22/22 | 8/14 | none |
| R4 `r4-verify-result-dropped` | 57 passed | both tamper tests fail | 0/22 | 2/6 | key agreement (tamper) |

The tamper tests exist only with the feature `monitor`. When a mutant accepts a tampered chunk
(M1, M2, R4), the two parties derive different keys, and the test's own key check fails. For R4
the monitor rejects the same runs, and it also names the step: for example "operation 1147,
`States::recv` in `ekSentCt1Received` epoch 2, ct2 #0: the model's Receive() fails, the code
accepted".

## 6. What the results do not show

- R1, R2 and R3 are deviations from the specification, not attacks. For example, R2 encodes the
  epoch little-endian, which is still a one-to-one encoding. A known-answer test of `mac_ct`
  also catches R1 and R2. R3 leaves `mac_ct` unchanged and changes its callers, so only a test
  that checks the MAC input of `send_ct2` or `recv_ct2` catches it.
- An acceptance covers only the steps that the tests executed. Code paths that no test reaches
  are not checked.
- The monitor reports the first step that the model cannot explain, and names the missing
  primitive value. It does not name the cause: "on other keys or data" can mean a wrong key, a
  wrong epoch encoding or missing bytes.
