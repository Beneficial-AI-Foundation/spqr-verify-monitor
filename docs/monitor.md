# Runtime monitor for SPQR

This branch adds a runtime monitor for the SPQR test harness, in the style of SpecMon. The
instrumented Rust tests write an event log. A Lean program replays each party's events through
`BraidModel`, the executable model of ML-KEM Braid §2.5 that `run_refines` relates to the
extracted code. The model includes three deviations of the code from §2.5
(`Spqr/Specs/Braid/Deviations.lean`). This document lists the results, what each result means, and how to reproduce
it.

The monitor checks what the proofs cannot reach. `run_refines` is a theorem about the Lean
translation, not about the binary. Aeneas translates only part of the program. The ML-KEM, HMAC
and HKDF calls are hand-written Lean models or opaque functions, the Rust is patched before
extraction, and the binary depends on the compiler and on code that is not translated. The
monitor takes each primitive value from the binary that runs, so it tests these assumptions on
real executions. Section 2 lists them.

## 1. Results

| # | Result | Evidence |
|---|--------|----------|
| 1 | If the monitor accepts a party, then for every primitive function that extends the tables built from that party's log, each logged step is the model's step, and the model has a run that emits the logged keys. | Lean theorems (section 2) |
| 2 | On the unmodified code, the monitor accepts every party of every test trace, and the cross-party checks pass. | `honest` run (section 4) |
| 3 | Six small changes to `src/` pass `cargo test`. On the eleven standard traces, the monitor rejects all 22 parties for each change, and names the rejected operation. | mutants M1, M2, M6, R1, R2, R3 (section 5) |
| 4 | A dropped verification result (R4) passes `cargo test`, and the monitor accepts R4 on the standard traces. A test driver that tampers with chunks in transit exposes it: when a `Ct2` decoder that got a tampered chunk completes, the MAC check fails and R4 accepts anyway, and the monitor rejects that step. The tamper tests also fail on their own key check. | mutant R4, tests `tamper_early` and `tamper_chaos` |
| 5 | Fixed KeyGen randomness (M5) is a valid model run. A separate check, outside the theorems, rejects it. | mutant M5 |

The other material on the branch illustrates these results. In the mutant comparison of section
7, the replays reject no mutant that the Lean monitor accepts:

- `scripts/trace-viewer.py` draws a trace as an SVG figure.
- `scripts/uppaal/` and `viz/veil/` replay a trace in an UPPAAL model and in a Veil model of the
  braid. Both models see an abstraction of the trace: a Python script checks the logged HMAC
  input against the model's formula and passes a token. UPPAAL gets a missing token when no
  input matches, and a bad token when the received tag differs from the computed one. Veil gets
  `absent`, `good` or `bad`: `bad` when the input does not have the form of the MAC input, or
  when its ciphertext bytes differ from those of the logged `decaps` or `encaps2` call. Veil
  does not compare tags. Section 7 compares the operations
  where they reject with the Lean monitor.
- `docs/monitor-slides/` is a Beamer talk (`latexmk -lualatex -cd docs/monitor-slides/slides.tex`).
  Section 8 says how to redraw its figures.

## 2. What is proved, and what is trusted

`Spqr/Specs/Braid/StateMachine/PartialModel.lean` defines partial primitives `OPrims` (a table
of the primitive values that one operation logged). The model's steps `sendM` and `receiveM` are
generic over a monad, and the checker runs them in `Option` over `OPrims`. `Agrees P Q` says that
the total primitives `P` extend the logged values of `Q`, and that `P` has the same total fields
as `Q`: `encode`, `decoderNew`, `addChunk`, the sizes, `PROTOCOL_INFO` and `ToBytes`. The
executable defines these total fields (`Monitor/Tables.lean`), so they are trusted too.
`Spqr/Specs/Braid/StateMachine/Monitor.lean` defines the checker `checkRun` and proves:

- `checkRun_sound`: if `checkRun σ steps = some σ'`, then for every `P` that extends the table of
  each step, the observations are model steps from `σ` to `σ'` (`Explains`). A `send` gives the
  observed message, key, state name and epoch. A successful `recv` gives the observed key, state
  name and epoch. A failed `recv` is a failed `Receive()` and leaves the state unchanged.
- `Explains.run`: such observations give a `BraidModel.Run` that emits the observed keys. The
  run has no step for a failed `recv`.
- `accepted_alice`, `accepted_bob`: both conclusions from `initAlice P ss` and `initBob P ss`,
  for every `P` that also extends the table of the initialization.

The proofs have no `sorry`. To list the axioms of the theorems:

```bash
cat > /tmp/axioms.lean <<'LEAN'
import Spqr.Specs.Braid.StateMachine.Monitor
#print axioms BraidModel.accepted_alice
#print axioms BraidModel.accepted_bob
LEAN
lake env lean /tmp/axioms.lean
```

Both depend only on `propext`, `Classical.choice` and `Quot.sound`. The following parts are trusted, not proved:

- the instrumentation hooks in `src/` and the event writer `src/monitor.rs`. The decoder hook
  calls `decoded_message()` itself, apart from the call whose value the code uses, so the two
  calls are assumed to return the same result. The replay takes the decoder result from the log;
- the executable in `Monitor/`: the JSON reader, the construction of each table from the logged
  calls, and the pass that adds decoder results to the tables. This construction interprets the
  log: it assigns each decoder result to the decoder that the model's step uses, keys the `hmac`
  table by the key and the data without the algorithm and the tag length, and keys the `Encaps2`
  table without the model's header argument. The tables of a party are consistent: one argument
  has one result. The tables of the two parties are not compared;
- the cross-party checks in `Monitor/Check.lean`: delivery (every received message was sent by
  the peer, or is a logged tampered copy of such a message), key agreement (each party logs at most one key per epoch, and
  when both parties log a key for an epoch, the keys are equal; an epoch with a key from one
  party only is listed as incomplete, not as a failure), and randomness reuse (no two `mlkem.generate` or `mlkem.encaps1`
  calls of a session get the same randomness).

### What the monitor checks that the proofs do not

`run_refines` says: if the code state `s` is related to the model state `σ` (`Refines s σ`),
then every sequence of successful calls of the extracted code from `s` is a `BraidModel` run from
`σ`, for every `P` with `CodeAgrees P`. `CodeAgrees` relates `P` to the Lean translation of the code. That
translation differs from the binary in these places:

- `SrcTranslated/FunsExternal.lean` replaces the external functions with Lean written by hand.
  ML-KEM is a model of FIPS 203, not a translation of libcrux. HMAC
  (`libcrux_hmac.hmac`) is `opaque`, with an axiom for its output size.
- The `opaque` list in `Cargo.toml` keeps `spqr::kdf::hkdf_to_slice` and the state encoding
  without a body. The `exclude` list drops the `log` crate, the prost code and the SIMD field
  multiplication `spqr::encoding::gf::accelerated`.
- `translation-patches/` changes 26 Rust functions before extraction. For example,
  `gf-mul2_u16.patch` removes the SIMD branch. On a CPU with `pclmulqdq` or `aes` (aarch64),
  the binary runs that branch, and the Lean code never sees it.
- The Rust compiler, the standard library and libcrux itself are trusted.

The monitor reads the keys, ciphertexts, chunks and MACs that the binary computed. On each
recorded run it checks three things that the proofs assume or cannot see:

- For each party, the tables built from the log are consistent, so one total `P` extends them.
  So each external function returned the same output for the same arguments, as far as the
  tables record them, as the Lean models assume when they make it a function. Calls of the two
  parties are checked separately.
- Each logged step, with the logged primitive values, is the model's step: the same message,
  key, state name and epoch. A change in the code, in a patch or in an untranslated branch
  shows up only if it changes one of these observations or a logged primitive call.
- When both parties log a key for an epoch, the keys are equal. A wrong primitive result that
  both parties compute in the same way gives equal wrong keys, which this check does not see.

The decoder results and the parity chunks are taken from the log, not recomputed: the erasure
code is trusted. The monitor does not check that a primitive meets its specification, for
example that libcrux computes FIPS 203. It checks only the recorded steps, and only values that
reach a logged call.

Scope: the monitor observes the chunked `States` machine as the orchestrator tests drive it
(`src/test/v1_impls.rs`). It does not observe the public API in `src/lib.rs`, the `chain.rs`
layer, or the state serialization. It checks test executions, not a deployed client.

## 3. Setup

- Rust: `cargo +1.99.1`. The default stable toolchain does not compile `std::assert_matches` in
  `src/lib.rs`.
- `protoc`, the Protocol Buffers compiler. `build.rs` runs it through `prost_build`.
- Lean: the toolchain in `lean-toolchain`. Build the theorems, the refinement proof that the
  monad change touches, and the monitor:

  ```bash
  lake build Spqr.Specs.Braid.StateMachine.Monitor Spqr.Specs.Braid.StateMachine.Refinement Monitor
  ```

- If several checkouts share one cargo target directory (for example through
  `~/.cargo/config.toml`), set `CARGO_TARGET_DIR` per checkout. Two runs that share a target
  directory can run each other's test binaries.

With the feature `monitor` off, the instrumentation compiles to nothing. To make sure that the
code that Charon extracts does not change, compare the expanded crate with the base commit
`acd6e308`:

```bash
git worktree add /tmp/spqr-base acd6e308
cargo +nightly-2025-09-24 rustc --lib --quiet -- -Zunpretty=expanded > /tmp/expanded-branch.rs
(cd /tmp/spqr-base && CARGO_TARGET_DIR=/tmp/spqr-base-target \
  cargo +nightly-2025-09-24 rustc --lib --quiet -- -Zunpretty=expanded) > /tmp/expanded-base.rs
diff /tmp/expanded-base.rs /tmp/expanded-branch.rs && echo identical
```

To make sure that the 26 translation patches still apply (needs Node.js):

```bash
npm ci
npm run patches-check
```

## 4. Run the monitor on the unmodified code

```bash
cargo +1.99.1 test
rm -rf /tmp/spqr-traces
SPQR_MONITOR_DIR=/tmp/spqr-traces cargo +1.99.1 test --features monitor
lake env lean --run Monitor/Main.lean /tmp/spqr-traces/*.jsonl
```

The `rm` removes the traces of earlier runs, which the monitor would also read. The feature run
writes one JSONL file per test thread that drives the instrumented SPQR `States` machine through
the test harness. The monitor prints one line per party (`ACCEPTED`, or `REJECTED` with the
reason and, when there is one, the operation) and one line per cross-party check. When an epoch
has a key from one party only, a further line lists those epochs. It ends with
`ALL CHECKS PASSED` (exit 0) or `SOME CHECKS FAILED` (exit 1). A file that does not parse stops
the program with an error and no verdict.
The interpreted run takes about 4 minutes for all traces. Run the monitor under a memory cap if
the machine has little memory.

Result on the branch (2026-11-21): `cargo test` 57 passed, the feature run 59 passed, 13
traces (the eleven standard tests and the two tamper tests), 18 sessions. The monitor accepts all
36 parties, and every cross-party check passes. In most sessions (15 of 18 in this run), the last
epoch has a key from one party only, because the test stops in the middle of an epoch. The report
lists that epoch as incomplete.

The standard tests draw their randomness from `OsRng`, so their traces, the operation numbers
in the report and the count of incomplete epochs change from run to run. The two tamper tests
use a fixed seed, so their traces are the same in every run.

## 5. Reproduce the mutant results

Each file in `mutants/` is a small change to `src/`. `scripts/monitor-mutants.sh` copies the
committed tree, applies one patch, runs both test commands with a separate target directory, and
runs the monitor on the new traces:

```bash
O=$(mktemp -d)
scripts/monitor-mutants.sh "$O"
```

The script refuses an output directory that already has a case, so each run uses a new one.
Sections 7 and 8 read the same `$O`. A run takes about 6 minutes per patch. The script runs the
monitor under `systemd-run --user --scope -p MemoryMax=16G` when `systemd-run` exists, and stops
before the tests if that command fails. To run the monitor without the cap, set
`SPQR_MONITOR_MEMCAP=0`. `$O/summary.txt` has one line per patch, and `$O/<name>/report.txt` has
the full monitor report. To count the rejected parties of the standard and the tamper traces in
one report:

```bash
awk '/^[^ ].*\.jsonl: /{t=($0~/tamper/)?"tamper":"standard"} / party [AB]: REJECTED/{r[t]++}
  / party [AB]: /{n[t]++} END{for(k in n) print k ": " r[k]+0 "/" n[k] " parties rejected"}' \
  "$O/r4-verify-result-dropped/report.txt"
```

Result on the branch (2026-11-21). "Standard" is the eleven standard traces (22 parties).
"Tamper" is the two tamper traces. A tamper test that fails stops early, so its trace has fewer
sessions.

| Patch | `cargo test` | Feature run | Standard: rejected | Tamper: rejected / parties | Failed cross-party checks |
|-------|--------------|-------------|--------------------|----------------------------|---------------------------|
| M1 `m1-skip-verify-ct` | 57 passed | both tamper tests fail | 22/22 | 2/6 | key agreement (tamper) |
| M2 `m2-skip-verify-hdr` | 57 passed | both tamper tests fail | 22/22 | 3/4 | none |
| M5 `m5-keygen-randomness-fixed` | 57 passed | 59 passed | 0/22 | 0/14 | randomness reuse, 12 sessions |
| M6 `m6-header-mac-label` | 57 passed | 59 passed | 22/22 | 14/14 | none |
| R1 `r1-mac-root-key` | 57 passed | 59 passed | 22/22 | 8/14 | none |
| R2 `r2-mac-le-epoch` | 57 passed | 59 passed | 22/22 | 8/14 | none |
| R3 `r3-mac-ct2-only` | 57 passed | 59 passed | 22/22 | 8/14 | none |
| R4 `r4-verify-result-dropped` | 57 passed | both tamper tests fail | 0/22 | 2/6 | key agreement (tamper) |

The tamper tests exist only with the feature `monitor`. A chunk that does not complete its
decoder is accepted by every version of the code, because the MAC is checked only when the
decoder completes. In the reported runs, when M1 or R4 accepts a ciphertext that was decoded
from a tampered chunk, the two parties derive different keys, and the test's own key check fails
(`src/test/orchestrator.rs:76`). A change in the MAC tag alone leaves the keys equal, so the key
check does not see it; the monitor's replay still rejects the accepted receive. When M2 accepts a header that was decoded from a tampered
chunk, a later receive returns `ErroneousDataReceived`, and both tamper tests fail.

For R4 the monitor rejects the step where the decoder completes. In `tamper_chaos`, the tampered
chunk completes the decoder: "operation 546 (line 636), `States::recv` in `ekSentCt1Received`
epoch 1, message epoch 1 ct2 #17: the model's Receive() fails, the code accepted". In session 2
of `tamper_early`, party A receives a tampered chunk at operation 176 and the monitor rejects
operation 192, where the decoder completes. In session 1 of `tamper_early`, the tampered chunk is
a header chunk, which R4 does not change, and the monitor accepts both parties.

The "Standard" column was the same in each of our runs. A run finds a mutant only if it
reaches the changed step, and the standard tests do not force that. The rejected operations in
the standard traces change from run to run (section 4).

## 6. What the results do not show

- R1, R2 and R3 are deviations from the specification, not attacks. For example, R2 encodes the
  epoch little-endian, which is still a one-to-one encoding. A known-answer test of `mac_ct`
  also catches R1 and R2. R3 leaves `mac_ct` unchanged and changes its callers, so a test
  catches it only if it runs `send_ct2` or `recv_ct2` and checks a result that depends on the MAC
  input, for example the emitted tag.
- The monitor supports chunk numbers below 65536 per encoder, because the code passes the chunk
  number to `chunk_at` as a `u16`. A later chunk rejects the party.
- An acceptance covers only the steps in the log. A log has no end marker, so a log that stops
  early, at an operation boundary, passes if every check on the recorded data passes. Code
  paths that no test reaches are not checked.
- The monitor reports the first step that the model cannot explain. When it can, it names the
  missing primitive value; otherwise it names the candidates or the step. It does not name the
  cause: a missing HMAC value can mean a wrong key, a wrong epoch encoding or missing bytes.

## 7. Compare with the UPPAAL and Veil replays

`scripts/viz-compare.sh` replays session 1 of four mutant traces, and of the honest `chaos`
trace, in the UPPAAL model and in the Veil model. It prints one row per party with the operation
where the Lean monitor and UPPAAL reject, and one row per case for Veil, which replays both
parties together (party column `AB`): the first rejection in trace order, or
"windows satisfiable". It reads the
output directory of section 5.

Prerequisites:

- UPPAAL `verifyta` (tested with 5.1.0-beta5), with a working license. Set `VERIFYTA` to its
  path. To make sure that the license works, run one query, for example
  `python3 -I scripts/uppaal/spqr_uppaal.py check "$O/honest/traces/v1.test.chaos.jsonl" --party A
  --max-ops 100`.
- For the Veil column, a built Veil checkout (tested with https://github.com/verse-lab/veil at
  commit `4624379`; see `viz/veil/README.md`). Set `VEIL_DIR` to it. Veil runs Lean under
  `systemd-run --user --scope`, so it needs a user systemd session. Without `VEIL_DIR`, the
  script runs UPPAAL only.

```bash
VERIFYTA=/opt/uppaal/lib/app/bin/verifyta VEIL_DIR=~/veil scripts/viz-compare.sh "$O"
```

UPPAAL takes a few seconds. Veil takes about 30 minutes.

Both replays check a prefix of the session, not the whole session. UPPAAL replays one party up
to 50 operations past the Lean rejection; a party that Lean accepts gets the bound of the other
party, and the honest trace gets the largest bound (operations 1 to 1176 of 85,228). Veil
replays both parties up to the first compressed step at or after the first Lean rejection and
two more steps; the honest trace gets the largest bound (153 of 25,762 steps). Veil checks the prefix in windows of 12 steps. Each window
starts from a state that `trace2veil.py` reads from the log, so a Veil acceptance means that
each window is satisfiable from its logged start state, not that one model run covers the
prefix. A full session is out of reach: UPPAAL did not finish one
honest party in 6 minutes, and Veil needs about 35 seconds per query of 12 steps.

Result on the branch (2026-11-21). The operation numbers of the `chaos` cases come from the run
of section 5 and change from run to run. In the UPPAAL column, "prefix accepted" means that the
checked prefix is a run of the model. In the Veil column, "windows satisfiable" means that each
window of the checked prefix is satisfiable.

| Mutant, trace | Party | Lean monitor (whole session) | UPPAAL (prefix) | Veil (prefix) |
|---------------|-------|------------------------------|-----------------|---------------|
| M1, `chaos` | A | op 600 | op 600 | op 600 |
| M1, `chaos` | B | op 1126 | op 1126 | not reached |
| R2, `chaos` | A | op 721 | op 721 | not reached |
| R2, `chaos` | B | op 556 | op 556 | op 556 |
| R3, `chaos` | A | op 583 | op 583 | not reached |
| R3, `chaos` | B | op 523 | op 523 | op 523 |
| R4, `tamper_chaos` | A | op 546 | op 546 | windows satisfiable (141 steps) |
| R4, `tamper_chaos` | B | accepted | prefix accepted (596 ops) | windows satisfiable (141 steps) |
| honest, `chaos` | A, B | accepted | prefix accepted (1176 ops) | windows satisfiable (153 steps) |

In these cases, where the Lean monitor rejects, UPPAAL rejects at the same operation. Veil replays both parties
together and stops at the first rejection in trace order, so it reports one party per case
("not reached" for the other). Veil does not find R4: its model sees
whether a MAC is absent, good or bad, but it does not compare the received MAC with the
computed one. UPPAAL finds R4 because its translator compares the two MACs in Python and gives
the model a bad token. Neither model checks the cryptographic values that the Lean monitor
checks, so their agreement on these cases adds no detection power.

## 8. Draw the figures

`scripts/trace-viewer.py` draws one session of a trace from a monitor report. It checks nothing
itself. `scripts/monitor-figures.sh` draws the six trace figures of the slides from the run of
section 5, and writes them to `docs/monitor-slides/fig/`:

```bash
scripts/monitor-figures.sh "$O"
latexmk -lualatex -cd docs/monitor-slides/slides.tex
```

It needs `rsvg-convert`. The deck needs LuaLaTeX with `latexmk`, the Beamer, TikZ and
`fontspec` packages, and the fonts DejaVu Sans, DejaVu Sans Mono, Noto Sans Math and STIX Two
Math. The slide text quotes no operation numbers, so it stays true after a
new run.

The other figure, `uppaal-party.png`, is a screenshot of the `Party` template of
`scripts/uppaal/braid.xml` in the UPPAAL editor.
