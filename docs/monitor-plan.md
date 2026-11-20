# Runtime monitor for SPQR: plan

Status: final plan (draft 4), 2026-11-19. Codex review rounds 1–3 in `docs/monitor-plan-reviews.md`; round 3 found no HIGH or MEDIUM issue.
Branch `claude/spqr-monitor-7f2bcf` (the monitor branch). Local document, never committed.

## 1. Goal and scope

Build a proof-of-concept runtime monitor in the style of SpecMon (ePrint 2026/1979, §2.2–§3)
for the SPQR test harness. The instrumented Rust code writes function-call events. A Lean
program replays each party's events through the executable `BraidModel`
(`Spqr/Specs/Braid/StateMachine/Model.lean`) and accepts or rejects the trace. A demo mutant
shows the value: it passes the full `cargo test` suite, and the monitor rejects its trace.

Scope: the monitor observes the chunked `States` machine as the orchestrator tests drive it
(`src/test/v1_impls.rs`). It does not observe the production API (`lib.rs` `send` / `recv`),
the `chain.rs` layer, or the prost state codec. It is a monitor of test executions, not of a
deployed client.

The paper's Signal model covers PQXDH and the Double Ratchet, not SPQR. This plan does not use
SpecMon or Tamarin (neither is installed, and there is no Tamarin model of SPQR). The checker
is the Lean model that `run_refines` already relates to the extracted code.

## 2. Facts found while planning

- `cargo test` does not compile with the default stable toolchain (1.93.1): upstream
  `src/lib.rs:597` uses the unstable `std::assert_matches`. `cargo +1.99.1 test` compiles and
  passes 57 tests in about 0.4 s. All commands use `cargo +1.99.1`. No file changes for this.
- The orchestrator tests drive `States` directly through `src/test/v1_impls.rs`
  (`Scka::scka_send` / `scka_recv` call `States::send` / `States::recv`), with auth key `b"1"`
  for both parties and `OsRng` randomness. No state serialization is involved.
- The translation patches `states-send.patch` and `states-recv.patch` each cover the whole body
  of `States::send` (lines 115–274) and `States::recv` (275–533) as context, and
  `polynomial-PolyDecoder-decoded_message.patch` covers the body of `decoded_message`. Any edit
  inside those bodies makes the patches fail. Hooks stay out of them (section 4).
- Charon runs `cargo` with `--locked` and no features (`aeneas-config.yml`). A new feature with
  no new dependency does not change `Cargo.lock`. Neither `charon` nor `aeneas` is installed.
- `PolyEncoder` is systematic with contiguous chunks: `encode_bytes_base` puts 2-byte word `w`
  of the message at position `w / 16` of polynomial `w % 16`, and `chunk_at(idx)` reads
  position `idx` of polynomials `0..16`, that is words `16·idx .. 16·idx + 15`, the bytes
  `[32·idx, 32·idx + 32)`. This holds while `idx < |m| / 32`; the message sizes here (96, 1152,
  960, 160) are multiples of 32. Later indices are parity chunks, computed by interpolation.
- Mutant screening in a scratch copy of the crate, full `cargo +1.99.1 test`:

  | Mutant | Change | `cargo test` |
  |--------|--------|--------------|
  | M1 skip `verify_ct` | `send_ek.rs:160`, call removed | passes |
  | M2 skip `verify_hdr` | `send_ct.rs:107`, call removed | passes |
  | M3 `KDF_OK` epoch + 1, both sides | `send_ct.rs:131`, `send_ek.rs:152` | fails (`regression_test_libcrux_issue_1275_from_generated_states`) |
  | M4 emitted key epoch + 1 | `send_ct.rs:143` | fails (6 tests) |
  | M5 KeyGen randomness fixed (all zero) | `incremental_mlkem768.rs:37` | passes |
  | M6 header MAC label `:ekheader` → `:ciphertext` | `authenticator.rs:93` | passes |

  M1 is the demo mutant: it is the SPQR form of the paper's skipped signature check
  (goto-fail, §6.2). M2 and M6 are secondary demos. M5 is outside `BraidModel` (section 5.7).

## 3. Event format

One JSON object per line, in the shape `⟨f(args), ret⟩` of the paper:

```json
{"s":1,"p":"A","op":7,"f":"hmac","args":["<key hex>","<data hex>"],"ret":"<tag hex>"}
```

`s` is a session number (one orchestrator run), `p` the party (`A` or `B`), `op` the operation
number. Bytes are lowercase hex. One file holds both parties of a session, in execution order
(both run on the test thread). Operations: the test harness starts operation `n + 1` of a
session just before it calls `States::send` or `States::recv`; every event emitted during the
call carries that number, and the call ends with exactly one terminal event (`States::send` or
`States::recv`) with the same number. Operation 0 of each party is its initialization (the
`init` event and the HKDF call of `Authenticator::new`). The monitor rejects a trace in which an
operation has no terminal event, two terminal events, events after its terminal event, or
events of two parties.

| `f` | `args` | `ret` | Hook |
|-----|--------|-------|------|
| `init` | `[role, auth_key]` | `null` | `States::init_a` / `init_b` (pre-trace) |
| `hkdf` | `[salt, ikm, info, len]` | `okm` | `kdf::hkdf_to_slice` |
| `hmac` | `[key, data]` | `tag` | `authenticator.rs` (the `hmac` import) |
| `mlkem.generate` | `[seed]` | `[dk, hdr, ek]` | `incremental_mlkem768::generate` |
| `mlkem.encaps1` | `[hdr, randomness]` | `[es, ct1, ss]` | `incremental_mlkem768::encaps1` |
| `mlkem.encaps2` | `[ek, es]` | `ct2` | `incremental_mlkem768::encaps2` |
| `mlkem.decaps` | `[dk, ct1, ct2]` | `ss` | `incremental_mlkem768::decaps` |
| `mlkem.ek_matches_header` | `[ek, hdr]` | `bool` | `incremental_mlkem768::ek_matches_header` |
| `decoder.message` | `[pts_needed]` | `bytes` or `null` | the five `decoded_message()` call sites in `v1/chunked/send_ek.rs` and `send_ct.rs` |
| `States::send` | `[state, epoch]` | `{state, epoch, msg, key}` or `{err}` | `v1_impls.rs` `scka_send` |
| `States::recv` | `[state, epoch, msg]` | `{state, epoch, key}` or `{err}` | `v1_impls.rs` `scka_recv` |

`seed` and `randomness` are the local arrays that `generate` and `encaps1` fill from the RNG
(`incremental_mlkem768.rs:34`, `:51`), read after `fill_bytes`. `msg` is
`{epoch, kind, index, data}` with `kind` one of `none`, `hdr`, `ek`, `ekct1ack`, `ct1ack`,
`ct1ackfalse`, `ct1`, `ct2` (`index`, `data` only for chunk kinds). `key` is `null` or
`{epoch, secret}`. `state` is the `States` variant name.

The `init` event is the pre-trace of §3.3 of the paper: the role and the shared auth key from
which `InitAlice` / `InitBob` start.

The trace holds key material and KEM randomness in clear. The harness draws them from `OsRng`
for a test run only, with auth key `b"1"`, so they protect nothing. The party is set only from
`#[cfg(test)]` code, so a non-test build with the feature on writes nothing. The feature must
not be enabled in a production build; the plan does not add redaction.

## 4. Rust instrumentation (monitor branch only)

### 4.1 Feature and sink

- `Cargo.toml`: `[features] monitor = []`. No new dependency.
- New module `src/monitor.rs`, declared in `src/lib.rs` as
  `#[cfg(feature = "monitor")] pub(crate) mod monitor;`. It has a hand-written JSON writer
  (hex strings, no serde), a thread-local sink, and the event functions. The functions that
  only the test harness calls (session, party, operation, step events, the `States` name and
  epoch helper) are `#[cfg(test)]`.
- The sink writes only when `SPQR_MONITOR_DIR` is set and the thread has a party set. The
  orchestrator sets it: `OrchestratorBase::new` starts a session and sets `A` before
  `K::init_a` and `B` before `K::init_b`; `send` and `receive_*` set the party from `is_alex`;
  `Drop` ends the session and flushes. Tests that do not use the orchestrator write nothing.
- File: `$SPQR_MONITOR_DIR/<thread name>.jsonl`, created on the first event. The test harness
  names each test thread after its test.

### 4.2 Hook sites

All hooks are `#[cfg(feature = "monitor")]` statements or a `#[cfg]`-switched `use` line.

- `src/authenticator.rs`: `use libcrux_hmac::hmac;` gets `#[cfg(not(feature = "monitor"))]`;
  `#[cfg(feature = "monitor")] use crate::monitor::hmac;` imports a wrapper with the same
  signature that calls libcrux and logs. No function body changes.
- `src/kdf.rs`: one cfg statement at the end of `hkdf_to_slice` (opaque to Charon).
- `src/incremental_mlkem768.rs`: one cfg statement in each of `generate`, `encaps1`, `encaps2`,
  before the return expression. `encaps2` logs its `es` argument as given, before the libcrux
  issue 1275 fix-up, because `CodeAgrees.encaps2` relates the model to the function's argument.
  In `decaps` and `ek_matches_header`, a cfg block computes the libcrux result once, logs it and
  returns it, so the logged value is the returned value; with the feature off the original
  return expression runs. The function gets
  `#[cfg_attr(feature = "monitor", allow(unreachable_code))]`.
- `src/v1/chunked/send_ek.rs` (2 sites), `src/v1/chunked/send_ct.rs` (3 sites): one cfg
  statement before each `if let Some(..) = x.decoded_message()`. It calls `decoded_message()`
  a second time (it takes `&self`) and logs the result with `pts_needed`.
- `src/v1/chunked/states.rs`: one cfg statement at the start of `init_a` and `init_b`
  (lines 58–65, outside the patched hunks).
- `src/test/v1_impls.rs` (test code): operation start before `self.send(rng)` /
  `self.recv(msg)` and the terminal step event after.
- `src/test/orchestrator.rs` (test code): session start, party selection, session end.

The `States` name and epoch helper lives in `src/monitor.rs`: the state types are `pub(crate)`
and each has a `pub fn epoch()`, so a crate module can match on `States` and call them.

The step hook sits in the test harness, at the `States::send` / `States::recv` boundary, not in
the arms: the arms are inside the patched hunks, and the boundary sees the same data (the state
before, the message, and the state, message and key after).

### 4.3 Extraction compatibility

This is a hypothesis with two checks, not a rerun of the extraction:

1. Every translation patch applies on the monitor branch: `git apply --check` for each file in
   `translation-patches/`, alone, on the clean tree (what `npm run patches-check` does first).
2. With the feature off, the expanded crate is the same as on `main`: run
   `cargo +nightly-2025-09-24 rustc --lib -- -Zunpretty=expanded` on both trees and diff. The
   expanded output is after cfg stripping, so an empty diff shows that the compiler front end,
   and therefore Charon, gets the same items. Spans and line numbers still differ, so a future
   extraction changes the `Source:` comments in `SrcTranslated/` and the spans in
   `translation.json`.

The instrumentation stays on the monitor branch and out of any PR: `src/` is under the code
freeze in `CLAUDE.md`. The user rules on it.

## 5. Lean monitor

### 5.1 Layout

- `Spqr/Specs/Braid/StateMachine/PartialModel.lean` (partial primitives, partial model, their
  soundness) and `Spqr/Specs/Braid/StateMachine/Monitor.lean` (the checker and its theorems),
  both in `Spqr` and re-exported from `Spqr.lean`. Pure: no IO,
  no JSON, no tables.
- `Monitor/` (new `lean_lib Monitor` and `lean_exe spqr-monitor` in `lakefile.toml`): trace
  reader, tables, learning pass, cross-party checks, CLI.
- Run as `lake exe spqr-monitor <trace.jsonl>...`. If the native build of the executable is too
  slow (it compiles the Mathlib C code that Aeneas imports), the fallback is
  `lake env lean --run Monitor/Main.lean <trace.jsonl>...`.

### 5.2 Partial primitives

`OPrims Enc Dec Chunk` has the fields of `Prims`, with an `Option` result for each primitive
that the monitor only knows from observed calls: `nextChunk`, `message`, `keyGen`, `encaps1`,
`encaps2`, `decaps`, `ekMatches`, `mac`, `kdfAuth`, `kdfOk`. The others (`encode`,
`decoderNew`, `addChunk`, the sizes, `protocolInfo`, `toBytes`) stay total.

`Agrees P Q` (for `P : Prims`, `Q : OPrims`): the total fields are equal, and every `Option`
field of `Q` that returns `some v` on an argument gives `v` in `P` on that argument.

`sendO`, `receiveEqO`, `receiveO`, `initAliceO`, `initBobO` are `send`, `receiveEq`, `receive`,
`initAlice`, `initBob` written in the `Option` monad over `Q`: `none` means that the step needs
a primitive value that `Q` does not have. The theorems relate them to the model:

- `sendO_sound : sendO Q σ r = some x → Agrees P Q → send P σ r = x`, and the same for
  `receiveO`, `initAliceO`, `initBobO`.

### 5.3 The checker and its theorems

Each observation is checked with its own partial primitives: `Q_i` is built from the events of
operation `i` only. A step can therefore use only primitive values that the code computed during
the same `States` call. A value computed in another call, for example a MAC computed earlier and
cached, does not count. This scoping fits the code as it is: every primitive value a transition
of the model needs is computed by the code within the same call (transition (1): `generate`,
`mac_hdr`; (5): `decaps`, HKDF, `update`, `verify_ct`; (6): `verify_hdr`; (7): `encaps1`, HKDF,
`update`; (9), (11), (12): `ek_matches_header`, `encaps2`, `mac_ct`; initialization: the HKDF of
`Authenticator::new`). The order of calls within one operation is not checked.

```lean
inductive Obs (Chunk : Type) where
  | send (r : Bytes) (m : Msg Chunk) (k : Option Key) (l : Label) (e : Nat)
  | recvOk (m : Msg Chunk) (k : Option Key) (l : Label) (e : Nat)
  | recvErr (m : Msg Chunk)
```

A `States::send` step event with `{err}` is rejected as unsupported: every arm of `States::send`
returns `Ok`, and `Obs` has no failed send. `checkStep Q σ` on `send r m k l e` requires `sendO Q σ r = some (σ', m, k)` with `σ'` named
`l` at epoch `e`. On `recvOk m k l e` it requires `receiveO Q σ m = some (some (σ', k))` with
`σ'` named `l` at epoch `e`. On `recvErr m` it requires `receiveO Q σ m = some none` and keeps
`σ`. A missing primitive value is `none` at the outer level: a rejection, never a default.
`checkRun σ steps` folds `checkStep` over a list of pairs `(Q_i, obs_i)`. `Explains P σ obs σ'`
is an inductive relation that states these facts with `send P` / `receive P`.

1. `checkRun_sound : (∀ q ∈ steps, Agrees P q.1) → checkRun σ steps = some σ' →
   Explains P σ (steps.map (·.2)) σ'`.
2. `Explains.run : Explains P σ obs σ' → Run P σ σ' (obsKeys obs)`.
3. `accepted_alice : initAliceO Q₀ ss = some σ₀ → checkRun σ₀ steps = some σ' → ∀ P,
   Agrees P Q₀ → (∀ q ∈ steps, Agrees P q.1) → Explains P (initAlice P ss) obs σ' ∧
   Run P (initAlice P ss) σ' (obsKeys obs)` with `obs = steps.map (·.2)`, and `accepted_bob`.

Theorem 3 holds for every total `P` that agrees with all the operation tables, in particular for
any `P` that coincides with the real primitives on the logged calls. The run does not depend on
values the code never computed: each value a step uses was logged in that step's operation. Proofs: case splits on
the state and payload, `Option.bind_eq_some_iff`, `simp only` with the definitions. No
`maxHeartbeats` change, no axiom; `#print axioms` must show only `propext`,
`Classical.choice`, `Quot.sound`.

### 5.4 Concrete representation

- `Chunk := MChunk` = `{ index : Nat, data : Bytes }`.
- `Enc := Bytes × Nat` (message, chunks emitted). `encode m = (m, 0)`. `nextChunk (m, i)`: for
  `i < |m| / 32` the systematic chunk `⟨i, m[32i, 32i+32)⟩` (section 2), computed; for larger
  `i` a parity chunk from the parity table (section 5.5).
- `Dec := Nat × List MChunk`: the decoder's size and history, the chunks added in order.
  `decoderNew n = (n, [])`, `addChunk (n, cs) c = (n, cs ++ [c])`, `message` from the decoder
  table. The history is not the `PolyDecoder` state; it is an index for it. The code's decoder
  after `new(n)` and a sequence of `add_chunk` calls is a function of `n` and that sequence, so
  `message` is a well-defined partial function of the history. The monitor does not decode:
  the decoder's result is a logged primitive output, like an HMAC tag.
- `keyGen`, `encaps1`, `encaps2`, `decaps`, `ekMatches`, `mac`: tables keyed by the arguments,
  filled from the party's own crypto events. `encaps2 es hdr ek` ignores `hdr` (the code's
  `encaps2` has no `hdr` argument; `CodeAgrees.encaps2` quantifies over it).
- `kdfAuth rk k e` is the `hkdf` table at `(0^32, rk ++ k, updateLabel ++ be64 e, 64)` and
  `kdfOk ss e` at `(0^32, ss, sckaKeyLabel ++ be64 e, 32)`: the salt, key layout and info of
  `CodeAgrees.kdfAuth` / `kdfOk`.
- `protocolInfo = ascii "Signal_PQCKA_V1_MLKEM768"`, `toBytes e = be64 e`, sizes 64, 1152,
  960, 128, 32: the values `CodeAgrees` fixes.

Tables are per operation of one party (section 5.3): an entry comes only from that party's calls
during that `States` call. A skipped check is therefore a missing entry: if party A does not
compute the MAC that `Receive()` compares in transition (5), `receiveO` is `none` and the step is
rejected.

### 5.5 Learning pass (untrusted)

`Monitor/Check.lean` builds one table per operation of one party:

1. The crypto events of the operation go into its table, keyed by their arguments. A key seen
   twice with different results, in one operation or in two operations of the party, is a
   rejection ("the primitive is not a function"); otherwise no single `P` agrees with all
   operation tables.
2. The randomness `r` of a `send` observation is the seed of the `mlkem.generate` event, or the
   randomness of the `mlkem.encaps1` event, of the same operation; otherwise `[]`. Two such
   events in one operation are a rejection.
3. A replay with the operation tables gives the model state before each operation. From it the
   pass reads the decoder that `receiveEq` adds the chunk to and records
   `message (n, cs ++ [c]) :=` the operation's `decoder.message` result, after checking
   `n = 2 · pts_needed`. An operation with more than one `decoder.message` event is a
   rejection.
4. For a send from an encoder `(m, i)` with `i ≥ |m| / 32` it records the observed chunk as
   `nextChunk (m, i)`. Parity chunks are the one value the monitor takes from the event it then
   compares with: they are trusted codec outputs (section 7).

The checked pass runs `checkRun` with the operation tables. The learning pass is not trusted:
whatever tables it builds, an acceptance means theorem 3 holds for them.

### 5.6 Cross-party checks (untrusted)

Per session, in file order (the execution order):

- Delivery: each `States::recv` of a party consumes one earlier `States::send` message of the
  other party that is equal to it and not yet consumed (a multiset). A receive with no such
  message is a failure. Sent messages that are never received are expected (the tests drop
  messages and end with full queues).
- Keys: a party that emits two keys for one epoch fails. For each epoch where both parties
  emitted a key, the secrets must be equal; otherwise a failure. An epoch where only one party
  emitted a key by the end of the trace is reported as incomplete, not as a failure.

These checks bind the two local replays to one session. They are not covered by the theorems.

### 5.7 Freshness (extension, not part of `BraidModel`)

`BraidModel.send` takes any `r`, so reused randomness is a model run. As in SpecMon, where `Fr`
facts are monitored through randomness generation, the monitor checks that the `generate`
seeds and `encaps1` randomness of a session are pairwise distinct. Distinct byte strings are not
freshness in the symbolic or computational sense; the check only catches reuse. It is reported
apart and not covered by the theorems.

### 5.8 Report

For each `(session, party)`: accepted, or the first rejected operation with its number, the
model state, the observation, and the reason: a missing primitive value (which table and
key), a model step that differs (layer 1: state name, epoch, payload kind, key epoch; layer 2:
chunk bytes, key bytes), a trace format error, or a learning-pass conflict. Then the
cross-party and freshness results. The exit code is 0 only if every check passes.

## 6. Trace generation and demo

1. `SPQR_MONITOR_DIR=<dir> cargo +1.99.1 test --features monitor` runs the whole suite and
   writes one file per test that drives `States` through the orchestrator: the six tests of
   `v1::test` (`chaos`, `random_balanced_out_of_order`, `random_balanced`, `balanced_healing`,
   `random_slow_alex_healing_auth_bidir`, `onlineoffline_healing_unidir`) and the five of
   `test::messaging_scka::test`. All eleven traces are part of the acceptance claim.
2. `lake exe spqr-monitor <dir>/*.jsonl` accepts every party of every trace. If a trace is too
   large to check in reasonable time, the report says so and checks a chronological prefix of
   it; that is partial coverage of that test, not acceptance of the whole run.
3. Mutant branch `claude/spqr-monitor-mutant-skip-verify-ct`, cut from the monitor branch, one
   commit: M1. `cargo +1.99.1 test` passes (57 tests). The monitor rejects the `chaos` and
   `random_balanced_out_of_order` traces at party A's first transition (5) with "missing `mac`".
4. M2 and M6 in the scratch copy (no branch): record the monitor result. M5: record that the
   model replay accepts and the freshness check rejects.
5. `docs/monitor-demo.md` records the commands, the test summaries and the monitor reports.

## 7. What the monitor checks that `run_refines` does not

`run_refines` proves, for the extracted Lean code, that every successful run refines
`BraidModel` under any `P` with `CodeAgrees P`. Its trusted base: the Aeneas translation of the
patched Rust source (`translation-patches/`), the opaque functions (libcrux `hmac`,
`hkdf_to_slice`, the prost codec; the libcrux ML-KEM functions are FIPS 203 models), and the
hand-written axioms (`hkdf_to_slice_spec`, `hmac_sha256_tag32_spec`, `encode_state_pb_spec`,
`decode_state_pb_total`, `alloc.fmt.format_spec`,
`potentially_fix_state_incorrectly_encoded_by_libcrux_issue_1275_spec`).

The monitor makes these checks on the compiled binary, for the executed paths only:

- The control flow and data flow of the compiled Rust, without the Aeneas translation or the
  translation patches in between.
- How the code calls the primitives: with the salt, key layout and info of `CodeAgrees.kdfAuth`
  / `kdfOk`, the MAC input `PROTOCOL_INFO ‖ label ‖ be64(epoch) ‖ data` under the current MAC
  key, and `encaps2`, `decaps`, `ek_matches_header` on the values the model holds. A call with
  other inputs is a missing entry or a different output, so a rejection (M6).
- That the code performs each primitive evaluation the model needs, per party (M1, M2).
- Code that changed after the last extraction: a mutant compiles and passes the tests, while
  `run_refines` still holds for the old `SrcTranslated/`. The monitor needs no re-extraction.

It does not check: that `P` satisfies `CodeAgrees` (the primitives' own behavior is taken from
the log: a wrong HMAC that both parties share is accepted), the erasure code (decoder results
and parity chunks are logged outputs), unexecuted paths, `lib.rs`, `chain.rs`, the prost codec,
and anything the instrumentation fails to log. The instrumentation and the trace reader are
trusted, as in the paper (§3, "trusted event extraction").

## 8. What an acceptance means

For one party: there is a run of `BraidModel` from `InitAlice` or `InitBob` with the logged
auth key, under every primitive interpretation `P` that agrees with the party's logged calls,
whose steps produce exactly the logged messages, keys, state names and epochs (theorem 3).
Every primitive value the replay used was logged. The learning pass, the cross-party checks, the
freshness check, the JSON reader and the instrumentation are not verified.

## 9. Open questions

- The user rules on whether any `src/` instrumentation leaves the monitor branch.
- Whether libsignal 0.87.1 (the paper's version) runs SPQR is not checked.
- Instrumenting `lib.rs` `send` / `recv` would cover the prost state codec, which `run_refines`
  does not cover (a state restored from bytes). It needs hooks next to the `lib-send.patch` /
  `lib-recv.patch` hunks.

## 10. Implementation state (2026-11-19)

- Monitor branch `claude/spqr-monitor-7f2bcf`: `aa52318` (monitor), `1c7bcc6` (docstrings),
  `152b3d3` (one party per operation), `957f33f` (code round 1 fixes), `5fcd212` (code round 2
  fixes). `lake build Spqr` and the linter pass; `accepted_alice` / `accepted_bob` use only
  `propext`, `Classical.choice`, `Quot.sound`.
- Mutant branch `claude/spqr-monitor-mutant-skip-verify-ct`: `2ea76f0` on `aa52318`.
- Demo done: `docs/monitor-demo.md`. Rechecked on `5fcd212`: honest traces 22/22 parties
  accepted, M1 traces 22/22 rejected at transition (5).
- Plan review loop closed (round 3: no HIGH or MEDIUM).
- Code review loop closed: Codex rounds 1 and 2 (6 findings, fixed); round 3 by a Claude
  reviewer because Codex hit its usage limit: no HIGH or MEDIUM, 5 LOW fixed in `790ca27`.
