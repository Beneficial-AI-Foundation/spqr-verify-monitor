# Runtime monitor demo

Date: 2026-11-19. Plan: `docs/monitor-plan.md`. Run log of the development sessions. Branch names and `/tmp` paths refer to that time; to reproduce the results, follow `docs/monitor.md`.

Branches:

- `claude/spqr-monitor-7f2bcf` (monitor branch), commit `aa52318` and later review fixes.
- `claude/spqr-monitor-mutant-skip-verify-ct` (mutant branch), cut from `aa52318`, one commit
  `2ea76f0` that removes the `verify_ct` call in `src/v1/unchunked/send_ek.rs` (M1).

All Rust commands use `cargo +1.99.1`: the default stable toolchain (1.93.1) does not compile
upstream's `std::assert_matches` in `src/lib.rs`. The monitor runs interpreted
(`lake env lean --run Monitor/Main.lean`). The native `lake exe spqr-monitor` was not built: it
compiles the Mathlib C code that Aeneas imports into `.lake/packages`, which this worktree shares
with the main checkout. The interpreted run takes about 2 minutes for all eleven traces.

## 1. Extraction compatibility (monitor branch, feature off)

Every translation patch applies on its own and all apply together:

```
for p in translation-patches/*.patch; do git apply --check "$p"; done   # 26 ok
git apply --check translation-patches/*.patch                            # ok
```

The expanded crate with the feature off is the same as on `main` (`acd6e30`):

```
cargo +nightly-2025-09-24 rustc --lib --quiet -- -Zunpretty=expanded > /tmp/spqr-expanded-monitor.rs
# same in a `git archive acd6e30` copy -> /tmp/spqr-expanded-main.rs
diff /tmp/spqr-expanded-main.rs /tmp/spqr-expanded-monitor.rs | wc -l   # 0 (11164 lines each)
```

## 2. Unmutated code: accepted

```
cargo +1.99.1 test                                              # 57 passed
SPQR_MONITOR_DIR=/tmp/spqr-traces cargo +1.99.1 test --features monitor   # 57 passed, 11 traces
lake env lean --run Monitor/Main.lean /tmp/spqr-traces/*.jsonl  # exit 0, ALL CHECKS PASSED
```

| Trace | Events | Party A | Party B |
|-------|--------|---------|---------|
| `test.messaging_scka.test.onlineoffline_healing` | 76671 | 28084 ops, 242 keys | 28078 ops, 241 keys |
| `test.messaging_scka.test.pingpong_healing` | 22931 | 9803 ops, 40 keys | 9800 ops, 39 keys |
| `test.messaging_scka.test.random_balanced_healing` | 14750 | 5090 ops, 54 keys | 5090 ops, 53 keys |
| `test.messaging_scka.test.random_balanced` | 14479 | 5019 ops, 52 keys | 5017 ops, 53 keys |
| `test.messaging_scka.test.random_balanced_out_of_order` | 14440 | 5011 ops, 52 keys | 5011 ops, 51 keys |
| `v1.test.balanced_healing` | 14750 | 5090 ops, 54 keys | 5090 ops, 53 keys |
| `v1.test.chaos` | 96984 | 42637 ops, 136 keys | 42813 ops, 135 keys |
| `v1.test.onlineoffline_healing_unidir` | 75610 | 27604 ops, 240 keys | 27592 ops, 241 keys |
| `v1.test.random_balanced` | 14453 | 5035 ops, 52 keys | 5039 ops, 51 keys |
| `v1.test.random_balanced_out_of_order` | 14665 | 5085 ops, 52 keys | 5085 ops, 53 keys |
| `v1.test.random_slow_alex_healing_auth_bidir` | 13853 | 5115 ops, 42 keys | 5116 ops, 43 keys |

Every party of every trace is accepted. Delivery, key agreement and the randomness reuse check
pass in every session. Each session ends with one epoch whose key only one party emitted (the
test stops mid-epoch); the report lists it as incomplete, not as a failure.

## 3. Mutant M1 (skip `verify_ct`): passes the tests, rejected by the monitor

On `claude/spqr-monitor-mutant-skip-verify-ct`:

```
cargo +1.99.1 test                                                 # 57 passed; 0 failed
SPQR_MONITOR_DIR=/tmp/spqr-traces-m1 cargo +1.99.1 test --features monitor   # 57 passed
lake env lean --run Monitor/Main.lean /tmp/spqr-traces-m1/v1.test.chaos.jsonl \
  /tmp/spqr-traces-m1/v1.test.random_balanced_out_of_order.jsonl   # exit 1
```

Output:

```
/tmp/spqr-traces-m1/v1.test.chaos.jsonl: 96521 events, 1 session(s)
  session 1 party A: REJECTED: operation 623 (line 711), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #6: missing primitive value: no hmac call for the ciphertext MAC (verify_ct)
  session 1 party B: REJECTED: operation 1256 (line 1428), States::recv in BraidModel.Label.ekSentCt1Received epoch 2, message epoch 2 ct2 #10: missing primitive value: no hmac call for the ciphertext MAC (verify_ct)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-m1/v1.test.random_balanced_out_of_order.jsonl: 14338 events, 1 session(s)
  session 1 party A: REJECTED: operation 212 (line 300), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call for the ciphertext MAC (verify_ct)
  session 1 party B: REJECTED: operation 406 (line 578), States::recv in BraidModel.Label.ekSentCt1Received epoch 2, message epoch 2 ct2 #4: missing primitive value: no hmac call for the ciphertext MAC (verify_ct)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
SOME CHECKS FAILED
```

Each party is rejected at its first transition (5), the step that completes the `ct2 ‖ mac`
decoder and emits the epoch key: A in epoch 1, B in epoch 2 (B sends the encapsulation key in
even epochs). The verified checker's `receiveO` needs the MAC of `ct1 ‖ ct2` under the updated
MAC key, and the code computed none during that call.

Over all eleven M1 traces (`lake env lean --run Monitor/Main.lean /tmp/spqr-traces-m1/*.jsonl`),
all 22 parties are rejected with the same reason, each at its first transition (5): party A in
epoch 1, party B in epoch 2.

## 4. Secondary mutants (scratch copy of the monitor branch, no branch)

Script: `/tmp/spqr-mutants2.sh`, log `/tmp/spqr-mutants2.log`. Each mutant passes
`cargo +1.99.1 test` (57 passed) and the feature run (57 passed).

| Mutant | Change | Monitor on `chaos` and `random_balanced_out_of_order` |
|--------|--------|------------------------------------------------------|
| M2 skip `verify_hdr` | `send_ct.rs:107` | both parties rejected at their first transition (6): "no hmac call for the header MAC (verify_hdr)" |
| M5 KeyGen randomness fixed | `incremental_mlkem768.rs:43` (`fill_bytes` removed) | both parties accepted by the model; "randomness reuse (outside BraidModel): FAILED: mlkem.generate reuses randomness of an earlier call" |
| M6 header MAC label `:ciphertext` | `authenticator.rs:96` | A rejected at its first send (transition (1)): "no hmac call for the header MAC"; B rejected at its first transition (6) |

M5 shows the limit of the model check: `BraidModel.send` takes any randomness, so a run with
reused KeyGen randomness is a model run. Only the separate reuse check, which the theorems do not
cover, rejects it.

Screened before the instrumentation (plan §2) and not run through the monitor, because the test
suite already fails on them: M3 (`KDF_OK` epoch + 1) and M4 (emitted key epoch + 1).

## 5. Realistic scenarios (2026-11-19)

M1 (deleting the `verify_ct` call) stays as scenario 0: it shows the mechanism, but no engineer
deletes a check by mistake. The scenarios below are slips a refactor could make. Each changes both
parties the same way, so the parties still agree on keys. Scratch runs: `/tmp/spqr-mutants3.sh`,
log `/tmp/spqr-mutants3.log`, traces `/tmp/spqr-traces-R*/`. Monitor results counted over all
eleven traces (22 parties).

| # | Change | `cargo test` | Monitor |
|---|--------|--------------|---------|
| R1 | `Authenticator::mac_ct` keys the HMAC with `root_key` instead of `mac_key` (copy-paste) | passes (57) | 22/22 rejected |
| R2 | `mac_ct` encodes the epoch with `to_le_bytes` | passes (57) | 22/22 rejected |
| R3 | sender and receiver MAC `ct2` only, not `ct1 ‖ ct2` (`ct1` left out of the MAC input) | passes | 22/22 rejected |
| R4 | `let _ = auth.verify_ct(...)` instead of `...?` (result dropped) | passes | honest traces accepted, tamper tests rejected |
| R5 | `Authenticator::update` encodes the epoch with `to_le_bytes` | fails (regression test with stored states) | not run |

R1 has a branch: `claude/spqr-monitor-mutant-mac-root-key` (`392b552`, on `f56fb87`). Party A is
rejected when it verifies the ciphertext MAC (transition (5)); party B earlier, when it builds the
`ct2` encoder (transitions (9)/(11)). Report line (chaos):

```
party A: REJECTED: operation 609 States::recv in ekSentCt1Received epoch 1, message epoch 1 ct2 #12: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
party B: REJECTED: operation 513 States::recv in ct1Acknowledged epoch 1, message epoch 1 ekct1ack #62: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
```

An ignored verification result changes nothing in an honest run, so no monitor of honest traces
can see R4. The tampering driver (`src/test/orchestrator/tamper.rs`) gives the adversarial input.
It changes some `ct2` / `hdr` chunks in transit, tolerates the expected `recv` errors, and logs a
`tamper` event `[orig, copy]` for each change. The delivery check accepts a received message if it
is a logged tampered copy of a sent message. With R4 applied, the model's `Receive()` fails
(`receiveO = some none`) on a tampered chunk, but the code accepts it, so the checker rejects the
step. The patch is `mutants/r4-verify-result-dropped.patch`.

### R2: little-endian epoch in the ciphertext MAC (branch)

R2 has a branch: `claude/spqr-monitor-mutant-mac-le-epoch` (`6b6d346`, on `f56fb87`). The commit
changes `ep.to_be_bytes()` to `ep.to_le_bytes()` in `Authenticator::mac_ct` only. `verify_ct`
calls `mac_ct`, so the sender and the receiver compute the same wrong MAC.

```
cargo +1.99.1 test                      # 57 passed, 0 failed
rm -rf /tmp/spqr-traces-R2-branch
SPQR_MONITOR_DIR=/tmp/spqr-traces-R2-branch cargo +1.99.1 test --features monitor   # 57 passed, 11 traces
lake env lean --run Monitor/Main.lean /tmp/spqr-traces-R2-branch/*.jsonl            # exit 1, SOME CHECKS FAILED
```

The monitor rejects all 22 parties at the ciphertext MAC. In all 11 traces, party A fails at MAC
verification (transition (5)). Party B fails at the build of the `ct2` encoder: at transition
(11) in 10 traces, and at transition (12) in `v1.test.random_balanced_out_of_order`. Report lines
(chaos, `session 1` prefix removed):

```
party A: REJECTED: operation 660 (line 749), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
party B: REJECTED: operation 456 (line 537), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #81: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
```

The report also prints `key agreement: ok` for every session. That line does not show that the
keys agree: a rejected party contributes no keys, and the check compares two empty lists. A
direct comparison of the `key` fields in the logged `States::send`/`recv` results shows that the
parties agree. In all 11 traces, every epoch that both parties logged has the same secret, and
no party logged an epoch twice.

Fixed on the monitor branch in `94ee49b`: the key agreement check now reads the keys from the logged
step events, for accepted and rejected parties alike. On the R2 traces it prints
`key agreement: ok` for all 11 sessions, now with the logged keys behind it; a trace with one
altered secret fails with "epoch 1: the parties' secrets differ" (`/tmp/spqr-neg-keydiff.jsonl`).

Scope: little-endian is still a one-to-one encoding of the epoch, so R2 does not let an attacker
forge a MAC. R2 shows a mismatch between the code and the specification that the existing test
suite does not catch. A known-answer test of `mac_ct` at an epoch such as 1 catches it as well.
For the same key and ciphertext, a mutant peer and a correct peer use different MAC inputs at
most epochs, for example epoch 1. The inputs are equal at an epoch whose eight bytes read the same
in both directions, for example 0 or `0x0000000101000000`. At those epochs the mutation has no
effect.

### R3: MAC only `ct2` (branch)

R3 has a branch: `claude/spqr-monitor-mutant-mac-ct2-only-aa9798` (`7110d3f`, on `f56fb87`). The
commit changes `auth.mac_ct(epoch, &ct1)` to `&ct2` in `src/v1/unchunked/send_ct.rs` and
`auth.verify_ct(epoch, &ct1, &mac)` to `&ct2` in `src/v1/unchunked/send_ek.rs`. At both places
`ct1` already holds `ct1 ‖ ct2`, so the MAC input now has `ct2` only.

`~/.cargo/config.toml` sets one shared `target-dir` for all worktrees. A first R3 run
(`/tmp/spqr-traces-R3-branch`) ran at the same time as the R2 run, and it logged R2 behavior. Do not
use those traces. The run below uses its own target directory:

```
export CARGO_TARGET_DIR=/tmp/spqr-target-R3
cargo +1.99.1 test                                                                    # 57 passed, 0 failed
SPQR_MONITOR_DIR=/tmp/spqr-traces-R3-isolated cargo +1.99.1 test --features monitor   # 57 passed, 11 traces
python3 -I docs/monitor-tools/check_ct_mac.py /tmp/spqr-traces-R3-isolated            # 2025 ciphertext MACs, all 171 bytes, big-endian epoch
python3 -I docs/monitor-tools/check_suffix.py /tmp/spqr-traces-R3-isolated            # 1013 sender MACs, data is exactly the encaps2 ct2
lake env lean --run Monitor/Main.lean /tmp/spqr-traces-R3-isolated/*.jsonl            # exit 1, SOME CHECKS FAILED
```

The two scripts make sure that the traces come from the R3 code. A ciphertext MAC input of 171
bytes is the domain label (35), the big-endian epoch (8) and `ct2` (128). With `ct1 ‖ ct2`, it is
1131 bytes.

The monitor rejects all 22 parties. Party A is rejected in all 11 traces when it verifies the
ciphertext MAC (`ekSentCt1Received`). Party B is rejected when it builds the `ct2` encoder: in 9
traces at `ct1Acknowledged`, in one at `ct1Sampled`, and in one at `ekReceivedCt1Sampled`. The
report also prints "key agreement: ok". That line has no value here: a rejected party gives an
empty key list (`Monitor/Check.lean:278`), so the check compares two empty lists. Report lines
(chaos):

```
session 1 party A: REJECTED: operation 606 (line 695), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #15: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
session 1 party B: REJECTED: operation 479 (line 560), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #50: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
```

The messages do not name the cause. "On other keys or data" can mean a wrong key, a wrong epoch
encoding or missing ciphertext bytes. B's message is a disjunction, but the trace has an
`mlkem.encaps2` call in that operation, so the HMAC is the missing value.

Why it matters: the spec (ML-KEM Braid §2.5) MACs `ct1 ‖ ct2`. R3 removes `ct1` from the MAC
input, so the code drops an explicit binding that the spec requires. The receiver still uses both
parts in ML-KEM decapsulation, and the decapsulated secret goes into the MAC key. Under the usual
cryptographic assumptions, a changed `ct1` with the original `ct2` and tag will therefore fail
verification. We did not test this, and we did not show that the changed protocol is secure. The
demo shows a spec deviation that the monitor detects, not an authentication bypass. The existing
tests did not detect the slip, because both parties make it and no test checks the MAC input
against a fixed value. The monitor detects it, because the logged HMAC input is not the input that
the model requires.
