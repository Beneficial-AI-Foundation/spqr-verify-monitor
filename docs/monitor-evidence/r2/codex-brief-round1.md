# Review request: R2 demo mutant for the SPQR runtime monitor

## Context
SPQR (Rust) has a cargo feature `monitor` that logs each party's `States::send`/`recv` calls and primitive calls (hmac, encaps, ...) as JSON lines. A Lean program `Monitor/Main.lean` replays them through a verified model checker (BraidModel). A step needing a primitive value the code did not compute in that call is rejected.
The demo shows realistic one-line slips that pass `cargo test` but are caught by the monitor. Each slip is a branch with one commit, not for merging. R1 (branch claude/spqr-monitor-mutant-mac-root-key, commit 392b552) keyed the ciphertext MAC with root_key. R2 (this review) encodes the epoch little-endian in Authenticator::mac_ct.

## Task that was given
1. In src/authenticator.rs, inside Authenticator::mac_ct only, change ep.to_be_bytes() to ep.to_le_bytes(). Commit only that, modeled on 392b552.
2. Show `cargo +1.99.1 test` passes (57 tests). Generate traces with `SPQR_MONITOR_DIR=/tmp/spqr-traces-R2-branch cargo +1.99.1 test --features monitor`, run `lake env lean --run Monitor/Main.lean /tmp/spqr-traces-R2-branch/*.jsonl`, confirm all 22 parties rejected, quote the two chaos report lines.
3. Append a short R2 subsection to docs/monitor-demo.md §5 (local doc, never committed).
Also: the worktree branch was renamed from claude/spqr-monitor-mutant-mac-le-epoch-204a0a to claude/spqr-monitor-mutant-mac-le-epoch to match R1's naming.

## What to check
- The mutant is exactly the intended one-line slip (only mac_ct, not verify_ct at line ~51 or update at ~97). Note: verify_ct may call mac_ct internally; consider whether that matters for the claim "both parties make it, so they still agree".
- The commit message is accurate.
- The doc subsection's claims match the evidence: "at the same transitions as R1", 22/22 rejected, exit code 1, 57 tests, the quoted lines.
- Anything misleading or missing in the doc (e.g. table row for R2 says "passes" without count; the R1 report lines in the doc are in an older format without "(line N)" and "BraidModel.Label." prefix).

## Files you can read
- Mutant worktree: /home/lacra/git_repos/baif/SparsePostQuantumRatchet-verify/.claude/worktrees/spqr-monitor-mutant-mac-le-epoch-204a0a (git show 6b6d346; git show 392b552; src/authenticator.rs)
- Demo doc: /home/lacra/git_repos/baif/SparsePostQuantumRatchet-verify/.claude/worktrees/spqr-monitor-7f2bcf/docs/monitor-demo.md (section 5)
- Monitor report (full output): /tmp/spqr-R2-report.txt
- Traces: /tmp/spqr-traces-R2-branch/*.jsonl

## Commit
```
commit 6b6d346333df71b8484f5d1161e34e5440fbe2a1
Author: astefano <lacramioara.astefanoaei@gmail.com>
Date:   Thu Nov 19 20:57:45 2026 +0100

    Demo mutant: encode the epoch little-endian in the ciphertext MAC
    
    A one-word slip in Authenticator::mac_ct: to_le_bytes instead of
    to_be_bytes. Both parties make it, so they still agree and the test
    suite passes. This branch is not for merging.
    
    Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

diff --git a/src/authenticator.rs b/src/authenticator.rs
index 76bc3af..58bcb4e 100644
--- a/src/authenticator.rs
+++ b/src/authenticator.rs
@@ -69,7 +69,7 @@ pub fn verify_ct(&self, ep: Epoch, ct: &[u8], expected_mac: &[u8]) -> Result<(),
     pub fn mac_ct(&self, ep: Epoch, ct: &[u8]) -> Mac {
         let ct_mac_data = [
             b"Signal_PQCKA_V1_MLKEM768:ciphertext".as_slice(),
-            &ep.to_be_bytes(),
+            &ep.to_le_bytes(),
             ct,
         ]
         .concat();
```

## Doc section 5 as it stands
```markdown
## 5. Realistic scenarios (2026-11-19)

M1 (deleting the `verify_ct` call) stays as scenario 0: it shows the mechanism, but no engineer
deletes a check by mistake. The scenarios below are slips a refactor could make. Each changes both
parties the same way, so the parties still agree on keys. Scratch runs: `/tmp/spqr-mutants3.sh`,
log `/tmp/spqr-mutants3.log`, traces `/tmp/spqr-traces-R*/`. Monitor results counted over all
eleven traces (22 parties).

| # | Change | `cargo test` | Monitor |
|---|--------|--------------|---------|
| R1 | `Authenticator::mac_ct` keys the HMAC with `root_key` instead of `mac_key` (copy-paste) | passes (57) | 22/22 rejected |
| R2 | `mac_ct` encodes the epoch with `to_le_bytes` | passes | 22/22 rejected |
| R3 | sender and receiver MAC `ct2` only, not `ct1 ‖ ct2` (`ct1` unauthenticated) | passes | 22/22 rejected |
| R4 | `let _ = auth.verify_ct(...)` instead of `...?` (result dropped) | passes | **accepted** |
| R5 | `Authenticator::update` encodes the epoch with `to_le_bytes` | fails (regression test with stored states) | not run |

R1 has a branch: `claude/spqr-monitor-mutant-mac-root-key` (`392b552`, on `f56fb87`). Party A is
rejected when it verifies the ciphertext MAC (transition (5)); party B earlier, when it builds the
`ct2` encoder (transitions (9)/(11)). Report line (chaos):

```
party A: REJECTED: operation 609 States::recv in ekSentCt1Received epoch 1, message epoch 1 ct2 #12: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
party B: REJECTED: operation 513 States::recv in ct1Acknowledged epoch 1, message epoch 1 ekct1ack #62: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
```

R2 has a branch: `claude/spqr-monitor-mutant-mac-le-epoch` (`6b6d346`, on `f56fb87`). The commit
changes `ep.to_be_bytes()` to `ep.to_le_bytes()` in `Authenticator::mac_ct` only. `cargo +1.99.1 test`
passes (57 tests). The monitor rejects all 22 parties (exit code 1) at the same transitions as R1.
Commands:

```
cargo +1.99.1 test
SPQR_MONITOR_DIR=/tmp/spqr-traces-R2-branch cargo +1.99.1 test --features monitor
lake env lean --run Monitor/Main.lean /tmp/spqr-traces-R2-branch/*.jsonl
```

Report lines (chaos):

```
party A: REJECTED: operation 660 (line 749), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
party B: REJECTED: operation 456 (line 537), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #81: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
```

R4 is the important gap. An ignored verification result changes nothing in an honest run, so no
monitor of honest traces can see it. Catching it needs adversarial input: a test driver that
tampers with some `ct2` / `hdr` chunks, tolerates the expected `recv` errors, and logs them. Then
the model's `Receive()` fails (`receiveO = some none`) while the mutant's code accepts, and the
checker rejects the step.

### R3: MAC only `ct2` (branch)

R3 has a branch: `claude/spqr-monitor-mutant-mac-ct2-only-aa9798` (`52c4169`, on `f56fb87`). The
commit changes `auth.mac_ct(epoch, &ct1)` to `&ct2` in `src/v1/unchunked/send_ct.rs` and
`auth.verify_ct(epoch, &ct1, &mac)` to `&ct2` in `src/v1/unchunked/send_ek.rs`. At both places
`ct1` already holds `ct1 ‖ ct2`, so the MAC now covers `ct2` only.

```
cargo +1.99.1 test                      # 57 passed, 0 failed
SPQR_MONITOR_DIR=/tmp/spqr-traces-R3-branch cargo +1.99.1 test --features monitor   # 57 passed, 11 traces
lake env lean --run Monitor/Main.lean /tmp/spqr-traces-R3-branch/*.jsonl            # exit 1, SOME CHECKS FAILED
```

All 22 parties are rejected. Delivery, key agreement and randomness reuse are ok in every trace.
Each party is rejected at the same transition as in R1. Report lines (chaos):

```
session 1 party A: REJECTED: operation 690 (line 779), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #8: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
session 1 party B: REJECTED: operation 522 (line 603), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #91: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
```

Why it matters: the spec (ML-KEM Braid §2.5) MACs `ct1 ‖ ct2`. With the mutant, `ct1` is no
longer covered by the MAC, so the code drops a binding that the spec requires. A changed `ct1` is
probably still caught indirectly: the receiver updates the MAC key from `decaps(dk, ct1, ct2)`
before the check, and ML-KEM implicit rejection gives a different secret. We did not test this.
The tests cannot see the slip, because both parties make it and nobody changes `ct1`. The monitor
sees it, because the logged HMAC input is not the input that the model requires.
```

## Monitor report
```
/tmp/spqr-traces-R2-branch/test.messaging_scka.test.onlineoffline_healing.jsonl: 75740 events, 1 session(s)
  session 1 party A: REJECTED: operation 246 (line 335), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 211 (line 292), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/test.messaging_scka.test.pingpong_healing.jsonl: 22931 events, 1 session(s)
  session 1 party A: REJECTED: operation 355 (line 444), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 286 (line 367), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/test.messaging_scka.test.random_balanced_healing.jsonl: 14750 events, 1 session(s)
  session 1 party A: REJECTED: operation 196 (line 285), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 172 (line 253), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/test.messaging_scka.test.random_balanced.jsonl: 14282 events, 1 session(s)
  session 1 party A: REJECTED: operation 226 (line 315), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 202 (line 283), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/test.messaging_scka.test.random_balanced_out_of_order.jsonl: 14396 events, 1 session(s)
  session 1 party A: REJECTED: operation 173 (line 262), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 156 (line 237), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/v1.test.balanced_healing.jsonl: 14750 events, 1 session(s)
  session 1 party A: REJECTED: operation 196 (line 285), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 172 (line 253), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/v1.test.chaos.jsonl: 97899 events, 1 session(s)
  session 1 party A: REJECTED: operation 660 (line 749), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 456 (line 537), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #81: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/v1.test.onlineoffline_healing_unidir.jsonl: 74417 events, 1 session(s)
  session 1 party A: REJECTED: operation 171 (line 260), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 144 (line 225), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/v1.test.random_balanced.jsonl: 14518 events, 1 session(s)
  session 1 party A: REJECTED: operation 185 (line 274), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 165 (line 246), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/v1.test.random_balanced_out_of_order.jsonl: 14444 events, 1 session(s)
  session 1 party A: REJECTED: operation 171 (line 260), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #3: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 155 (line 236), States::recv in BraidModel.Label.ekReceivedCt1Sampled epoch 1, message epoch 1 ekct1ack #37: missing primitive value: a primitive value of a payload without a decoder (ct2 encoder)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
/tmp/spqr-traces-R2-branch/v1.test.random_slow_alex_healing_auth_bidir.jsonl: 13853 events, 1 session(s)
  session 1 party A: REJECTED: operation 267 (line 356), States::recv in BraidModel.Label.ekSentCt1Received epoch 1, message epoch 1 ct2 #4: missing primitive value: no hmac call with the key and data of the ciphertext MAC (verify_ct) (this operation logged 1 hmac call(s), on other keys or data)
  session 1 party B: REJECTED: operation 246 (line 327), States::recv in BraidModel.Label.ct1Acknowledged epoch 1, message epoch 1 ekct1ack #35: missing primitive value: no encaps2 call, or no hmac call with the key and data of the ciphertext MAC, for the ct2 encoder (this operation logged 1 hmac call(s), on other keys or data)
  session 1 delivery: ok
  session 1 key agreement: ok
  session 1 randomness reuse (outside BraidModel): ok
SOME CHECKS FAILED
```
