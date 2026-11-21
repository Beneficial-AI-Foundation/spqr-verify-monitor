# Round 2: revised R2 doc text after your first review

Your first review (full text): /tmp/codex-R2-review1.txt (read the part after the last "codex" line).
Responses:
1. Vacuous key agreement: confirmed in Monitor/Check.lean (fail -> keys []). Not fixed here: it is monitor-branch code, out of scope for the R2 mutant branch. The doc now says the line is vacuous, and reports a direct comparison of the logged `key` fields of States::send/recv results: in all 11 traces, every epoch that both parties logged has the same secret, no duplicates.
2. Transitions: now A at (5) in all 11; B at (11) in 10 traces, (12) in v1.test.random_balanced_out_of_order. Checked against Model.lean:253-275. Dropped "same as R1".
3. Stale traces: added `rm -rf` before the trace run, and per-command outcomes as comments.
4. Scope: added a paragraph (no forgery, test-suite gap, KAT would catch it, mixed peers disagree except at epoch 0).
5. Table cell now "passes (57)". Not changed: R1 lines and the "no engineer deletes a check" sentence (other sessions' text, not R2).

Review the revised text below for accuracy against the evidence (traces /tmp/spqr-traces-R2-branch, report /tmp/spqr-R2-report.txt, code in the current directory). Is anything still wrong or misleading? In particular: is "a mutant peer and a correct peer disagree at every epoch except 0" correct for u64 epochs? Zero new findings is a valid answer.

# R2 doc revision for docs/monitor-demo.md §5 (after Codex review, 2026-11-19)

Apply to `/home/lacra/git_repos/baif/SparsePostQuantumRatchet-verify/.claude/worktrees/spqr-monitor-7f2bcf/docs/monitor-demo.md`.
A hook blocks the R2 session from writes to another worktree, so the R2 session did not edit it.

1. In the §5 table, change the R2 row's `cargo test` cell from `passes` to `passes (57)`.
2. Delete the R2 paragraph, code blocks and report lines that sit between the R1 report lines and
   the paragraph "R4 is the important gap." (they start with "R2 has a branch:").
3. Insert the subsection below directly before `### R3: MAC only `ct2` (branch)`.

Also for the monitor branch (not a doc change): for a rejected party, `key agreement: ok` is
vacuous. `checkParty` returns `keys := []` on failure (`Monitor/Check.lean`, `fail` at line 278),
and `sessionChecks` then compares two empty maps. The R3 subsection relies on that line too.

---

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

Scope: little-endian is still a one-to-one encoding of the epoch, so R2 does not let an attacker
forge a MAC. R2 shows a mismatch between the code and the specification that the existing test
suite does not catch. A known-answer test of `mac_ct` at an epoch such as 1 catches it as well.
A mutant peer and a correct peer disagree at every epoch except 0, where both encodings are equal.
