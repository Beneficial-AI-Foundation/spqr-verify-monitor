# Codex reviews of the monitor plan

Raw outputs: `/tmp/codex-monitor-plan-r<n>.out`.

## Round 1 (draft 1)

| # | Sev. | Point | Decision |
|---|------|-------|----------|
| 1 | HIGH | Systematic chunks are not contiguous 32-byte slices | Rejected. `encode_bytes_base` puts word `w` at position `w/16` of polynomial `w%16`; `chunk_at(idx)` reads position `idx` of polynomials 0..16, so words `16·idx..16·idx+15`. Recorded in plan §2; the honest traces will confirm it. |
| 2 | HIGH | `Dec = (n, List Chunk)` does not model `PolyDecoder` | Partly accepted. It is an index (the history), not a model; the code's decoder state is a function of the history, so a table on it is a well-defined partial function. Wording fixed in §5.4; the codec is a logged primitive, not checked (§7). |
| 3 | HIGH | Defaults on missing table entries make detection probabilistic | Accepted. Replaced by `Option`-valued primitives (`OPrims`) and an `Option`-monad model; a missing value is a deterministic rejection (§5.2, §5.3). |
| 4 | HIGH | `CodeAgrees` checking claimed but not established | Accepted. §7 now says what is checked (call inputs and that each needed evaluation happened) and that `CodeAgrees P` is not. Theorem 3 is now for every `P` that agrees with the log. |
| 5 | MEDIUM | `States` name/epoch helper cannot live in `src/monitor.rs` | Rejected. The state types are `pub(crate)` with `pub fn epoch()`; `src/monitor.rs::state_info` compiles (`cargo +1.99.1 build --features monitor`). |
| 6 | MEDIUM | No cross-party binding | Accepted as an untrusted check (§5.6): received messages were sent by the peer; per-epoch secrets agree. |
| 7 | MEDIUM | M1 detection depends on instrumentation | Accepted as a scope statement (§7, §8: instrumentation trusted, as in the paper). The demo checks it empirically. |
| 8 | HIGH | No explicit operation ids | Accepted. Every event carries `op`; exactly one terminal event per operation (§3). |
| 9 | MEDIUM | Randomness hook underspecified; secrets in clear | Accepted in part: §3 specifies the local arrays after `fill_bytes` and states the test-only status (party set only from `#[cfg(test)]` code). Redaction rejected: test keys from `OsRng` and auth key `b"1"` protect nothing. Freshness reworded as reuse detection (§5.7). |
| 10 | MEDIUM | `git apply --check` is not an extraction check | Accepted. §4.3 is now a hypothesis with two checks; added the `-Zunpretty=expanded` diff against `main` with the feature off. |
| 11 | LOW | Feature does not exist yet | Rejected: the plan adds it. It now exists on the branch and builds. |
| 12 | LOW | Per-party truncation misrepresents coverage | Accepted. §6 reports a prefix as partial coverage. |
| 13 | LOW | Scope is the test harness | Accepted. §1 says so. |

## Round 2 (draft 2)

Codex ran while the implementation had started, and reviewed the branch as well as the plan.

| # | Sev. | Point | Decision |
|---|------|-------|----------|
| 1 | HIGH | `op` protocol not implemented in `src/monitor.rs` | Not a plan defect: phase 3 implements it. Will be in the code-review round. |
| 2 | HIGH | Per-party final tables lose which call computed a value; a cached MAC would satisfy a later step | Accepted. Tables are now per operation (§5.3): each step uses only values logged during its own `States` call. Checked that every transition's values are computed in the same call. |
| 3 | HIGH | `Monitor.lean` still over total `Prims` | Not a plan defect; since done: `PartialModel.lean` (`OPrims`, `Agrees`, `sendO`, `receiveO`, soundness) and `Monitor.lean` over `OPrims`; `#print axioms` shows only `propext`, `Classical.choice`, `Quot.sound`. |
| 4 | HIGH | Executable absent | Not a plan defect: phase 3. |
| 5 | MEDIUM | `decaps`, `ek_matches_header` hooks call libcrux twice | Accepted: compute once, log, return (§4.2). The repeated `decoded_message()` stays: it takes `&self`, and avoiding it would change code outside cfg. |
| 6 | MEDIUM | Cross-party rule underspecified (multiplicity, incomplete epochs) | Accepted: multiset consumption in file order; one-sided epochs reported as incomplete (§5.6). |
| 7 | LOW | "events of two parties" contradicts one file per session | Accepted: one party per operation (§3). |

## Round 3 (draft 3)

No HIGH or MEDIUM issue. Loop closed. LOW points, all accepted into draft 4:

| # | Sev. | Point | Decision |
|---|------|-------|----------|
| 1 | LOW | `v1::test::` filter does not run the `messaging_scka` tests | Accepted: §6 runs the whole suite; all eleven traces count. |
| 2 | LOW | Conflicts within one operation unspecified | Accepted: §5.5 rejects them too (the code's `insertFn` already does). |
| 3 | LOW | Failed `States::send` has no checker rule | Accepted: §5.3 rejects it as unsupported (the code's `parseObs` already does). |

# Codex reviews of the implementation

## Code round 1 (`152b3d3`)

No defect in the Rust hook values. Four trace-format gaps, all accepted and fixed in the next
commit, each with a negative test (`/tmp/spqr-neg-*.jsonl`, all rejected); honest traces still
accepted (22/22 parties), M1 traces still rejected (22/22).

| # | Sev. | Point | Fix |
|---|------|-------|-----|
| 1 | MEDIUM | Step event in operation 0 ignored | `checkParty` rejects a step event in the initialization. |
| 2 | MEDIUM | Role not bound to party (`"x"` treated as Bob) | Party A must have role `a`, B role `b`; the party chooses `initAliceO` / `initBobO`. |
| 3 | LOW | Unknown parties ignored | `checkFile` rejects any party other than A and B. |
| 4 | LOW | Operation numbers only nondecreasing | `checkFile` requires each new operation number to be the previous one plus 1. |

## Code round 2 (`957f33f`)

Round-1 fixes confirmed. No HIGH. Two MEDIUM, accepted and fixed in the next commit, with
negative tests (`/tmp/spqr-neg-{empty,aonly,prestate}.jsonl`, all rejected); honest traces still
accepted (22/22 parties), M1 still rejected (22/22). (A first run failed before reviewing: the
Codex default model had changed to one this account cannot use; rerun with `-m gpt-5.6-terra`,
the model of all earlier rounds.)

| # | Sev. | Point | Fix |
|---|------|-------|-----|
| 1 | MEDIUM | A session missing a party, or an empty file, is accepted | `checkFile` rejects an empty file and a session without events of A or of B. |
| 2 | MEDIUM | The logged pre-state of a step is never checked | `checkParty` rejects a step whose logged state name and epoch differ from the model's state before it. |

## Code round 3 (`5fcd212`)

Not completed. Codex read the diff and then stopped with "You've hit your usage limit ... try
again at Dec 19th, 2026 6:47 PM" (`/tmp/codex-code-monitor-r3.out`). No verdict on the round-2
fixes. The code review loop is open: rerun round 3 with
`codex exec -m gpt-5.6-terra --skip-git-repo-check -s read-only '<prompt>' < /tmp/codex-code-monitor-r3.md`.

## Code round 3 (`5fcd212`), Claude reviewer

Codex was unavailable (usage limit), so on the user's choice an independent Claude subagent ran
round 3 with the same brief. It confirmed the round-1 and round-2 fixes, reran the expanded-crate
diff (identical), the patch check (26 ok), the honest traces (22/22 accepted) and M1 (22/22
rejected). No HIGH or MEDIUM: the code review loop is closed. Its five LOW findings are fixed in
`790ca27`, each checked with its crafted trace (`/tmp/spqr-review-traces/`, now rejected); honest
traces still 22/22 accepted, M1 still 22/22 rejected.

| # | Sev. | Point | Fix |
|---|------|-------|-----|
| 1 | LOW | Parity chunk index and length unchecked | Reject unless index = `i mod 65536` and 32 bytes. |
| 2 | LOW | Second `init` event ignored | Reject more than one `init` in operation 0. |
| 3 | LOW | `--max-ops` prints "ALL CHECKS PASSED", exit 0 | Prints a partial-coverage line, exit code 3. |
| 4 | LOW | Wrong docstrings (`addMessage`, `Tables`) | Fixed. |
| 5 | LOW | Plan names `Learn.lean` and puts the partial model in `Monitor.lean` | Plan fixed. |

## Finding from the R2 session (after code round 3)

"key agreement: ok" was vacuous for a rejected party: `checkParty` returned no keys on failure.
Fixed in `94ee49b`: the check uses the keys logged in the step events. Honest traces still pass
(22/22 accepted, 11 sessions key agreement ok); an altered secret is caught.
