You review the branch `claude/spqr-monitor-review` of this repository against its base `acd6e308`
(see `git diff acd6e308 HEAD`). The branch adds a runtime monitor for SPQR: Rust instrumentation
(`src/monitor.rs`, hooks under `src/`, feature `monitor`), a tampering test driver
(`src/test/orchestrator/tamper.rs`), a Lean checker with soundness theorems
(`Spqr/Specs/Braid/StateMachine/{PartialModel,Monitor}.lean`) and an executable (`Monitor/*.lean`),
demo mutants (`mutants/`, `scripts/monitor-mutants.sh`), visualization scripts (`scripts/`,
`viz/veil/`), and docs (`docs/monitor.md` is the reviewer guide; `docs/monitor-demo.md`,
`docs/monitor-plan*.md`, `docs/monitor-evidence/` are historical logs; `docs/monitor-slides/`).

Review for these properties only:
1. Useful results are clear: `docs/monitor.md` says which results matter and why.
2. Reproducibility: a reviewer can rerun every claim in `docs/monitor.md` from the documented
   commands. (Sections 4 and 5 contain placeholders RESULTS-HONEST and RESULTS-MUTANTS that are
   being filled in by a run in progress; do not report them.)
3. No overclaims: in `docs/monitor.md`, the slides, READMEs, docstrings and doc comments, every
   claim must be true of the code and theorems. Check claims against the code.
4. Lean docstrings: concise, accurate, clear and formal, in the style of
   ../secure-messaging/SecureMessaging/SCKA/OppUniKEM/Correctness.lean (one plain statement;
   "Assume: ... Then ..."; no bold labels, no history). Rust and Python doc comments: the same bar.
5. No inefficient code and no duplicated code in the files the branch adds or changes.
6. Standard coding practice for Lean 4, Rust and Python.

Constraints the authors must keep (do not ask to break them): the library code under `src/`
(outside `src/test/` and `src/monitor.rs`) is frozen and must expand identically to the base with
the feature off, so hooks may change only in comments; no `maxHeartbeats` and no toolchain changes.
The historical logs may mention old branches and /tmp paths; report them only if
`docs/monitor.md` relies on them.

Output: a list of findings, each with severity HIGH (wrong claim, broken reproduction, bug),
MEDIUM (misleading text, real duplication or inefficiency, clear style violation) or LOW (nit),
a file:line, the problem, and a concrete fix. Then one final line: `VERDICT: CLEAN` if there is no
HIGH or MEDIUM finding, else `VERDICT: CHANGES NEEDED`. Do not edit files.
