# R4 scratch files (local, not committed)

Copied from `/tmp` on 2026-11-20. Branches: `claude/spqr-monitor-tamper-8a6172` (`b629a74`),
`claude/spqr-monitor-mutant-verify-result-dropped` (`339cf74`).

- `spqr-r4.sh`: applies R4 to a scratch copy, then runs `cargo test`, the feature run and the
  monitor. It reads `/tmp/spqr-r4` and writes `/tmp/spqr-traces-R4`.
- `make-forged-traces.py`: writes the five forged traces from a `tamper_early` trace.
- `traces/honest`: unmutated code, 13 traces, all checks pass.
- `traces/R4`: R4 mutant traces, the two tamper traces are rejected.
- `traces/tamper-first-run`: the first tamper traces, before the full suite run.
- `traces/forged`: forge1 to forge5, each fails the delivery check.
- `monitor-output`: monitor reports for `traces/honest` and `traces/R4`.
- `codex`: inputs and outputs of the two Codex review rounds.
