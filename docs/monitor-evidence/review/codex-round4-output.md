# Codex review, round 4

1. HIGH — [viz/veil/trace2veil.py:265]: Veil can report acceptance after Lean fails. `run` recognizes verdict text before checking the subprocess status. A focused test confirmed that output containing `Satisfying trace found` returns acceptance with exit status 1 or 137, even alongside an error diagnostic. The comparison script consequently treats that failed invocation as successful. Fix: generate queries with `set_option veil.violationIsError false`, so ordinary unsatisfiability does not require a failing exit status; then require exit status zero before interpreting either verdict. Preserve diagnostics and reject killed or otherwise failed invocations.

2. MEDIUM — [Monitor/Tables.lean:41]: Decoder replay still performs quadratic history comparisons. The round-3 fix removes repeated list copying and hashing, but derived `DecidableEq` compares the complete `chunks` lists. Each successful decoder-table lookup during replay compares a newly reconstructed history with the stored history, traversing all preceding chunks. A focused test using the current representation took approximately 2.4, 8.7 and 35.6 seconds for lookups across 1,000, 2,000 and 4,000 successive histories. Fix: intern histories by `(previous-history ID, chunk)`, with message size represented in the initial history, and use canonical IDs for decoder-table keys. Keep interning collision-safe; comparing hashes alone would compromise correctness.

VERDICT: CHANGES NEEDED

## Resolution

1. Fixed. Each query starts with `set_option veil.violationIsError false in`, so Lean exits 0
   for both verdicts. `run` stops on any nonzero exit before it reads a verdict. The R3 search
   still stops at op 275, and its unsatisfiable query exits 0.
2. Not changed. The histories are short in practice: the longest decoder history in the honest
   traces has 223 chunks, and all decoders of all 13 honest traces need at most 3.7 million
   chunk comparisons, against a monitor run of about 4 minutes. Interning would change the
   decoder representation that the trusted table construction relies on, for a small gain.
