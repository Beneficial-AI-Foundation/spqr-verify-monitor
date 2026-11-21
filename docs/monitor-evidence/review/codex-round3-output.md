# Codex review, round 3

1. HIGH — [docs/monitor.md:16]: R4’s detection claim is too broad. The monitor does not reject the first party that accepts a tampered chunk. In the seeded R4 `tamper_early` trace, Bob accepts a tampered header chunk at session 1, operation 2; the monitor accepts both parties for that entire session. In session 2, Alice accepts the tampered ciphertext chunk at operation 176 but is rejected only at operation 192, when decoding completes. The statement at line 137 that accepting a tampered chunk causes different keys is likewise false for incomplete chunks. Fix: say that R4 is detected when ciphertext decoding completes and the code accepts despite a failed MAC check; distinguish this from legitimately accepting incomplete chunks.

2. HIGH — [scripts/viz-compare.sh:51]: Missing Lean verdicts still pass through the comparison script. The round-2 failure-handling fix covers UPPAAL and Veil, but `lean_verdict` returns success with empty output when an existing report lacks the requested trace or party—for example, after an interrupted monitor run or moving the output directory. I confirmed that this produces status 0 and an empty verdict. The caller interprets the empty operation as zero, derives a 50-operation bound, and can finish successfully with `none` in the Lean column. Fix: require a recognized Lean acceptance or rejection before calculating bounds; exit nonzero with the report, trace, and party when the verdict is missing or unrecognized.

3. HIGH — [docs/monitor.md:144]: The standard rejection counts are not guaranteed “in every run.” The standard tests do not enforce coverage of the mutated transitions. For example, `chaos_with` permits zero sends on every tick, and its key-consistency assertion passes on empty key histories. Such a run never exercises the mutations and its initialization-only trace is accepted. Although this outcome is extremely unlikely, the universal claim is unsupported. Fix: describe the counts as observed results and explain that detection requires reaching the affected transition. Keep the standard tests’ `OsRng` behavior unchanged.

4. MEDIUM — [Monitor/Tables.lean:39]: Decoder histories incur quadratic copying and storage. `d.2 ++ [c]` copies the accumulated list whenever a chunk arrives. `checkParty` retains these successive histories as decoder-table keys, so a decoder receiving \(n\) chunks retains approximately \(n(n+1)/2\) list cells; hashing these keys also repeatedly traverses the histories. Repeated chunks can keep a decoder incomplete while this cost grows. Fix: represent histories with shared reverse lists or another persistent structure, and cache an incremental hash while retaining collision-safe equality. Update the decoder representation’s docstring accordingly.

VERDICT: CHANGES NEEDED

## Resolution

1. Fixed. Result 4 and section 5 of `docs/monitor.md` say that the monitor rejects the step
   where a `Ct2` decoder that got a tampered chunk completes, and give both R4 examples. The
   slide quotes the key agreement failure of the seeded run (epoch 1).
2. Fixed. `lean_verdict` stops the script when the report has no verdict for the trace and
   party. Tested with a truncated report.
3. Fixed. Section 5 says that the standard column was the same in each run, and that a run
   finds a mutant only if it reaches the changed step.
4. Fixed. `MDec` is a structure with the chunks newest first and a hash that `addChunk`
   extends, so adding a chunk and hashing a decoder take constant time. The monitor reports on
   the honest and R4 traces are byte-identical to the reports before the change.
