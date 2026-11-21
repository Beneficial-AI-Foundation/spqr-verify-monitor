# Codex review, round 6

1. LOW — docs/monitor.md:109: “Each file … is a one-line change” is imprecise: R3 changes two call sites in two files, and M5 replaces multiple lines. The same wording appears at line 15. Fix: use “small change” in both places.

2. LOW — docs/monitor-slides/slides.tex:90: “Every operation ends with exactly one step event” omits initialization. Operation 0 contains initialization events and must have no step event, as `checkParty` enforces. Fix: say “Every operation other than initialization (operation 0) ends with exactly one step event,” and regenerate the PDF.

3. LOW — scripts/uppaal/spqr_uppaal.py:366: The query caption says Alice finishes epoch 1 as the ciphertext sender. Alice starts as the encapsulation-key sender in epoch 1 and first reaches `Ct2Sampled` in epoch 2. The query itself imposes no epoch condition. Fix: change the caption to “Alice reaches Ct2Sampled” and regenerate `scripts/uppaal/braid.xml`.

VERDICT: CLEAN

## Resolution

All three LOW findings are fixed as proposed. `scripts/uppaal/braid.xml` and the slide PDF are regenerated.
