# Codex review, round 5

1. HIGH — [viz/veil/model-check.sh:26]: Failed Lean builds can still produce success. The `|| true` discards the compiler’s exit status. If its output contains `VEIL_BUILD_ONLY`, the script runs the reported binary and prints `wrote …` even when compilation failed. A focused mock returning a build marker followed by an error and exit status 1 made this script exit 0. This leaves the same failure-handling problem that round 4 fixed in `trace2veil.py`. Fix: require the build command to exit successfully before parsing its marker; print the captured diagnostics and exit nonzero otherwise.

2. MEDIUM — [docs/monitor-slides/slides.tex:438]: The comparison table still obscures replay coverage. The row labelled “whole trace” puts Lean’s 85,000-operation run beside UPPAAL’s “10k steps in 90 s” and Veil’s “12-step windows.” It does not distinguish complete-session checking from bounded replay or explain that window size is not total coverage. Section 7 of the guide now makes these distinctions explicitly, but the slides and committed PDF retain the misleading comparison. Fix: label the row “Replay cost and coverage,” identify each measured scope, and state the prefix limits for the reproduced comparison. Regenerate the PDF.

VERDICT: CHANGES NEEDED

## Resolution

1. Fixed. `model-check.sh` stops with the build output when `lake lean` exits nonzero. A normal
   run still writes the counterexample.
2. Fixed. The slide row is "checked in the comparison": the whole session for the Lean monitor,
   a prefix of up to 1183 operations of one party for UPPAAL, and a prefix of up to 144 steps of
   both parties for Veil. The PDF is rebuilt.
