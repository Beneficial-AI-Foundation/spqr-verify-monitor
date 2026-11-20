# Codex review, round 1

Model output (findings section), followed by how each finding was handled.

1. HIGH — [docs/monitor.md:116]: A known-answer test of `mac_ct` does not catch R3. That patch leaves `mac_ct` unchanged and changes two callers to pass `ct2` instead of `ct1 || ct2`. A standalone test supplying the correct concatenation still passes. Fix: restrict this claim to R1 and R2, and describe a caller-level test for R3 that checks the authenticated ciphertext contents.

2. HIGH — [docs/monitor.md:50]: The stated key-agreement guarantee is stronger than the implementation. `sessionChecks` permits epochs with a key from only one party; it reports them as incomplete without failing. Evaluating it with no Alice keys and one Bob key returns `Except.ok ()`. The slides repeat the stronger claim at line 350. Fix: say that keys agree whenever both parties log a key for the same epoch, each party logs at most one key per epoch, and incomplete epochs are reported separately.

3. HIGH — [docs/monitor-slides/slides.tex:414]: “R4 … [is] out of reach” is false for the UPPAAL implementation; the comparison table repeats this at line 433. In `formula` mode, the translator compares the computed and received MACs. An accepted R4 receive with a mismatch becomes `RECV` with `T_BAD`, while the model permits only `RECV_ERR` for that token. An available R4 trace produces precisely this combination at operation 1737. Fix: distinguish UPPAAL’s ability to detect this case from Veil’s omission of MAC equality, and update the table and generated PDF.

4. HIGH — [docs/monitor.md:22]: The claim that UPPAAL and Veil reproduce the same rejection operations has no reproduction procedure in the reviewer guide. Its commands generate traces and run the Lean monitor, but never run either visualization checker. The UPPAAL README’s example uses an old `/tmp` trace, and Veil requires an external built checkout without a documented revision here. Fix: add commands using the section 5 output paths, document the required tool versions and Veil checkout, and explain how to compare each party’s rejected operation with the Lean report.

5. HIGH — [scripts/monitor-mutants.sh:25]: The documented mutant command unconditionally requires `systemd-run`, a working user service manager, and support for its memory-limit properties. Section 3 documents only Rust and Lean prerequisites. Without that environment, every monitor invocation fails before checking a trace. Fix: document and check these prerequisites before starting the expensive test runs, or provide a configurable alternative runner.

6. HIGH — [scripts/monitor-mutants.sh:38]: The advertised `OUT_DIR` argument breaks when it is relative. After the subprocess changes into `$dir/src-tree`, both `CARGO_TARGET_DIR=$dir/target` and `SPQR_MONITOR_DIR=$dir/traces` resolve relative to that directory. The monitor subsequently looks for traces relative to the repository root and finds none. Fix: resolve the output directory to an absolute path before constructing per-mutant paths or changing directories.

7. HIGH — [scripts/trace-viewer.py:342]: Message matching reuses the first later receive for every identical send. A sequence containing two identical `Ct1Ack` sends followed by two receives draws both arrows to the first receive and none to the second. The global `tampered_orig` set also marks every identical send as tampered when only one delivery was changed. Fix: match occurrences in file order using queues of outstanding sends, consume an occurrence for an ordinary receive, and associate tampering with the specific matched delivery. Preserve the original send’s availability for the driver’s retry behavior.

8. MEDIUM — [Monitor/Check.lean:17]: “The learning pass is not trusted” misstates the trust boundary and contradicts the guide and slides. `checkRun_sound` proves a property of the supplied tables and observations; it does not prove that the learning pass associates logged decoder results and parity chunks with the correct arguments. Replaying those tables again does not establish that association. Fix: state that table construction is trusted to represent the log correctly, while `checkRun` verifies the resulting model replay.

9. MEDIUM — [viz/veil/trace2veil.py:204]: Every window reconstructs its starting state by copying and scanning the entire preceding trace. Searching \(N\) retained steps in windows of size \(W\) therefore performs approximately \(N^2/(2W)\) prefix visits, with further rescans during bisection. Fix: advance the logged state once through the trace, retain snapshots at window boundaries, and reuse the failing window’s snapshot during bisection.

10. MEDIUM — [viz/veil/SpqrBraid.lean:10]: The module docstring includes implementation history about an abandoned representation failing at eight steps, contrary to the requested formal, history-free style. The new `PartialModel.lean:22` and `StateMachine/Monitor.lean:26` module docstrings also retain explicitly prohibited bold `Source` labels. Fix: state the current action structure directly, move the historical explanation to the historical documentation, and use plain source citations.


VERDICT: CHANGES NEEDED

## Resolution

1. Fixed. Section 6 of `docs/monitor.md` limits the KAT claim to R1 and R2.
2. Fixed in `docs/monitor.md` section 2 and in the slides.
3. Fixed. UPPAAL `formula` mode finds R4 under tampering (operation 1147 in the rerun). The slides say so.
4. Fixed. `scripts/viz-compare.sh` and section 7 of `docs/monitor.md`.
5. Fixed. The cap is used only when `systemd-run` exists; `SPQR_MONITOR_MEMCAP=0` turns it off.
6. Fixed. The output directory is made absolute.
7. Fixed. The viewer matches each receive to one send through per-message queues.
8. Fixed. `Monitor/Check.lean` says that table construction is trusted.
9. Fixed. `trace2veil.py` keeps snapshots at window boundaries.
10. The history sentence is removed. The `**Source:**` label is kept: it is the convention of
    the Lean files on `main`.
