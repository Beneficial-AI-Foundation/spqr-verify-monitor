# Veil model of the ML-KEM Braid

`SpqrBraid.lean` is a [Veil](https://github.com/verse-lab/veil) model of the
braid. `trace2veil.py` replays monitor traces (the JSONL logs of the cargo
feature `monitor`) against it as Veil trace queries. `model-check.sh` runs
the Veil model checker on it.

## Get and build Veil

The scripts were run with Veil commit `4624379`.

```bash
git clone https://github.com/verse-lab/veil.git
cd veil
git switch --detach 4624379
lake build Veil
```

The scripts run `lake lean` in this checkout, under a 12 GB memory cap
(`systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0`).

## Replay a trace

```bash
python3 -I viz/veil/trace2veil.py search TRACE.jsonl --veil VEIL_DIR --steps N --jobs 2
```

`search` cuts the first N steps of session 1 into windows of 12 steps.
Each window is one query. It starts from the state that the log gives
before the window. The script bisects the first window with no model and
prints the first step with no model: its trace line, party and operation.
One window takes about 30 seconds. `query` prints one query and `check`
runs it. The docstring of `trace2veil.py` has all the options.

Veil replays both parties of a session together. So it finds only the
first rejection in trace order, not one rejection per party.

`scripts/viz-compare.sh` runs `search` on the mutant traces and compares
the result with the Lean monitor and UPPAAL.

## Model check

```bash
viz/veil/model-check.sh VEIL_DIR OUT.json
```

This checks a property that fails once Alice reaches epoch 3. It writes
the counterexample as JSON for `panel.html`.

## What Veil sees of the MACs

For each operation, the script gives Veil one MAC observation: `absent`
(no `hmac` call), `good` (every `hmac` input has the form of `MacHdr` or
`MacCt` for the epoch) or `bad`. Veil does not compare MAC values: it does
not check that the computed MAC equals the received MAC, and it does not
see the MAC key. So Veil cannot find R1 (MAC with the wrong key) or R4
(the result of the MAC check is dropped).
