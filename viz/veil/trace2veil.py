#!/usr/bin/env python3
"""Turn a monitor trace into Veil trace queries on SpqrBraid.lean, and run them.

The trace is a JSONL file of the cargo feature `monitor` (format in `scripts/spqr_trace.py`).
Each step event (States::send / States::recv) of one session becomes one action of
SpqrBraid.lean (send, recv or recvErr), followed by an `assert` that pins what the trace
logged: the party, the message type, the epoch of the message relative to the receiver,
whether a key was emitted, and the state and epoch after the step. The assert also pins a MAC
observation (absent, good or bad) that this script computes from the `hmac` calls of the
operation (`mac_obs`). Veil sees only that observation, not the bytes.

A step that repeats the previous step of the same party and leaves its state unchanged is
dropped: in SpqrBraid it is enabled again and changes nothing, so the query keeps its answer.

Veil's trace queries start from the initial state and fail in its `simp` preprocessing
beyond about 20 steps. So `search` cuts the steps into windows; each window is a query from
the SpqrBraid state that the log gives before it (each party's state and epoch, and the
messages sent so far). The first unsatisfiable window is then bisected.

Modes:
  query   print one `sat trace` over the first N steps (all steps by default)
  check   run that query in Lean
  search  windowed queries up to the first step with no model

Usage (`check` and `search` run `lake lean` in a built Veil checkout, under a memory cap):
  python3 -I viz/veil/trace2veil.py query  TRACE [--session S] [--steps N]
  python3 -I viz/veil/trace2veil.py check  TRACE [--session S] [--steps N] --veil DIR [--keep DIR]
  python3 -I viz/veil/trace2veil.py search TRACE [--session S] [--steps N] --veil DIR
                                           [--window W] [--jobs J]
"""

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "scripts"))
from spqr_trace import (CT_LABEL, CT1_SIZE, CT2_SIZE, HDR_LABEL, HDR_SIZE,  # noqa: E402
                        KIND_ALIASES, LABELS, STEP_FUNCS, mac_input, operations)

MEM = "12G"
MODEL = os.path.join(HERE, "SpqrBraid.lean")

# Trace names to SpqrBraid names: `KeysUnsampled` -> `keysUnsampled`, `ekct1ack` -> `kEkCt1Ack`.
VEIL_LABELS = {name: name[0].lower() + name[1:] for name in LABELS}
VEIL_KINDS = {"none": "kNone", "hdr": "kHdr", "ek": "kEk", "ekct1ack": "kEkCt1Ack",
              "ct1ack": "kCt1Ack", "ct1": "kCt1", "ct2": "kCt2"}
VEIL_KINDS.update({k: VEIL_KINDS[v] for k, v in KIND_ALIASES.items()})
PARTIES = {"A": "pA", "B": "pB"}


def mac_input_ok(data: bytes, epoch: int, ops: list) -> bool:
    """Whether an HMAC input has the form of MacHdr or MacCt (§2.4) for `epoch`:
    PROTOCOL_INFO, the label, the epoch as 8 big-endian bytes, then the header (64 bytes) or
    ct1 || ct2 (960 + 128 bytes). For MacCt, when the operation logged decaps or encaps2,
    the ciphertext bytes must also be the ones of that call."""
    for lab, size in ((HDR_LABEL, HDR_SIZE), (CT_LABEL, CT1_SIZE + CT2_SIZE)):
        prefix = mac_input(lab, epoch, b"")
        if data.startswith(prefix) and len(data) == len(prefix) + size:
            if lab == CT_LABEL:
                ct = data[len(prefix):]
                for e in ops:
                    if e["f"] == "mlkem.decaps":
                        if ct != bytes.fromhex(e["args"][1]) + bytes.fromhex(e["args"][2]):
                            return False
                    if e["f"] == "mlkem.encaps2":
                        if ct[CT1_SIZE:] != bytes.fromhex(e["ret"]):
                            return False
            return True
    return False


def mac_obs(ops: list, epoch: int, any_mac_form: bool) -> str:
    """The MAC observation of an operation: `absent` (no `hmac` call), `good` (every `hmac`
    input passes `mac_input_ok`, or `any_mac_form` is set) or `bad`."""
    calls = [bytes.fromhex(e["args"][1]) for e in ops if e["f"] == "hmac"]
    if not calls:
        return "absent"
    if any_mac_form:
        return "good"
    return "good" if all(mac_input_ok(c, epoch, ops) for c in calls) else "bad"


def steps(path: str, session: int, any_mac_form: bool = False):
    """The step observations of one session, in file order."""
    for ops in operations(path, session):
        e = ops[-1]
        if e["f"] not in STEP_FUNCS:
            continue
        n = e["line"]
        pre_label, pre_epoch = e["args"][0], e["args"][1]
        ret = e["ret"]
        st = {"line": n, "op": e["op"], "party": e["p"],
              "mac": mac_obs(ops, pre_epoch, any_mac_form)}
        if e["f"] == "States::send":
            if "err" in ret:
                raise SystemExit(f"line {n}: send returned an error")
            st.update(action="send", kind=VEIL_KINDS[ret["msg"]["kind"]],
                      rel="same", key=ret["key"] is not None,
                      label=VEIL_LABELS[ret["state"]], epoch=ret["epoch"])
        else:
            msg = e["args"][2]
            d = msg["epoch"] - pre_epoch
            rel = "older" if d < 0 else "same" if d == 0 else "next" if d == 1 else "later"
            st.update(kind=VEIL_KINDS[msg["kind"]], rel=rel)
            if "err" in ret:
                st.update(action="recvErr", key=False,
                          label=VEIL_LABELS[pre_label], epoch=pre_epoch)
            else:
                st.update(action="recv", key=ret["key"] is not None,
                          label=VEIL_LABELS[ret["state"]], epoch=ret["epoch"])
        st["pre"] = (VEIL_LABELS[pre_label], pre_epoch)
        yield st


def compress(sts):
    """Drop a step that repeats the previous kept step of its party and changes no state."""
    last = {}
    out = []
    for s in sts:
        sig = tuple(s[k] for k in ("action", "kind", "rel", "mac", "key", "label", "epoch"))
        loop = s["pre"] == (s["label"], s["epoch"])
        if loop and last.get(s["party"]) == sig:
            continue
        last[s["party"]] = sig if loop else None
        out.append(s)
    return out


# (state before, message type, state after) -> the arm of a same-epoch `receive` that acts
ARMS = {
    ("keysSampled", "kCt1", "headerSent"): "recv_t2",
    ("headerSent", "kCt1", "ct1Received"): "recv_t3",
    ("ct1Received", "kCt2", "ekSentCt1Received"): "recv_t4",
    ("ekSentCt1Received", "kCt2", "noHeaderReceived"): "recv_t5",
    ("noHeaderReceived", "kHdr", "headerReceived"): "recv_t6",
    ("ct1Sampled", "kEkCt1Ack", "ct1Acknowledged"): "recv_t8",
    ("ct1Sampled", "kEkCt1Ack", "ct2Sampled"): "recv_t9",
    ("ct1Sampled", "kEk", "ekReceivedCt1Sampled"): "recv_t10",
    ("ct1Acknowledged", "kEkCt1Ack", "ct2Sampled"): "recv_t11_ekct1ack",
    ("ct1Acknowledged", "kEk", "ct2Sampled"): "recv_t11_ek",
    ("ekReceivedCt1Sampled", "kEkCt1Ack", "ct2Sampled"): "recv_t12_ekct1ack",
    ("ekReceivedCt1Sampled", "kCt1Ack", "ct2Sampled"): "recv_t12_ct1ack",
}
DECODING = {("headerSent", "kCt1"), ("ekSentCt1Received", "kCt2"), ("noHeaderReceived", "kHdr"),
            ("ct1Sampled", "kEk"), ("ct1Acknowledged", "kEkCt1Ack"), ("ct1Acknowledged", "kEk")}
MAC_CHECK = {("ekSentCt1Received", "kCt2"), ("noHeaderReceived", "kHdr")}
EK_CHECK = {("ct1Sampled", "kEk"), ("ct1Sampled", "kEkCt1Ack"),
            ("ct1Acknowledged", "kEk"), ("ct1Acknowledged", "kEkCt1Ack")}


def arm(s) -> str:
    """The SpqrBraid action for a step. The choice reads the logged state after the step,
    which stands in for the decoder; Veil then checks the arm's conditions, and the `assert`
    checks the logged observation against what the arm does. A step that fits no arm gets
    the arm of a same-epoch message that the state ignores, which then fails in Veil."""
    pre, _ = s["pre"]
    if s["action"] == "send":
        return {"keysUnsampled": "send_t1", "headerReceived": "send_t7"}.get(pre, f"send_{pre}")
    k, r = s["kind"], s["rel"]
    if s["action"] == "recvErr":
        if r == "later" or (r == "next" and pre != "ct2Sampled"):
            return "err_future"
        if r == "same" and (pre, k) in MAC_CHECK:
            return "err_mac"
        if r == "same" and (pre, k) in EK_CHECK:
            return "err_ek"
        return "err_future"
    if r == "older":
        return "recv_older"
    if r == "next" and pre == "ct2Sampled":
        return "recv_t13"
    if s["pre"] == (s["label"], s["epoch"]):
        return "recv_chunk" if (pre, k) in DECODING else "recv_noop"
    return ARMS.get((pre, k, s["label"]), "recv_noop")


def assertion(s) -> str:
    p = PARTIES[s["party"]]
    key = "true" if s["key"] else "false"
    return (f"assert (lastParty = {p} ∧ lastKind = {s['kind']} ∧ lastRel = {s['rel']} ∧ "
            f"lastMac = {s['mac']} ∧ lastKey = {key} ∧ lab {p} = {s['label']} ∧ "
            f"ep {p} = {s['epoch']})")


def query(sts, name: str) -> str:
    body = []
    for s in sts:
        body.append(f"  -- line {s['line']}, party {s['party']}, op {s['op']}")
        body.append(f"  {arm(s)}")
        body.append(f"  {assertion(s)}")
    # An unsatisfiable query is reported as information, so that Lean exits 0 for both verdicts.
    return (f"set_option veil.violationIsError false in\nsat trace [{name}] {{\n"
            + "\n".join(body) + "\n}\n")


def start_states(sts, starts) -> dict:
    """Map each `i` in `starts` to the SpqrBraid state before step `i`, read from the log:
    each party's state and epoch after its last step, and the messages sent so far in an epoch
    at least the smaller of the two epochs. One pass over the steps.

    A receive checks `sent` only at the receiver's epoch, and epochs do not decrease, so the
    older messages cannot change the result of a query."""
    lab = {"A": "keysUnsampled", "B": "noHeaderReceived"}
    ep = {"A": 1, "B": 1}
    sent = set()
    want = set(starts)
    out = {}
    for i in range(max(want, default=-1) + 1):
        if i in want:
            low = min(ep.values())
            sent = {m for m in sent if m[2] >= low}
            out[i] = (dict(lab), dict(ep), sorted(sent))
        if i < len(sts):
            s = sts[i]
            lab[s["party"]], ep[s["party"]] = s["label"], s["epoch"]
            if s["action"] == "send":
                sent.add((PARTIES[s["party"]], s["kind"], s["pre"][1]))
    return out


def init_block(state) -> str:
    lab, ep, sent = state
    lines = ["after_init {",
             f"  lab P := if P = pA then {lab['A']} else {lab['B']}",
             f"  ep P := if P = pA then {ep['A']} else {ep['B']}"]
    lines += [f"  sent {p} {k} {e} := true" for p, k, e in sent]
    lines += ["  lastParty := pA", "  lastKind := kNone", "  lastRel := same",
              "  lastMac := absent", "  lastKey := false", "}"]
    return "\n".join(lines) + "\n"


def lean_file(q: str, state=None) -> str:
    """SpqrBraid.lean with the query `q` before `end SpqrBraid`, and, if `state` is given,
    an `after_init` that starts from that state instead of `InitAlice` / `InitBob`."""
    with open(MODEL) as f:
        model = f.read()
    if state is not None:
        a = model.index("after_init {")
        b = model.index("\n}\n", a) + 3
        model = model[:a] + init_block(state) + model[b:]
    head, sep, tail = model.rpartition("end SpqrBraid")
    assert sep, "SpqrBraid.lean must end with `end SpqrBraid`"
    return head + q + "\n" + sep + tail


def run(veil: str, sts, keep: str, tag: str, start: int = 0, length=None, state=None):
    """Run the query of steps start .. start + length, from `state`, the logged state before
    `start` (`start_states`; None starts from the initial state); return (satisfiable,
    seconds, output)."""
    if length is None:
        length = len(sts) - start
    path = os.path.join(keep, f"{tag}.lean")
    with open(path, "w") as f:
        f.write(lean_file(query(sts[start:start + length], tag), state))
    t = time.time()
    # A memory cap: an uncapped 30-step query used all the memory of the machine.
    cmd = ["systemd-run", "--user", "--scope", "-q", "-p", f"MemoryMax={MEM}",
           "-p", "MemorySwapMax=0", "lake", "lean", path]
    p = subprocess.run(cmd, cwd=veil, capture_output=True, text=True)
    out = p.stdout + p.stderr
    with open(path[:-5] + ".out", "w") as f:
        f.write(out)
    if p.returncode in (137, -9):
        raise SystemExit(f"{path}: killed at the memory cap {MEM}")
    if p.returncode != 0:
        raise SystemExit(f"Lean exited with {p.returncode} on {path}:\n{out[-3000:]}")
    if "Satisfying trace found" in out:
        return True, time.time() - t, out
    if "No satisfying trace exists" in out:
        return False, time.time() - t, out
    raise SystemExit(f"no verdict in the Lean output for {path}:\n{out[-3000:]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["query", "search", "check"], help="see above")
    ap.add_argument("trace", help="JSONL trace of the cargo feature `monitor`")
    ap.add_argument("--session", type=int, default=1, help="session to replay (default 1)")
    ap.add_argument("--steps", type=int, metavar="N", help="use only the first N kept steps")
    ap.add_argument("--veil", metavar="DIR",
                    help="built Veil checkout to run `lake lean` in (check, search)")
    ap.add_argument("--window", type=int, default=12,
                    help="steps per query (search; default 12)")
    ap.add_argument("--jobs", type=int, default=3,
                    help="queries at a time (search; default 3)")
    ap.add_argument("--keep", metavar="DIR", default="/tmp/veil-spike/q",
                    help="where to write the queries and Lean outputs (check, search; "
                         "default /tmp/veil-spike/q)")
    ap.add_argument("--any-mac-form", action="store_true",
                    help="count every MAC call as good (no byte check of its input)")
    a = ap.parse_args()
    if a.mode != "query" and not a.veil:
        ap.error(f"{a.mode} needs --veil")

    raw = list(steps(a.trace, a.session, a.any_mac_form))
    sts = compress(raw)
    if a.steps is not None:
        sts = sts[: a.steps]
    print(f"{len(raw)} steps, {len(sts)} kept", file=sys.stderr)

    if a.mode == "query":
        print(query(sts, "replay"))
        return

    # Absolute, because Lean runs with the Veil checkout as its working directory.
    a.keep = os.path.abspath(a.keep)
    os.makedirs(a.keep, exist_ok=True)
    if a.mode == "check":
        tag = f"check_{len(sts)}"
        ok, secs, _ = run(a.veil, sts, a.keep, tag)
        print(f"{len(sts)} steps: {'sat' if ok else 'unsat'} ({secs:.0f} s)")
        return
    # search: windows of `--window` steps, each from the logged state before it. Each window
    # is one query, so the first unsatisfiable window holds the first step with no model.
    tag = os.path.basename(os.path.dirname(os.path.abspath(a.trace))).replace("-", "_")
    if a.any_mac_form:
        tag += "_anymac"
    W = a.window
    starts = list(range(0, len(sts), W))
    # The logged state before each window; step 0 starts from the initial state.
    states = start_states(sts, starts)
    states[0] = None
    bad = None
    with ThreadPoolExecutor(a.jobs) as pool:
        for b in range(0, len(starts), a.jobs):
            batch = starts[b:b + a.jobs]
            res = list(pool.map(
                lambda i: run(a.veil, sts, a.keep, f"{tag}_w{i}", i, W, states[i]), batch))
            for i, (ok, secs, _) in zip(batch, res):
                print(f"steps {i}..{min(i + W, len(sts)) - 1}: {'sat' if ok else 'unsat'} "
                      f"({secs:.0f} s)", flush=True)
            fails = [i for i, (ok, _, _) in zip(batch, res) if not ok]
            if fails:
                bad = fails[0]
                break
    if bad is None:
        print(f"all {len(sts)} steps satisfiable")
        return
    lo, hi = 0, min(W, len(sts) - bad)  # length lo is sat, length hi is unsat
    while hi - lo > 1:
        mid = (lo + hi) // 2
        ok, secs, _ = run(a.veil, sts, a.keep, f"{tag}_w{bad}_{mid}", bad, mid, states[bad])
        print(f"steps {bad}..{bad + mid - 1}: {'sat' if ok else 'unsat'} ({secs:.0f} s)")
        lo, hi = (mid, hi) if ok else (lo, mid)
    s = sts[bad + hi - 1]
    print(f"first step with no model: step {bad + hi - 1}, line {s['line']}, party "
          f"{s['party']}, op {s['op']}, {arm(s)} {s['kind']} ({s['rel']}), state "
          f"{s['pre'][0]} epoch {s['pre'][1]} -> {s['label']} epoch {s['epoch']}, mac {s['mac']}")


if __name__ == "__main__":
    main()
