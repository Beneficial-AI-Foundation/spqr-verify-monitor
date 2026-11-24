"""Shared definitions for the scripts that read SPQR monitor traces.

A trace is a JSONL file written by the cargo feature `monitor` (`src/monitor.rs`). Each line is
one event `{s, p, op, f, args, ret}`: session, party (`A` or `B`), operation number, function
name, arguments and result. Within a session, operations are numbered 0, 1, 2, ... in file
order, and every operation other than 0 (the initialization) belongs to one party. The Lean
monitor (`Monitor/Main.lean`) rejects a trace that breaks these two rules. An operation of the
code under test ends with its step event (`States::send` or `States::recv`).

This module is imported by `scripts/trace-viewer.py`, `scripts/uppaal/spqr_uppaal.py` and
`viz/veil/trace2veil.py`. Run as a command, it reads a Lean monitor report (`main`):
`verdict REPORT TRACE PARTY` and `last-reject REPORT TRACE [PARTY]`, used by
`scripts/viz-compare.sh` and `scripts/monitor-figures.sh`.
"""

import decimal
import json
import os
import re
import sys

# The eleven `Label` constructors of the braid, in the order of `BraidModel`.
LABELS = [
    "KeysUnsampled", "KeysSampled", "HeaderSent", "Ct1Received", "EkSentCt1Received",
    "NoHeaderReceived", "HeaderReceived", "Ct1Sampled", "EkReceivedCt1Sampled",
    "Ct1Acknowledged", "Ct2Sampled",
]

# The message kinds of a trace. A trace logs a `Ct1Ack(false)` payload as `ct1ackfalse`; the
# Lean monitor reads it as `none` (`Monitor/Trace.lean`).
KINDS = ["none", "hdr", "ek", "ekct1ack", "ct1ack", "ct1", "ct2"]
KIND_ALIASES = {"ct1ackfalse": "none"}

STEP_FUNCS = ("States::send", "States::recv")

# The MAC inputs (§2.4): PROTOCOL_INFO, a label, the epoch as 8 big-endian bytes, then the
# header (MacHdr) or ct1 || ct2 (MacCt).
PROTOCOL_INFO = b"Signal_PQCKA_V1_MLKEM768"
HDR_LABEL = b":ekheader"
CT_LABEL = b":ciphertext"
HDR_SIZE = 64
CT1_SIZE = 960
CT2_SIZE = 128


def short_label(label):
    """The initials of a label, for example `ESC1R` for `EkSentCt1Received`."""
    return re.sub(r"[a-z]", "", label)


def mac_input(label, epoch, body):
    """The MAC input of §2.4 for `label` (HDR_LABEL or CT_LABEL), `epoch` and `body`."""
    return PROTOCOL_INFO + label + epoch.to_bytes(8, "big") + body


def operations(path, session=None, max_op=None):
    """Yield the operations of one session of the trace at `path`, in file order, up to
    operation `max_op` if given.

    Each operation is the list of its events. Each event gets a key `line` with its line number
    in the file. Operation 0 is skipped. Every event up to the last yielded operation must pass
    `check_event`, and in each session the operation numbers must start at 0 and grow by at most
    1, as the Lean monitor requires; an operation is yielded before the events after it are
    checked. With `session=None`, the session of the first event is used. The file is read
    once, line by line.
    """
    group, group_op = [], None
    last = {}   # the last operation number of each session
    with open(path) as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            e = json.loads(line, parse_float=number)
            ours = isinstance(e, dict) and (session is None or e.get("s") == session)
            if ours and group and e.get("op") != group_op:
                yield group   # the operation is complete
                group = []
            if ours and max_op is not None and isinstance(e.get("op"), int) and e["op"] > max_op:
                return
            check_event(e, n)
            if session is None:
                session = e["s"]
            prev = last.get(e["s"], 0)
            if e["op"] not in (prev, prev + 1):
                raise SystemExit(f"line {n}: operation {e['op']} after operation {prev}")
            last[e["s"]] = e["op"]
            if e["s"] != session or e["op"] == 0:
                continue
            group_op = e["op"]
            e["line"] = n
            group.append(e)
    if group:
        yield group


def number(s):
    """A JSON number with a fraction or exponent, such as `1e0`: an int if its value is an
    integer, as the Lean reader reads it, else a float."""
    d = decimal.Decimal(s)
    return int(d) if d == d.to_integral_value() else float(s)


def _nat(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def _hex(x):
    return isinstance(x, str) and len(x) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", x) is not None


def check_event(e, n):
    """Stop with an error unless the event `e` on line `n` has the fields that the Lean
    monitor's reader requires: natural `s` and `op`, party `A` or `B`, a string `f`, an array
    `args` and a `ret`, and `init` only in operation 0."""
    if not (isinstance(e, dict) and _nat(e.get("s")) and _nat(e.get("op"))
            and e.get("p") in ("A", "B") and isinstance(e.get("f"), str)
            and isinstance(e.get("args"), list) and "ret" in e):
        raise SystemExit(f"line {n}: not an event of the monitor log")
    if e["f"] == "init" and e["op"] != 0:
        raise SystemExit(f"line {n}: an init event in operation {e['op']}")


def check_msg(m):
    """Whether `m` is a message as the Lean reader parses it: a natural `epoch`, a known
    `kind`, and for a chunk kind a natural `index` and hex `data`."""
    if not (isinstance(m, dict) and _nat(m.get("epoch"))):
        return False
    k = m.get("kind")
    if k in ("none", "ct1ackfalse", "ct1ack"):
        return True
    return k in KINDS and _nat(m.get("index")) and _hex(m.get("data"))


def check_result(r):
    """Whether `r` is a step result: a key (null or a natural `epoch` and hex `secret`), a
    known `state` and a natural `epoch`."""
    if not (isinstance(r, dict) and all(f in r for f in ("key", "state", "epoch"))):
        return False
    k = r["key"]
    key_ok = k is None or (isinstance(k, dict) and _nat(k.get("epoch")) and _hex(k.get("secret")))
    return key_ok and r["state"] in LABELS and _nat(r["epoch"])


def check_operation(ops):
    """Stop with an error unless the operation `ops` (from `operations`) is well formed, by the
    rules of the Lean monitor's reader: all its events have one party; it has exactly one step
    event, at its end, with the state and epoch before the call; a receive has a well-formed
    message (`check_msg`); and the result is either an error string with no `key`, `state` or
    `epoch` (not for a send), or a result (`check_result`), with a well-formed message for a
    send."""
    where = f"op {ops[0]['op']} (line {ops[0]['line']})"
    if len({e["p"] for e in ops}) != 1:
        raise SystemExit(f"{where}: events of two parties")
    if ops[-1]["f"] not in STEP_FUNCS or sum(e["f"] in STEP_FUNCS for e in ops) != 1:
        raise SystemExit(f"{where}: an operation needs exactly one step event, at its end")
    st = ops[-1]
    a, r = st["args"], st["ret"]
    if not (len(a) >= 2 and a[0] in LABELS and _nat(a[1])):
        raise SystemExit(f"{where}: the step has no state and epoch before the call")
    if not isinstance(r, dict):
        raise SystemExit(f"{where}: the step result is not an object")
    if st["f"] == "States::recv" and not (len(a) >= 3 and check_msg(a[2])):
        raise SystemExit(f"{where}: the receive has no well-formed message")
    if "err" in r:
        if st["f"] == "States::send":
            raise SystemExit(f"{where}: the send returned an error")
        if not isinstance(r["err"], str):
            raise SystemExit(f"{where}: the error is not a string")
        if any(f in r for f in ("key", "state", "epoch")):
            raise SystemExit(f"{where}: an error and a result")
        return
    if not check_result(r):
        raise SystemExit(f"{where}: the step result has no well-formed key, state and epoch")
    if st["f"] == "States::send" and not check_msg(r.get("msg")):
        raise SystemExit(f"{where}: the send has no well-formed message")


def op_at_line(path, n):
    """The operation of the event on line `n` of the trace at `path`, or None."""
    with open(path) as f:
        for i, line in enumerate(f, 1):
            if i == n:
                return json.loads(line, parse_float=number)["op"] if line.strip() else None
    return None


def rejected_at(text, path):
    """(operation, line) of a monitor rejection diagnosis `text`: the operation from
    `operation N`, else from the event on its `line N` in the trace at `path`; each None if the
    diagnosis does not give it."""
    o = re.search(r"operation (\d+)", text)
    ln = re.search(r"line (\d+)", text)
    line = int(ln.group(1)) if ln else None
    if o:
        return int(o.group(1)), line
    return (op_at_line(path, line) if line else None), line


def report_rejects(report, trace, session=1):
    """Map party to its row text ("ACCEPTED ..." or "REJECTED: ...") for session `session` of
    `trace` in a Lean monitor report."""
    want = os.path.realpath(trace)
    current, rows = False, {}
    pat = re.compile(r"^\s+session (\d+) party (\w+): (.*)$")
    with open(report) as f:
        for line in f:
            if not line.startswith(" ") and ".jsonl: " in line:
                current = os.path.realpath(line.split(": ")[0]) == want
                continue
            m = pat.match(line.rstrip("\n"))
            if current and m and int(m.group(1)) == session:
                rows[m.group(2)] = m.group(3)
    return rows


def main(argv):
    """`verdict REPORT TRACE PARTY` prints "accepted", "OP LINE" (LINE is - when the report
    gives none) or "rejected" (no operation); nothing if the party has no row.
    `last-reject REPORT TRACE [PARTY]` prints the largest rejected operation of session 1, of
    PARTY if given, or 0."""
    cmd, report, trace = argv[0], argv[1], argv[2]
    rows = report_rejects(report, trace)
    if cmd == "verdict":
        row = rows.get(argv[3])
        if row is None:
            return
        if row.startswith("ACCEPTED"):
            print("accepted")
            return
        op, line = rejected_at(row, trace)
        print("rejected" if op is None else f"{op} {line if line else '-'}")
    elif cmd == "last-reject":
        ops = [rejected_at(r, trace)[0] for p, r in rows.items()
               if r.startswith("REJECTED") and (len(argv) < 4 or p == argv[3])]
        print(max([o for o in ops if o is not None], default=0))
    else:
        raise SystemExit(f"unknown command {cmd}")


if __name__ == "__main__":
    main(sys.argv[1:])
