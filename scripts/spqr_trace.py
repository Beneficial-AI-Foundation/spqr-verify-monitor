"""Shared definitions for the scripts that read SPQR monitor traces.

A trace is a JSONL file written by the cargo feature `monitor` (`src/monitor.rs`). Each line is
one event `{s, p, op, f, args, ret}`: session, party (`A` or `B`), operation number, function
name, arguments and result. Within a session, operations are numbered 0, 1, 2, ... in file
order, and every operation other than 0 (the initialization) belongs to one party. The Lean
monitor (`Monitor/Main.lean`) rejects a trace that breaks these two rules. An operation of the
code under test ends with its step event (`States::send` or `States::recv`).

This module is imported by `scripts/trace-viewer.py`, `scripts/uppaal/spqr_uppaal.py` and
`viz/veil/trace2veil.py`. It is not a command.
"""

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


def operations(path, session=None):
    """Yield the operations of one session of the trace at `path`, in file order.

    Each operation is the list of its events. Each event gets a key `line` with its line number
    in the file. Operation 0 is skipped. With `session=None`, the session of the first event is
    used. The file is read once, line by line.
    """
    group, group_op = [], None
    with open(path) as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            if session is None:
                session = e["s"]
            if e["s"] != session or e["op"] == 0:
                continue
            if e["op"] != group_op and group:
                yield group
                group = []
            group_op = e["op"]
            e["line"] = n
            group.append(e)
    if group:
        yield group


def op_at_line(path, n):
    """The operation of the event on line `n` of the trace at `path`, or None."""
    with open(path) as f:
        for i, line in enumerate(f, 1):
            if i == n:
                return json.loads(line)["op"] if line.strip() else None
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
