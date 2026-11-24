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
import re

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
