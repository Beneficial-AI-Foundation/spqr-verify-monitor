#!/usr/bin/env python3
"""Draw one session of an SPQR monitor trace as an SVG figure.

The trace is a JSONL file of the cargo feature `monitor` (`src/monitor.rs`). Two views:

  overview  the braid state of both parties over the whole session, one colored band per
            party, with epoch ticks, emitted keys and the operation the monitor rejected
  seq       a sequence diagram of a window of operations: one lifeline per party, a chip for
            each step, an arrow from each send to its receive, tampered and lost messages,
            and the monitor's diagnosis at the rejected step

The rejections come from a report of the Lean monitor (`lake env lean --run Monitor/Main.lean`),
passed with `--report`. The viewer checks nothing itself.

Examples (from the repository root):
  python3 scripts/trace-viewer.py overview T.jsonl --session 1 --report report.txt -o overview.svg
  python3 scripts/trace-viewer.py seq T.jsonl --report report.txt --around-reject A -o seq.svg
  python3 scripts/trace-viewer.py seq T.jsonl --from 0 --to 120 --hide-idle -o start.svg
"""

import argparse
import os
import re
import sys
from collections import deque
from html import escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spqr_trace import LABELS, STEP_FUNCS, operations, short_label  # noqa: E402

# Blues for the half that sends the encapsulation key, oranges for the half that sends the
# ciphertext.
COLORS = {
    "KeysUnsampled": "#dbe9f6", "KeysSampled": "#b5d3ee", "HeaderSent": "#86b6e0",
    "Ct1Received": "#5596cc", "EkSentCt1Received": "#2f6fae",
    "NoHeaderReceived": "#fde4c8", "HeaderReceived": "#fbc994", "Ct1Sampled": "#f6a95f",
    "EkReceivedCt1Sampled": "#ec8a3a", "Ct1Acknowledged": "#d86c1f", "Ct2Sampled": "#b4520e",
}
DARK = {"Ct1Received", "EkSentCt1Received", "Ct1Acknowledged", "Ct2Sampled",
        "EkReceivedCt1Sampled"}
RED = "#c62828"
GREY = "#9e9e9e"
FONT = "font-family='DejaVu Sans, Helvetica, Arial, sans-serif'"


def msg_key(m):
    """A key that identifies a message: (epoch, kind, chunk index, chunk data)."""
    if not m or m.get("kind") in (None, "none"):
        return None
    return (m.get("epoch"), m.get("kind"), m.get("index"), m.get("data"))


def msg_text(m):
    kind = m.get("kind")
    idx = m.get("index")
    return f"{kind} #{idx}" if idx is not None else kind


class Op:
    """One operation: its step event, its tamper event and the step summary `info`."""

    def __init__(self, events):
        self.n = events[0]["op"]
        self.party = events[0]["p"]
        self.step = None
        self.tamper = None
        for e in events:
            if e["f"] in STEP_FUNCS:
                self.step = e
            elif e["f"] == "tamper":
                self.tamper = e
        self.info = step_info(self.step)


def load(path, session):
    return [Op(events) for events in operations(path, session)]


def parse_report(path, trace, session):
    """Map party to (operation, diagnosis) for the rejections of `trace` in a monitor report."""
    rejects = {}
    if not path:
        return rejects
    want = os.path.realpath(trace)
    current = False
    pat = re.compile(r"^\s+session (\d+) party (\w+): REJECTED: (.*)$")
    with open(path) as f:
        for line in f:
            if not line.startswith(" ") and ": " in line and ".jsonl" in line:
                current = os.path.realpath(line.split(":")[0]) == want
                continue
            m = pat.match(line.rstrip("\n"))
            if not m or not current or int(m.group(1)) != session:
                continue
            text = m.group(3)
            o = re.search(r"operation (\d+)", text)
            diag = text.split(": ", 1)[1] if ": " in text else text
            rejects[m.group(2)] = (int(o.group(1)) if o else None, diag)
    return rejects


def step_info(e):
    """(pre label, post label, post epoch, key epoch or None, sent msg, received msg, error)
    of a step event, or None."""
    if e is None:
        return None
    ret = e.get("ret")
    if not isinstance(ret, dict):
        ret = {}
    pre = e["args"][0]
    err = ret.get("err")
    post = ret.get("state")
    epoch = ret.get("epoch")
    key = ret.get("key")
    kep = key.get("epoch") if isinstance(key, dict) else (epoch if key else None)
    sent = ret.get("msg") if e["f"] == "States::send" else None
    recv = e["args"][2] if e["f"] == "States::recv" and len(e["args"]) > 2 else None
    return pre, post, epoch, kep, sent, recv, err


def svg_text(x, y, s, size=11, anchor="start", fill="#222", weight="normal", extra=""):
    return (f"<text x='{x:.1f}' y='{y:.1f}' font-size='{size}' text-anchor='{anchor}' "
            f"fill='{fill}' font-weight='{weight}' {FONT} {extra}>{escape(str(s))}</text>")


def wrap(s, width):
    words, lines, cur = s.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width and cur:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def legend(x, y, cols=4):
    out = []
    for i, lab in enumerate(LABELS):
        cx = x + (i % cols) * 190
        cy = y + (i // cols) * 18
        out.append(f"<rect x='{cx}' y='{cy - 10}' width='14' height='12' rx='2' "
                   f"fill='{COLORS[lab]}' stroke='#555' stroke-width='0.5'/>")
        out.append(svg_text(cx + 19, cy, f"{lab} ({short_label(lab)})", 10))
    return out


def overview(ops, rejects, title):
    W, left, right = 1200, 70, 30
    span = W - left - right
    first, last = ops[0].n, ops[-1].n

    def x(n):
        return left + span * (n - first) / max(1, last - first)

    bands = {"A": 70, "B": 150}
    bh = 40
    out = [svg_text(left, 28, title, 15, weight="bold")]
    for party, y0 in bands.items():
        out.append(svg_text(left - 12, y0 + bh / 2 + 5, party, 15, "end", weight="bold"))
        pops = [o for o in ops if o.party == party and o.step is not None]
        rej = rejects.get(party, (None,))[0]
        runs = []  # (start op, label, epoch)
        for o in pops:
            pre, post, ep, *_, err = o.info
            if err:  # a failed receive leaves the state unchanged
                post, ep = pre, o.step["args"][1]
            if not runs or runs[-1][1] != post:
                runs.append((o.n, post, ep))
        for i, (a, lab, _) in enumerate(runs):
            nb = runs[i + 1][0] if i + 1 < len(runs) else last
            x0, x1 = x(a), max(x(nb), x(a) + 0.6)
            fill = COLORS.get(lab, "#eee")
            if rej is not None and a > rej:
                fill = "#e0e0e0"
            out.append(f"<rect x='{x0:.2f}' y='{y0}' width='{x1 - x0:.2f}' height='{bh}' "
                       f"fill='{fill}'/>")
        out.append(f"<rect x='{left}' y='{y0}' width='{span}' height='{bh}' fill='none' "
                   f"stroke='#555' stroke-width='0.6'/>")
        # epoch ticks
        last_ep, last_lx = None, -1e9
        for a, _, ep in runs:
            if ep != last_ep:
                xx = x(a)
                out.append(f"<line x1='{xx:.1f}' y1='{y0 - 4}' x2='{xx:.1f}' y2='{y0}' "
                           f"stroke='#333' stroke-width='0.8'/>")
                if xx - last_lx > 22:
                    out.append(svg_text(xx, y0 - 6, f"e{ep}", 8, "middle", "#333"))
                    last_lx = xx
                last_ep = ep
        # keys
        for o in pops:
            kep = o.info[3]
            if kep is not None:
                xx = x(o.n)
                yy = y0 + bh + 2
                out.append(f"<path d='M{xx:.1f},{yy} l-4,8 h8 z' fill='#f2b705' "
                           f"stroke='#7a5c00' stroke-width='0.5'/>")
        if rej is not None:
            xx = x(rej)
            out.append(f"<line x1='{xx:.1f}' y1='{y0 - 10}' x2='{xx:.1f}' y2='{y0 + bh + 10}' "
                       f"stroke='{RED}' stroke-width='3'/>")
            out.append(svg_text(min(xx + 5, W - 260), y0 + bh + 22,
                                f"REJECTED at operation {rej}", 11, fill=RED, weight="bold"))
    # axis
    ay = 240
    out.append(f"<line x1='{left}' y1='{ay}' x2='{left + span}' y2='{ay}' stroke='#555'/>")
    for i in range(6):
        n = first + (last - first) * i // 5
        out.append(f"<line x1='{x(n):.1f}' y1='{ay}' x2='{x(n):.1f}' y2='{ay + 4}' stroke='#555'/>")
        out.append(svg_text(x(n), ay + 16, n, 10, "middle"))
    out.append(svg_text(left + span / 2, ay + 32, "operation", 11, "middle"))
    out.append(f"<path d='M{left},{ay + 50} l-4,8 h8 z' fill='#f2b705' stroke='#7a5c00' "
               f"stroke-width='0.5'/>")
    out.append(svg_text(left + 10, ay + 58, "key emitted", 10))
    out.append(svg_text(left + 110, ay + 58, "e<n> epoch starts", 10))
    out += legend(left + 260, ay + 58)
    H = ay + 120
    y = H
    for party, (_, diag) in sorted(rejects.items()):
        for line in wrap(f"{party}: {diag}", 170):
            out.append(svg_text(left, y, line, 10, fill=RED))
            y += 14
        y += 4
    H = y + 10
    return (f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' "
            f"viewBox='0 0 {W} {H}'><rect width='100%' height='100%' fill='white'/>"
            + "".join(out) + "</svg>")


def match_messages(ops):
    """Map each send operation to its deliveries, a list of (receiving operation, tampered).

    Sends and receives are matched in file order. Each (sender, message) pair has a queue of
    sends that are not yet delivered, and a receive takes the oldest send of its message. A
    receive whose operation has a `tamper` event `[orig, copy]` got a tampered copy of `orig`;
    it is a tampered delivery of the oldest send of `orig`. When the code rejects the copy, the
    tamper driver (`src/test/orchestrator/tamper.rs`) later delivers the original, so that send
    stays in its queue.
    """
    pending, deliveries = {}, {}
    for o in ops:
        if o.info is None:
            continue
        _, _, _, _, sent, recv, err = o.info
        k = msg_key(sent)
        if k is not None:
            pending.setdefault((o.party, k), deque()).append(o.n)
            deliveries[o.n] = []
        tam = o.tamper is not None
        k = msg_key(o.tamper["args"][0] if tam else recv)
        q = pending.get(("B" if o.party == "A" else "A", k))
        if k is None or not q:
            continue
        deliveries[q[0]].append((o.n, tam))
        if not (tam and err):
            q.popleft()
    return deliveries


def compact_rows(rows, rejects, deliveries):
    """The rows of the `--compact` view, in order."""
    keep = set()
    for o in rows:
        pre, post, ep, kep, _, _, err = o.info
        rej = rejects.get(o.party, (None,))[0]
        if (o.n == rej or kep is not None or err or o.tamper or pre != post
                or o.step["args"][1] != ep):
            keep.add(o.n)
    # The sends whose message a kept receive got.
    for o in rows:
        if any(n in keep for n, _ in deliveries.get(o.n, [])):
            keep.add(o.n)
    return [o for o in rows if o.n in keep]


def seq(ops, rejects, title, lo, hi, hide_idle, max_rows, compact):
    deliveries = match_messages(ops)

    def visible(o):
        if o.step is None or not lo <= o.n <= hi:
            return False
        if hide_idle:
            pre, post, _, kep, sent, recv, err = o.info
            rej = rejects.get(o.party, (None,))[0]
            if o.n == rej or kep is not None or err:
                return True
            if o.step["f"] == "States::send" and msg_key(sent) is None:
                return False
            if o.step["f"] == "States::recv" and msg_key(recv) is None and pre == post:
                return False
        return True

    rows = [o for o in ops if visible(o)]
    if compact:
        rows = compact_rows(rows, rejects, deliveries)
    rows = rows[:max_rows]
    row_of = {o.n: i for i, o in enumerate(rows)}

    W = 860
    xs = {"A": 240, "B": 620}
    t0 = 40 if title else 0
    top, rh = 60 + t0, 26
    H = top + rh * len(rows) + 30
    out = [svg_text(20, 28, title, 15, weight="bold")] if title else []
    for p, xx in xs.items():
        out.append(f"<rect x='{xx - 45}' y='{t0 + 8}' width='90' height='28' rx='4' "
                   f"fill='#37474f'/>")
        out.append(svg_text(xx, t0 + 27, "Alice (A)" if p == "A" else "Bob (B)", 13, "middle",
                            "white", "bold"))
        out.append(f"<line x1='{xx}' y1='{t0 + 36}' x2='{xx}' y2='{H - 20}' stroke='#90a4ae' "
                   f"stroke-dasharray='4 3'/>")

    def y_of(i):
        return top + rh * i + rh / 2

    notes = []
    arrows = []
    for i, o in enumerate(rows):
        _, post, ep, kep, sent, _, err = o.info
        y = y_of(i)
        rej = rejects.get(o.party, (None,))[0]
        after = rej is not None and o.n > rej
        is_rej = rej is not None and o.n == rej
        if is_rej:
            out.append(f"<rect x='10' y='{y - rh / 2}' width='{W - 20}' height='{rh}' "
                       f"fill='#ffebee'/>")
        xx = xs[o.party]
        lab = post if not err else f"error: {err}"
        fill = "#eeeeee" if after else COLORS.get(lab, "#ffcdd2")
        if err:
            ep = None
        tcol = "white" if lab in DARK and not after else ("#777" if after else "#111")
        stroke = RED if is_rej else "#555"
        sw = 2.5 if is_rej else 0.6
        out.append(f"<rect x='{xx - 95}' y='{y - 10}' width='190' height='20' rx='3' "
                   f"fill='{fill}' stroke='{stroke}' stroke-width='{sw}'/>")
        out.append(svg_text(xx, y + 4.5, f"{lab} e{ep}" if ep is not None else lab, 12,
                            "middle", tcol))
        side = -1 if o.party == "A" else 1
        verb = "send" if o.step["f"] == "States::send" else "recv"
        out.append(svg_text(xx + side * 102, y + 4.5,
                            f"{verb} op {o.n}" if side < 0 else f"op {o.n} {verb}", 11,
                            "end" if side < 0 else "start", "#78909c"))
        if kep is not None:
            kx = xx + side * 205
            out.append(f"<circle cx='{kx}' cy='{y}' r='8' fill='#f2b705' stroke='#7a5c00'/>")
            out.append(svg_text(kx, y + 3.5, f"K{kep}", 8, "middle", "#3e2b00", "bold"))
        if is_rej:
            notes.append((i, o.party, rejects[o.party][1]))
        if o.n in deliveries:
            dst = "B" if o.party == "A" else "A"
            arrows.append((i, o.party, dst, deliveries[o.n], sent))
    for i, src, dst, dels, m in arrows:
        x0, x1 = xs[src], xs[dst]
        d = 1 if x1 > x0 else -1
        x0 += d * 95
        x1 -= d * 95
        y0 = y_of(i)
        label = msg_text(m)
        if not dels:
            xm = x0 + (x1 - x0) * 0.35
            out.append(f"<line x1='{x0}' y1='{y0}' x2='{xm:.1f}' y2='{y0 + 6}' "
                       f"stroke='{GREY}' stroke-width='1'/>"
                       f"<path d='M{xm - 4:.1f},{y0 + 2} l8,8 M{xm + 4:.1f},{y0 + 2} l-8,8' "
                       f"stroke='{GREY}' stroke-width='1.5'/>")
            out.append(svg_text(x0 + d * 6, y0 - 3, f"{label} (lost)", 10,
                                "start" if d > 0 else "end", GREY))
            continue
        labelled = False  # a send delivered twice (a rejected tampered copy, then the
        # original) gets two arrows and one label
        for rn, tam in dels:
            if rn not in row_of:
                continue
            y1 = y_of(row_of[rn])
            col = RED if tam else "#455a64"
            out.append(f"<line x1='{x0}' y1='{y0}' x2='{x1}' y2='{y1:.1f}' stroke='{col}' "
                       f"stroke-width='{1.6 if tam else 1}' "
                       f"marker-end='url(#ah{'r' if tam else ''})'/>")
            if not labelled:
                out.append(svg_text(x0 + d * 6, y0 - 3, label, 10, "start" if d > 0 else "end",
                                    col))
                labelled = True
            if tam:
                xm, ym = (x0 + x1) / 2, (y0 + y1) / 2
                out.append(f"<path d='M{xm - 6:.1f},{ym - 9:.1f} l9,7 l-5,1 l7,8 l-11,-6 l5,-1 "
                           f"z' fill='{RED}'/>")
                # Beside the mark, on the side of the sender, where the arrow is not.
                out.append(svg_text(xm - d * 12, ym + 4, "tampered in transit", 11,
                                    "end" if d > 0 else "start", RED, weight="bold"))
    for i, party, diag in notes:
        y = y_of(i) + 16
        lines = wrap(diag, 52)
        bx = 250
        bw = 360
        out.append(f"<rect x='{bx}' y='{y}' width='{bw}' height='{16 * len(lines) + 28}' rx='4' "
                   f"fill='white' stroke='{RED}' stroke-width='1.5'/>")
        out.append(svg_text(bx + 8, y + 15, f"Monitor: party {party} REJECTED here", 12, fill=RED,
                            weight="bold"))
        for j, line in enumerate(lines):
            out.append(svg_text(bx + 8, y + 34 + 16 * j, line, 11, fill="#333"))
        H = max(H, y + 16 * len(lines) + 44)
    defs = ("<defs><marker id='ah' markerWidth='8' markerHeight='8' refX='7' refY='4' "
            "orient='auto'><path d='M0,0 L8,4 L0,8 z' fill='#455a64'/></marker>"
            f"<marker id='ahr' markerWidth='8' markerHeight='8' refX='7' refY='4' orient='auto'>"
            f"<path d='M0,0 L8,4 L0,8 z' fill='{RED}'/></marker></defs>")
    return (f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' "
            f"viewBox='0 0 {W} {H}'>{defs}<rect width='100%' height='100%' fill='white'/>"
            + "".join(out) + "</svg>")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["overview", "seq"], help="the view to draw")
    ap.add_argument("trace", help="JSONL trace of the cargo feature `monitor`")
    ap.add_argument("--session", type=int, default=1, help="session to draw (default 1)")
    ap.add_argument("--report", help="output of the Lean monitor on this trace; without it, "
                                     "no rejection is shown")
    ap.add_argument("--title", help="figure title (default: trace file name and session; "
                                    "an empty title drops the title line in seq)")
    ap.add_argument("--from", dest="lo", type=int, default=0, metavar="OP",
                    help="first operation to draw (default 0)")
    ap.add_argument("--to", dest="hi", type=int, default=10**12, metavar="OP",
                    help="last operation to draw (default: the last one)")
    ap.add_argument("--around-reject", choices=["A", "B"],
                    help="seq: draw from RADIUS operations before to 6 operations after the "
                         "operation where this party was rejected; overrides --from and --to")
    ap.add_argument("--radius", type=int, default=30,
                    help="operations before the rejection for --around-reject (default 30)")
    ap.add_argument("--hide-idle", action="store_true",
                    help="seq: hide sends that emit no message, and receives of no message that "
                         "leave the state unchanged")
    ap.add_argument("--compact", action="store_true",
                    help="seq: keep only steps that change the state or epoch, emit a key, fail, "
                         "are rejected or receive a tampered message, and the sends whose "
                         "message a kept receive got")
    ap.add_argument("--max-rows", type=int, default=70,
                    help="seq: draw at most this many steps (default 70)")
    ap.add_argument("-o", "--output", default="-", help="SVG file (default: standard output)")
    a = ap.parse_args()
    ops = load(a.trace, a.session)
    if not ops:
        sys.exit(f"no operations for session {a.session} in {a.trace}")
    rejects = parse_report(a.report, a.trace, a.session)
    title = a.title if a.title is not None else f"{os.path.basename(a.trace)}, session {a.session}"
    if a.mode == "overview":
        ops = [o for o in ops if a.lo <= o.n <= a.hi]
        if not ops:
            sys.exit(f"no operations between {a.lo} and {a.hi}")
        svg = overview(ops, rejects, title)
    else:
        lo, hi = a.lo, a.hi
        if a.around_reject:
            r = rejects.get(a.around_reject)
            if not r or r[0] is None:
                sys.exit(f"party {a.around_reject} has no rejected operation in the report")
            lo, hi = r[0] - a.radius, r[0] + 6
        svg = seq(ops, rejects, title, lo, hi, a.hide_idle, a.max_rows, a.compact)
    if a.output == "-":
        sys.stdout.write(svg)
    else:
        with open(a.output, "w") as f:
            f.write(svg)

if __name__ == "__main__":
    main()
