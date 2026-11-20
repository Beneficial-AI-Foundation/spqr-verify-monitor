#!/usr/bin/env python3
"""Draw SPQR monitor traces as SVG.

Two views of one session of a JSONL trace (the format of `src/monitor.rs`):

  overview  the braid state of both parties over the whole session, one colored band per
            party, with epoch ticks, emitted keys and the operation the monitor rejected
  seq       a sequence diagram of a window of operations: one lifeline per party, a chip for
            each step, an arrow from each send to its receive, tampered and dropped messages,
            and the monitor's diagnosis at the rejected step

The verdicts come from a report of the Lean monitor (`lake env lean --run Monitor/Main.lean`),
passed with `--report`. The viewer does not check anything itself.

Examples:
  trace-viewer.py overview T.jsonl --session 1 --report report.txt -o overview.svg
  trace-viewer.py seq T.jsonl --session 1 --report report.txt --around-reject A --radius 30 -o seq.svg
  trace-viewer.py seq T.jsonl --session 1 --from 0 --to 120 --hide-idle -o start.svg
"""

import argparse
import json
import os
import re
import sys
from html import escape

LABELS = [
    "KeysUnsampled", "KeysSampled", "HeaderSent", "Ct1Received", "EkSentCt1Received",
    "NoHeaderReceived", "HeaderReceived", "Ct1Sampled", "EkReceivedCt1Sampled",
    "Ct1Acknowledged", "Ct2Sampled",
]
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


def short(label):
    return re.sub(r"[a-z]", "", label) if label else "?"


def msg_key(m):
    if not m or m.get("kind") in (None, "none"):
        return None
    return (m.get("epoch"), m.get("kind"), m.get("index"), m.get("data"))


def msg_text(m):
    kind = m.get("kind")
    idx = m.get("index")
    return f"{kind} #{idx}" if idx is not None else kind


class Op:
    def __init__(self, n, party):
        self.n = n
        self.party = party
        self.step = None
        self.calls = 0
        self.tamper = None


def load(path, session):
    ops = {}
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("s") != session or e.get("op", 0) == 0:
                continue
            op = ops.setdefault(e["op"], Op(e["op"], e["p"]))
            if e["f"] in ("States::send", "States::recv"):
                op.step = e
            elif e["f"] == "tamper":
                op.tamper = e
            else:
                op.calls += 1
    return [ops[k] for k in sorted(ops)]


def parse_report(path, trace, session):
    """Map party to (operation, diagnosis) for the rejections of `trace` in a monitor report."""
    rejects = {}
    if not path:
        return rejects
    current = None
    pat = re.compile(r"^\s+session (\d+) party (\w+): REJECTED: (.*)$")
    with open(path) as f:
        for line in f:
            if not line.startswith(" ") and ": " in line and ".jsonl" in line:
                current = line.split(":")[0]
                continue
            m = pat.match(line.rstrip("\n"))
            if not m or current is None or os.path.realpath(current) != os.path.realpath(trace):
                continue
            if int(m.group(1)) != session:
                continue
            text = m.group(3)
            o = re.search(r"operation (\d+)", text)
            diag = text.split(": ", 1)[1] if ": " in text else text
            rejects[m.group(2)] = (int(o.group(1)) if o else None, diag, text)
    return rejects


def step_info(op):
    """(pre label, post label, post epoch, key epoch or None, sent msg, received msg, error)."""
    e = op.step
    if e is None:
        return None
    ret = e.get("ret") or {}
    pre = e["args"][0]
    err = ret.get("err") if isinstance(ret, dict) else None
    post = ret.get("state") if isinstance(ret, dict) else None
    epoch = ret.get("epoch") if isinstance(ret, dict) else None
    key = ret.get("key") if isinstance(ret, dict) else None
    kep = key.get("epoch") if isinstance(key, dict) else (epoch if key else None)
    sent = ret.get("msg") if e["f"] == "States::send" and isinstance(ret, dict) else None
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
        out.append(svg_text(cx + 19, cy, f"{lab} ({short(lab)})", 10))
    return out


def overview(ops, rejects, title):
    W, left, right = 1200, 70, 30
    span = W - left - right
    first, last = ops[0].n, ops[-1].n
    x = lambda n: left + span * (n - first) / max(1, last - first)
    bands = {"A": 70, "B": 150}
    bh = 40
    out = [svg_text(left, 28, title, 15, weight="bold")]
    for party, y0 in bands.items():
        out.append(svg_text(left - 12, y0 + bh / 2 + 5, party, 15, "end", weight="bold"))
        pops = [o for o in ops if o.party == party and o.step is not None]
        rej = rejects.get(party, (None,))[0]
        runs = []  # (start op, end op, label, epoch)
        for o in pops:
            _, post, ep, *_ = step_info(o)
            if runs and runs[-1][2] == post:
                runs[-1][1] = o.n
            else:
                runs.append([o.n, o.n, post, ep])
        for i, (a, b, lab, ep) in enumerate(runs):
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
        for a, b, lab, ep in runs:
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
            kep = step_info(o)[3]
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
    for party, (rop, diag, _) in sorted(rejects.items()):
        for line in wrap(f"{party}: {diag}", 170):
            out.append(svg_text(left, y, line, 10, fill=RED))
            y += 14
        y += 4
    H = y + 10
    return (f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' "
            f"viewBox='0 0 {W} {H}'><rect width='100%' height='100%' fill='white'/>"
            + "".join(out) + "</svg>")


def compact_rows(rows, rejects, recv_at, tampered):
    """The rows of the `--compact` view, in order."""
    keep = set()
    for o in rows:
        pre, post, ep, kep, sent, recv, err = step_info(o)
        rej = rejects.get(o.party, (None,))[0]
        if (o.n == rej or kep is not None or err or o.tamper or pre != post
                or o.step["args"][1] != ep):
            keep.add(o.n)
    # The sends whose message a kept receive got.
    for o in rows:
        k = msg_key(step_info(o)[4])
        if k is None:
            continue
        if any(n in keep for n in recv_at.get((o.party, k), []) if n > o.n):
            keep.add(o.n)
    return [o for o in rows if o.n in keep]


def seq(ops, rejects, title, lo, hi, hide_idle, max_rows, compact):
    # Match each send to its receive (tampered messages via the tamper events).
    sent_at, recv_at, tampered = {}, {}, {}
    for o in ops:
        info = step_info(o)
        if info is None:
            continue
        if o.tamper:
            orig, new = o.tamper["args"]
            tampered[msg_key(new)] = msg_key(orig)
        k = msg_key(info[4])
        if k is not None:
            sent_at.setdefault((o.party, k), []).append(o.n)
        k = msg_key(info[5])
        if k is not None:
            src = "B" if o.party == "A" else "A"
            k = tampered.get(k, k)
            recv_at.setdefault((src, k), []).append(o.n)

    def visible(o):
        if o.step is None or not lo <= o.n <= hi:
            return False
        if hide_idle:
            pre, post, ep, kep, sent, recv, err = step_info(o)
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
        rows = compact_rows(rows, rejects, recv_at, tampered)
    if len(rows) > max_rows:
        rows = rows[:max_rows]
    row_of = {o.n: i for i, o in enumerate(rows)}

    W = 1100
    xs = {"A": 260, "B": 840}
    top, rh = 90, 24
    H = top + rh * len(rows) + 40
    out = [svg_text(30, 30, title, 15, weight="bold")]
    for p, xx in xs.items():
        out.append(f"<rect x='{xx - 40}' y='42' width='80' height='26' rx='4' fill='#37474f'/>")
        out.append(svg_text(xx, 60, "Alice (A)" if p == "A" else "Bob (B)", 12, "middle",
                            "white", "bold"))
        out.append(f"<line x1='{xx}' y1='68' x2='{xx}' y2='{H - 30}' stroke='#90a4ae' "
                   f"stroke-dasharray='4 3'/>")
    y_of = lambda i: top + rh * i + rh / 2
    notes = []
    arrows = []
    for i, o in enumerate(rows):
        pre, post, ep, kep, sent, recv, err = step_info(o)
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
        out.append(f"<rect x='{xx - 80}' y='{y - 9}' width='160' height='18' rx='3' "
                   f"fill='{fill}' stroke='{stroke}' stroke-width='{sw}'/>")
        out.append(svg_text(xx, y + 4, f"{lab} e{ep}" if ep is not None else lab, 10,
                            "middle", tcol))
        side = -1 if o.party == "A" else 1
        out.append(svg_text(xx + side * 88, y + 4, f"op {o.n}", 9,
                            "end" if side < 0 else "start", "#78909c"))
        verb = "send" if o.step["f"] == "States::send" else "recv"
        out.append(svg_text(xx + side * 135, y + 4, verb, 9, "end" if side < 0 else "start",
                            "#78909c"))
        if kep is not None:
            kx = xx + side * 172
            out.append(f"<circle cx='{kx}' cy='{y}' r='8' fill='#f2b705' stroke='#7a5c00'/>")
            out.append(svg_text(kx, y + 3.5, f"K{kep}", 8, "middle", "#3e2b00", "bold"))
        if is_rej:
            notes.append((i, o.party, rejects[o.party][1]))
        k = msg_key(sent)
        if k is not None:
            dst = "B" if o.party == "A" else "A"
            later = [n for n in recv_at.get((o.party, k), []) if n > o.n]
            arrows.append((i, o.party, dst, later[0] if later else None, sent, k))
    for i, src, dst, rn, m, k in arrows:
        x0, x1 = xs[src], xs[dst]
        d = 1 if x1 > x0 else -1
        x0 += d * 80
        x1 -= d * 80
        y0 = y_of(i)
        label = msg_text(m)
        tam = k in tampered.values()
        if rn is None:
            xm = x0 + (x1 - x0) * 0.35
            arrows_svg = (f"<line x1='{x0}' y1='{y0}' x2='{xm:.1f}' y2='{y0 + 6}' "
                          f"stroke='{GREY}' stroke-width='1'/>"
                          f"<path d='M{xm - 4:.1f},{y0 + 2} l8,8 M{xm + 4:.1f},{y0 + 2} l-8,8' "
                          f"stroke='{GREY}' stroke-width='1.5'/>")
            out.append(arrows_svg)
            out.append(svg_text(x0 + d * 6, y0 - 3, f"{label} (lost)", 8,
                                "start" if d > 0 else "end", GREY))
            continue
        if rn not in row_of:
            continue
        y1 = y_of(row_of[rn])
        dash = ""
        col = RED if tam else "#455a64"
        out.append(f"<line x1='{x0}' y1='{y0}' x2='{x1}' y2='{y1:.1f}' stroke='{col}' "
                   f"stroke-width='{1.6 if tam else 1}' marker-end='url(#ah{'r' if tam else ''})'"
                   f"{dash}/>")
        out.append(svg_text(x0 + d * 6, y0 - 3, label, 8, "start" if d > 0 else "end", col))
        if tam:
            xm, ym = (x0 + x1) / 2, (y0 + y1) / 2
            out.append(f"<path d='M{xm - 6:.1f},{ym - 9:.1f} l9,7 l-5,1 l7,8 l-11,-6 l5,-1 z' "
                       f"fill='{RED}'/>")
            out.append(svg_text(xm + 10, ym - 4, "tampered in transit", 9, fill=RED,
                                weight="bold"))
    for i, party, diag in notes:
        y = y_of(i) + 16
        lines = wrap(diag, 70)
        bx = 360
        bw = 380
        out.append(f"<rect x='{bx}' y='{y}' width='{bw}' height='{14 * len(lines) + 24}' rx='4' "
                   f"fill='white' stroke='{RED}' stroke-width='1.5'/>")
        out.append(svg_text(bx + 8, y + 15, f"Monitor: party {party} REJECTED here", 10, fill=RED,
                            weight="bold"))
        for j, line in enumerate(lines):
            out.append(svg_text(bx + 8, y + 30 + 14 * j, line, 9, fill="#333"))
        H = max(H, y + 14 * len(lines) + 40)
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
    ap.add_argument("mode", choices=["overview", "seq"])
    ap.add_argument("trace")
    ap.add_argument("--session", type=int, default=1)
    ap.add_argument("--report", help="output of the Lean monitor on this trace")
    ap.add_argument("--title")
    ap.add_argument("--from", dest="lo", type=int, default=0)
    ap.add_argument("--to", dest="hi", type=int, default=10**12)
    ap.add_argument("--around-reject", choices=["A", "B"],
                    help="center the window on the operation where this party was rejected")
    ap.add_argument("--radius", type=int, default=30)
    ap.add_argument("--hide-idle", action="store_true",
                    help="hide sends that emit no message")
    ap.add_argument("--compact", action="store_true",
                    help="keep only steps that change state, emit a key, fail, are rejected or "
                         "tampered, and the sends that the kept receives got their message from")
    ap.add_argument("--max-rows", type=int, default=70)
    ap.add_argument("-o", "--output", default="-")
    a = ap.parse_args()
    ops = load(a.trace, a.session)
    if not ops:
        sys.exit(f"no operations for session {a.session} in {a.trace}")
    rejects = parse_report(a.report, a.trace, a.session)
    title = a.title or f"{a.trace.split('/')[-1]}, session {a.session}"
    if a.mode == "overview":
        svg = overview([o for o in ops if a.lo <= o.n <= a.hi], rejects, title)
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
