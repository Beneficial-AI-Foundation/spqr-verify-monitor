#!/usr/bin/env python3
"""UPPAAL model of the ML-KEM Braid and trace observers for SPQR monitor logs.

The model follows `Spqr/Specs/Braid/StateMachine/Model.lean` (`send`, `receive`,
`receiveEq`) over abstract data:

- epochs are bounded integers (1..EMAX);
- a message is (epoch, kind); chunk indices and bytes are dropped;
- the decoders, the MACs and the `ek` check are one token per step:
  NONE (no decoder or check), PART (decoder has no message yet),
  OK (decoder complete and the check passes), BAD (the check fails),
  MISS (the call the model needs is missing, or its input is not the
  model's formula). The script computes the token from the trace.

Subcommands:

  model OUT.xml
      The free model: Alice, Bob and a network that can deliver any sent
      message (loss, duplication, reordering). For the simulator.

  trace TRACE.jsonl OUT.xml [--max-ops N] [--party A|B] [--drop-idle]
                            [--data control|calls|formula]
      The model plus an observer that replays the trace step by step.
      Location `step_k` of the observer means k steps matched.

  check TRACE.jsonl [same options] [--workdir DIR]
      Generate, run verifyta, print the largest matched k and the step
      after it, and write the witness trace of the longest prefix.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from xml.sax.saxutils import escape

VERIFYTA = os.environ.get("VERIFYTA", "/opt/uppaal/lib/app/bin/verifyta.sh")

EMAX = 8

LABELS = ["KeysUnsampled", "KeysSampled", "HeaderSent", "Ct1Received",
          "EkSentCt1Received", "NoHeaderReceived", "HeaderReceived",
          "Ct1Sampled", "EkReceivedCt1Sampled", "Ct1Acknowledged", "Ct2Sampled"]
SHORT = ["KU", "KS", "HS", "C1R", "ESC1R", "NHR", "HR", "C1S", "ERC1S", "C1A", "C2S"]
LAB = {n: i for i, n in enumerate(LABELS)}

KINDS = ["none", "hdr", "ek", "ekct1ack", "ct1ack", "ct1", "ct2"]
KIND = {k: i for i, k in enumerate(KINDS)}
KIND["ct1ackfalse"] = KIND["none"]

T_NONE, T_PART, T_OK, T_BAD, T_MISS = range(5)
TOK_NAMES = ["T_NONE", "T_PART", "T_OK", "T_BAD", "T_MISS"]
SEND, RECV, RECV_ERR = range(3)
DIR_NAMES = ["SEND", "RECV", "RECV_ERR"]

PROTOCOL_INFO = b"Signal_PQCKA_V1_MLKEM768"
CT2_SIZE = 128
HDR_SIZE = 64

# --------------------------------------------------------------------------
# Model


def declarations(trace_mode, check_delivery):
    return f"""// ML-KEM Braid (Model.lean) over abstract data. See scripts/uppaal/README.md.
const bool TRACE = {"true" if trace_mode else "false"};   // an observer drives the steps
const bool CHECK_DELIVERY = {"true" if check_delivery else "false"}; // receive only sent messages

const int A = 0;
const int B = 1;
const int EMAX = {EMAX};
typedef int[0, EMAX + 1] epoch_t;

// states (Label)
{chr(10).join(f"const int {s} = {i};  // {l}" for i, (s, l) in enumerate(zip(SHORT, LABELS)))}
// receive outcomes besides a target state
const int STAY = -1;     // state unchanged
const int FAIL = -2;     // Receive() returns none
const int INVALID = -3;  // no model step (token does not fit)

// payload kinds (Payload)
{chr(10).join(f"const int K_{k.upper()} = {i};" for i, k in enumerate(KINDS))}
typedef int[0, {len(KINDS) - 1}] kind_t;

// data tokens
{chr(10).join(f"const int {n} = {i};" for i, n in enumerate(TOK_NAMES))}
typedef int[0, 4] tok_t;

// step directions
const int SEND = 0;
const int RECV = 1;
const int RECV_ERR = 2;

// party state, readable by the observer
int st[2] = {{KU, NHR}};
epoch_t ep[2] = {{1, 1}};
epoch_t key[2];          // epoch of the key output by the last step, 0 for none

// network: which (epoch, kind) each party sent
bool sent[2][EMAX + 2][{len(KINDS)}];
int[0, 1] d_p;           // message being delivered
epoch_t d_ep;
kind_t d_kind;

// the step the observer expects next
bool pending;
int[0, 1] e_party;
int[0, 2] e_dir;
kind_t e_kind;
epoch_t e_ep;
tok_t e_tok;
int matched;             // number of trace steps matched

// one channel per message kind for sends, one delivery channel per receiver
chan none_[2], hdr[2], ek[2], ekct1ack[2], ct1ack[2], ct1[2], ct2[2];
chan deliver[2];

// Receive() (with receiveEq) on the abstract state. t is the data token.
int next(int l, int e, int me, int mk, int t) {{
    if (l == C2S) {{
        if (me == e + 1) return t == T_NONE ? KU : INVALID;     // (13)
        if (me > e) return t == T_NONE ? FAIL : INVALID;
        return t == T_NONE ? STAY : INVALID;
    }}
    if (me > e) return t == T_NONE ? FAIL : INVALID;
    if (me < e) return t == T_NONE ? STAY : INVALID;
    if (l == KS && mk == K_CT1) return t == T_NONE ? HS : INVALID;            // (2)
    if (l == HS && mk == K_CT1)                                                 // (3)
        return t == T_OK ? C1R : t == T_PART ? STAY : INVALID;
    if (l == C1R && mk == K_CT2) return t == T_NONE ? ESC1R : INVALID;        // (4)
    if (l == ESC1R && mk == K_CT2)                                              // (5) MAC
        return t == T_OK ? NHR : t == T_PART ? STAY : t == T_BAD ? FAIL : INVALID;
    if (l == NHR && mk == K_HDR)                                                // (6) MAC
        return t == T_OK ? HR : t == T_PART ? STAY : t == T_BAD ? FAIL : INVALID;
    if (l == C1S && mk == K_EK)                                                 // (10) ek
        return t == T_OK ? ERC1S : t == T_PART ? STAY : t == T_BAD ? FAIL : INVALID;
    if (l == C1S && mk == K_EKCT1ACK)                                           // (8), (9)
        return t == T_PART ? C1A : t == T_OK ? C2S : t == T_BAD ? FAIL : INVALID;
    if (l == ERC1S && (mk == K_EKCT1ACK || mk == K_CT1ACK))                     // (12) MAC
        return t == T_OK ? C2S : INVALID;
    if (l == C1A && (mk == K_EKCT1ACK || mk == K_EK))                           // (11)
        return t == T_OK ? C2S : t == T_PART ? STAY : t == T_BAD ? FAIL : INVALID;
    return t == T_NONE ? STAY : INVALID;
}}

// the token of this step: the trace's, or any non-failing one in the free model
bool tokOk(int t) {{
    return TRACE ? t == e_tok : (t == T_NONE || t == T_PART || t == T_OK);
}}

// a send of kind k by party p, with token t
bool canSend(int p, int k, int t) {{
    return TRACE ? (pending && e_party == p && e_dir == SEND && e_kind == k
                    && e_ep == ep[p] && e_tok == t)
                 : true;
}}

// a receive by party p with outcome n (state, STAY or FAIL)
bool canRecv(int p, int n) {{
    if (n == INVALID) return false;
    if (!TRACE) return true;
    return n == FAIL ? e_dir == RECV_ERR : e_dir == RECV;
}}

void done(int p) {{
    pending = false;
}}

// the observer announces the next step of the trace
void expect(int p, int d, int k, int e, int t) {{
    e_party = p; e_dir = d; e_kind = k; e_ep = e; e_tok = t; pending = true;
}}

// the observer checks the state after the step
bool got(int p, int l, int e, int k) {{
    return !pending && st[p] == l && ep[p] == e && key[p] == k;
}}
"""


def nail(x, y):
    return f'<nail x="{x}" y="{y}"/>'


def edge(src, dst, select="", guard="", sync="", update="", comment="", nails=(),
         lx=None, ly=None):
    out = [f'<transition><source ref="{src}"/><target ref="{dst}"/>']
    y = 0
    def lab(kind, text):
        nonlocal y
        if not text:
            return ""
        pos = "" if lx is None else f' x="{lx}" y="{ly + y}"'
        y += 17
        return f'<label kind="{kind}"{pos}>{escape(text)}</label>'
    out.append(lab("select", select))
    out.append(lab("guard", guard))
    out.append(lab("synchronisation", sync))
    out.append(lab("assignment", update))
    out.append(lab("comments", comment))
    out.extend(nail(x, yy) for x, yy in nails)
    out.append("</transition>")
    return "".join(out)


# location layout of the Party template
POS = {
    "KU": (0, 0), "KS": (300, 0), "HS": (600, 0), "C1R": (900, 0), "ESC1R": (1200, 0),
    "NHR": (1320, 230), "HR": (1200, 460), "C1S": (900, 460), "ERC1S": (600, 330),
    "C1A": (600, 590), "C2S": (300, 460),
}

# the kind each state sends, and the state after the send
SENDS = {
    "KU": ("hdr", "KS", "(1)"), "KS": ("hdr", "KS", ""), "HS": ("ek", "HS", ""),
    "C1R": ("ekct1ack", "C1R", ""), "ESC1R": ("ct1ack", "ESC1R", ""),
    "NHR": ("none", "NHR", ""), "HR": ("ct1", "C1S", "(7)"), "C1S": ("ct1", "C1S", ""),
    "ERC1S": ("ct1", "ERC1S", ""), "C1A": ("none", "C1A", ""), "C2S": ("ct2", "C2S", ""),
}

# receive transitions that change state: (source, target, number, key, epoch increment)
RECVS = [
    ("KS", "HS", "(2)", "0", 0), ("HS", "C1R", "(3)", "0", 0), ("C1R", "ESC1R", "(4)", "0", 0),
    ("ESC1R", "NHR", "(5) MAC", "ep[p]", 1), ("NHR", "HR", "(6) MAC", "0", 0),
    ("C1S", "C1A", "(8)", "0", 0), ("C1S", "C2S", "(9) ek, MAC", "0", 0),
    ("C1S", "ERC1S", "(10) ek", "0", 0), ("C1A", "C2S", "(11) ek, MAC", "0", 0),
    ("ERC1S", "C2S", "(12) MAC", "0", 0), ("C2S", "KU", "(13)", "0", 1),
]

# hand-placed labels where the default overlaps: receive edges and self-loop shifts
RECV_LABEL = {("ERC1S", "C2S"): (330, 270), ("C1S", "ERC1S"): (760, 300),
              ("C1S", "C2S"): (640, 465), ("C1S", "C1A"): (770, 545),
              ("C1A", "C2S"): (330, 600), ("ESC1R", "NHR"): (1260, 10),
              ("NHR", "HR"): (1290, 350)}
LOOP_SHIFT = {"ERC1S": 60, "C1A": 60, "C1S": 40}          # receive self-loops
SEND_LOOP_SHIFT = {"C1A": -170, "C1S": 70, "C2S": -60}

PARTY_DECL = """// One party. The initial location follows st[p]: Alice KU, Bob NHR.

// send of kind k with data token t
bool sends(int k, int t) { return canSend(p, k, t); }

// receive of the delivered message that leaves state l unchanged, or fails
bool stays(int l, int t) {
    int n = next(l, ep[p], d_ep, d_kind, t);
    return tokOk(t) && (n == STAY || n == FAIL) && canRecv(p, n);
}

// receive of the delivered message that moves state l to l2
bool goes(int l, int l2, int t) {
    return tokOk(t) && next(l, ep[p], d_ep, d_kind, t) == l2 && canRecv(p, l2);
}

// enter state l, output the key of epoch k (0 for none), add inc to the epoch
void move(int l, int k, int inc) {
    st[p] = l; key[p] = k; ep[p] = ep[p] + inc; done(p);
}
"""


def party_template():
    locs = []
    for s in SHORT:
        x, y = POS[s]
        locs.append(f'<location id="{s}" x="{x}" y="{y}"><name x="{x + 12}" y="{y - 30}">'
                    f'{LABELS[SHORT.index(s)]}</name></location>')
    trans = []
    for s in SHORT:
        x, y = POS[s]
        k, dst, num = SENDS[s]
        chan = "none_" if k == "none" else k
        tok = "T_OK" if s == "KU" else "T_NONE"   # (1) computes the header MAC
        upd = f"move({dst}, {'ep[p]' if s == 'HR' else '0'}, 0)"
        g = f"sends(K_{k.upper()}, {tok})"
        if s == "NHR":   # loops to the sides, away from the (5) and (6) edges
            send_nails, send_lab = [(x + 55, y - 25), (x + 55, y + 25)], (x + 30, y - 130)
            recv_nails, recv_lab = [(x - 55, y - 25), (x - 55, y + 25)], (x - 215, y - 30)
        else:
            send_nails = [(x - 25, y - 55), (x + 25, y - 55)]
            send_lab = (x - 60 + SEND_LOOP_SHIFT.get(s, 0), y - 110)
            recv_nails = [(x - 25, y + 55), (x + 25, y + 55)]
            recv_lab = (x - 60 + LOOP_SHIFT.get(s, 0), y + 60)
        if dst == s:
            trans.append(edge(s, s, guard=g, sync=f"{chan}[p]!", update=upd,
                              nails=send_nails, lx=send_lab[0], ly=send_lab[1]))
        else:
            mx, my = (POS[s][0] + POS[dst][0]) // 2, (POS[s][1] + POS[dst][1]) // 2
            trans.append(edge(s, dst, guard=g, sync=f"{chan}[p]!", update=upd,
                              comment=f"send {num}", lx=mx - 70 if s == "KU" else mx - 50,
                              ly=my + 10 if s == "KU" else my - 70))
        trans.append(edge(s, s, select="t : tok_t", guard=f"stays({s}, t)",
                          sync="deliver[p]?", update="move(st[p], 0, 0)",
                          nails=recv_nails, lx=recv_lab[0], ly=recv_lab[1]))
    for src, dst, num, k, inc in RECVS:
        sx, sy = POS[src]
        dx, dy = POS[dst]
        mx, my = (sx + dx) // 2, (sy + dy) // 2
        nails = [(150, 230)] if (src, dst) == ("C2S", "KU") else []
        if nails:
            mx, my = 160, 270
        trans.append(edge(src, dst, select="t : tok_t", guard=f"goes({src}, {dst}, t)",
                          sync="deliver[p]?", update=f"move({dst}, {k}, {inc})",
                          comment=f"recv {num}", nails=nails,
                          lx=RECV_LABEL.get((src, dst), (mx + 10, 0))[0],
                          ly=RECV_LABEL[(src, dst)][1] if (src, dst) in RECV_LABEL
                          else my - 90 if sy == dy else my - 40))
    return (f'<template><name x="5" y="5">Party</name><parameter>const int[0, 1] p</parameter>'
            f'<declaration>{escape(PARTY_DECL)}</declaration>'
            + "".join(locs) +
            '<location id="Init" x="-150" y="230"><name x="-190" y="200">Init</name>'
            '<committed/></location>' + '<init ref="Init"/>' +
            edge("Init", "KU", guard="st[p] == KU", lx=-170, ly=90) +
            edge("Init", "NHR", guard="st[p] == NHR", nails=[(-150, 700), (1320, 700)],
                 lx=400, ly=705) +
            "".join(trans) + "</template>")


def net_template():
    """Idle stores sends; a delivery goes through a committed location named after the
    kind, so the MSC shows what is delivered."""
    import math
    parts = []
    for i, k in enumerate(KINDS):
        chan = "none_" if k == "none" else k
        a = 90 + i * 360 / len(KINDS)
        x, y = int(150 * math.cos(math.radians(a))), int(150 * math.sin(math.radians(a)))
        parts.append(edge("Idle", "Idle", select="p : int[0, 1]", sync=f"{chan}[p]?",
                          update=f"sent[p][ep[p]][K_{k.upper()}] = true",
                          nails=[(x - 15, y), (x + 15, y)], lx=x - 60, ly=y + 5))
        ly = -270 + i * 90
        parts.append(f'<location id="L{k}" x="520" y="{ly}"><name x="540" y="{ly - 10}">'
                     f'deliver_{k}</name><committed/></location>')
        parts.append(edge("Idle", f"L{k}", select="p : int[0, 1], e : int[1, EMAX]",
                          guard=f"mayDeliver(p, e, K_{k.upper()})",
                          update=f"d_p = p, d_ep = e, d_kind = K_{k.upper()}",
                          nails=[(300, ly - 20)], lx=250, ly=ly - 45))
        parts.append(edge(f"L{k}", "Idle", sync="deliver[d_p]!", nails=[(340, ly + 20)]))
    return ('<template><name x="5" y="5">Net</name>'
            '<declaration>// delivers any message that was sent: loss, duplication and '
            'reordering are allowed\n'
            'bool mayDeliver(int p, int e, int k) {\n'
            '    return (!CHECK_DELIVERY || (TRACE &amp;&amp; k == K_NONE) || sent[1 - p][e][k])\n'
            '        &amp;&amp; (!TRACE || (pending &amp;&amp; e_party == p &amp;&amp; e_dir != SEND\n'
            '                       &amp;&amp; e_ep == e &amp;&amp; e_kind == k));\n}</declaration>'
            '<location id="Idle" x="0" y="0"><name x="-20" y="-30">Idle</name></location>'
            + "".join(x for x in parts if x.startswith("<location")) +
            '<init ref="Idle"/>' + "".join(x for x in parts if x.startswith("<transition")) +
            "</template>")


def document(templates, system, queries):
    q = "".join(f"<query><formula>{escape(f)}</formula><comment>{escape(c)}</comment></query>"
                for f, c in queries)
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<!DOCTYPE nta PUBLIC \'-//Uppaal Team//DTD Flat System 1.6//EN\' '
            '\'http://www.it.uu.se/research/group/darts/uppaal/flat-1_6.dtd\'>\n'
            f'<nta><declaration>{escape(templates[0])}</declaration>'
            + "".join(templates[1:]) +
            f'<system>{escape(system)}</system><queries>{q}</queries></nta>\n')


def free_model():
    decl = declarations(False, True)
    system = "Alice = Party(A);\nBob = Party(B);\nsystem Alice, Bob, Net;\n"
    queries = [("E<> Alice.Ct2Sampled", "Alice finishes epoch 1 as sender of ct2"),
               ("E<> ep[A] == 3 && ep[B] == 3", "both parties reach epoch 3"),
               ("A[] (ep[A] <= ep[B] + 1 && ep[B] <= ep[A] + 1)",
                "the epochs of the parties differ by at most one")]
    return document([decl, party_template(), net_template()], system, queries)


# --------------------------------------------------------------------------
# Trace reading


def read_events(path):
    evs = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            if line.strip():
                e = json.loads(line)
                e["line"] = n
                evs.append(e)
    return evs


def hexb(s):
    return bytes.fromhex(s)


def be8(n):
    return n.to_bytes(8, "big")


def mac_data(label, epoch, body):
    return PROTOCOL_INFO + label + be8(epoch) + body


class Step:
    def __init__(self, op, party, d, kind, mep, tok, label, epoch, key, line, pre):
        self.op, self.party, self.dir, self.kind, self.mep = op, party, d, kind, mep
        self.tok, self.label, self.epoch, self.key, self.line, self.pre = (
            tok, label, epoch, key, line, pre)

    def describe(self):
        p = "A" if self.party == 0 else "B"
        msg = f"epoch {self.mep} {KINDS[self.kind]}"
        res = ("error" if self.dir == RECV_ERR else
               f"-> {LABELS[self.label]} epoch {self.epoch}" + (f" key {self.key}" if self.key else ""))
        return (f"op {self.op} (line {self.line}) party {p} {DIR_NAMES[self.dir].lower()} {msg} "
                f"in {LABELS[self.pre[0]]} epoch {self.pre[1]}, token {TOK_NAMES[self.tok]} {res}")


def steps_of(evs, max_ops, data):
    """The step events of session 1, with the data token of each."""
    s1 = [e for e in evs if e["s"] == evs[0]["s"]]
    ct1_recv = {0: None, 1: None}   # ct1 a party decoded at (3)
    ct1_own = {0: None, 1: None}    # ct1 a party sampled at (7)
    ops = {}
    for e in s1:
        if max_ops is not None and e["op"] > max_ops:
            continue
        ops.setdefault((e["op"], e["p"]), []).append(e)
    out = []
    for (op, pname), es in sorted(ops.items()):
        if op == 0:
            continue
        p = 0 if pname == "A" else 1
        st = es[-1]
        if not st["f"].startswith("States::"):
            raise SystemExit(f"op {op}: last event is {st['f']}, not a step")
        pre = (LAB[st["args"][0]], st["args"][1])
        r = st["ret"]
        hmacs = [e for e in es if e["f"] == "hmac"]
        decoded = [e for e in es if e["f"] == "decoder.message"]
        gen = [e for e in es if e["f"] == "mlkem.generate"]
        enc1 = [e for e in es if e["f"] == "mlkem.encaps1"]
        enc2 = [e for e in es if e["f"] == "mlkem.encaps2"]
        ekm = [e for e in es if e["f"] == "mlkem.ek_matches_header"]
        if enc1:
            ct1_own[p] = hexb(enc1[0]["ret"][1])

        def mac_tok(label, epoch, body, received_mac, code_ok):
            """Token of a MAC computation or check."""
            if data == "control":
                return T_OK if code_ok else T_BAD
            if data == "calls":
                if not hmacs:
                    return T_MISS
                return T_OK if code_ok else T_BAD
            want = mac_data(label, epoch, body)
            hit = [h for h in hmacs if hexb(h["args"][1]) == want]
            if not hit:
                return T_MISS
            if received_mac is None:
                return T_OK
            return T_OK if hexb(hit[0]["ret"]) == received_mac else T_BAD

        if st["f"] == "States::send":
            if "err" in r:
                raise SystemExit(f"op {op}: send returned an error")
            m = r["msg"]
            tok = T_NONE
            if pre[0] == LAB["KeysUnsampled"]:
                hdr = hexb(gen[0]["ret"][1]) if gen else b""
                tok = mac_tok(b":ekheader", pre[1], hdr, None, True)
            key = r["key"]["epoch"] if r.get("key") else 0
            out.append(Step(op, p, SEND, KIND[m["kind"]], m["epoch"], tok, LAB[r["state"]],
                            r["epoch"], key, st["line"], pre))
            continue
        m = st["args"][2]
        k = KIND[m["kind"]]
        ok = "err" not in r
        tok = T_NONE
        l, e = pre
        if m["epoch"] == e and l != LAB["Ct2Sampled"]:
            dec_case = (l, k) in {
                (LAB["HeaderSent"], KIND["ct1"]), (LAB["EkSentCt1Received"], KIND["ct2"]),
                (LAB["NoHeaderReceived"], KIND["hdr"]), (LAB["Ct1Sampled"], KIND["ek"]),
                (LAB["Ct1Sampled"], KIND["ekct1ack"]), (LAB["Ct1Acknowledged"], KIND["ek"]),
                (LAB["Ct1Acknowledged"], KIND["ekct1ack"])}
            if dec_case:
                if not decoded:
                    tok = T_MISS
                elif decoded[0]["ret"] is None:
                    tok = T_PART
                else:
                    msg = hexb(decoded[0]["ret"])
                    if l == LAB["HeaderSent"]:
                        ct1_recv[p] = msg
                        tok = T_OK
                    elif l == LAB["EkSentCt1Received"]:
                        tok = mac_tok(b":ciphertext", e, (ct1_recv[p] or b"") + msg[:CT2_SIZE],
                                      msg[CT2_SIZE:], ok)
                    elif l == LAB["NoHeaderReceived"]:
                        tok = mac_tok(b":ekheader", e, msg[:HDR_SIZE], msg[HDR_SIZE:], ok)
                    else:
                        if data == "control":
                            ek_ok = ok
                        elif not ekm:
                            ek_ok = None
                        else:
                            ek_ok = bool(ekm[0]["ret"])
                        if ek_ok is None:
                            tok = T_MISS
                        elif not ek_ok:
                            tok = T_BAD
                        elif l == LAB["Ct1Sampled"] and k == KIND["ek"]:
                            tok = T_OK                                       # (10)
                        else:                                                # (9), (11)
                            ct2 = hexb(enc2[0]["ret"]) if enc2 else b""
                            tok = mac_tok(b":ciphertext", e, (ct1_own[p] or b"") + ct2, None, ok)
            elif l == LAB["EkReceivedCt1Sampled"] and k in (KIND["ekct1ack"], KIND["ct1ack"]):
                ct2 = hexb(enc2[0]["ret"]) if enc2 else b""                  # (12)
                tok = mac_tok(b":ciphertext", e, (ct1_own[p] or b"") + ct2, None, ok)
        if ok:
            key = r["key"]["epoch"] if r.get("key") else 0
            out.append(Step(op, p, RECV, k, m["epoch"], tok, LAB[r["state"]], r["epoch"], key,
                            st["line"], pre))
        else:
            out.append(Step(op, p, RECV_ERR, k, m["epoch"], tok, pre[0], pre[1], 0, st["line"],
                            pre))
    return out


def is_idle(s):
    return (s.kind == KIND["none"] and s.dir != RECV_ERR and s.label == s.pre[0]
            and s.epoch == s.pre[1])


def observer_template(steps):
    """Location step_k: k steps matched, step k expected. Each edge checks the result of
    one step and announces the next."""
    cols = 8
    def pos(i):
        return (i % cols) * 240, (i // cols) * 120
    n = len(steps)
    def expect(s):
        return (f"expect({s.party}, {DIR_NAMES[s.dir]}, K_{KINDS[s.kind].upper()}, {s.mep}, "
                f"{TOK_NAMES[s.tok]})")
    def check(s):
        if s.dir == RECV_ERR:
            return "!pending"
        return f"got({s.party}, {SHORT[s.label]}, {s.epoch}, {s.key})"
    locs = ['<location id="start" x="-240" y="0"><name x="-260" y="-30">start</name>'
            '<committed/></location>']
    for i in range(n + 1):
        x, y = pos(i)
        name = "done" if i == n else f"step_{i}"
        locs.append(f'<location id="s{i}" x="{x}" y="{y}"><name x="{x - 20}" y="{y - 30}">'
                    f'{name}</name></location>')
    trans = []
    if n:
        trans.append(edge("start", "s0", update=expect(steps[0]), comment=steps[0].describe(),
                          lx=-230, ly=10))
    else:
        trans.append(edge("start", "s0"))
    for i, s in enumerate(steps):
        x, y = pos(i)
        upd = f"matched = {i + 1}" + (f", {expect(steps[i + 1])}" if i + 1 < n else "")
        trans.append(edge(f"s{i}", f"s{i + 1}", guard=check(s), update=upd,
                          comment=steps[i + 1].describe() if i + 1 < n else "",
                          lx=x + 10, ly=y + 10))
    return ('<template><name x="5" y="5">Obs</name>'
            '<declaration>// replays the trace: step_k means k steps matched</declaration>'
            + "".join(locs) + '<init ref="start"/>' + "".join(trans) + "</template>")


def trace_model(steps, party):
    decl = declarations(True, party is None)
    system = "Alice = Party(A);\nBob = Party(B);\nsystem Obs, Alice, Bob, Net;\n"
    queries = [("E<> Obs.done", "the whole trace is a run of the model"),
               ("sup: matched", "the largest number of matched steps")]
    return document([decl, party_template(), net_template(), observer_template(steps)],
                    system, queries)


def build(args):
    evs = read_events(args.trace)
    steps = steps_of(evs, args.max_ops, args.data)
    if args.party:
        p = 0 if args.party == "A" else 1
        steps = [s for s in steps if s.party == p]
    if args.drop_idle:
        steps = [s for s in steps if not is_idle(s)]
    global EMAX
    EMAX = max([3] + [max(s.mep, s.epoch) for s in steps])   # epochs are bounded by the trace
    return steps


def run_verifyta(model, query_text, extra=()):
    qpath = model + ".q"
    with open(qpath, "w") as f:
        f.write(query_text + "\n")
    r = subprocess.run([VERIFYTA, "-q", "-s", *extra, model, qpath], capture_output=True,
                       text=True)
    return r.stdout + r.stderr


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("model")
    m.add_argument("out")
    for name in ("trace", "check"):
        t = sub.add_parser(name)
        t.add_argument("trace")
        if name == "trace":
            t.add_argument("out")
        else:
            t.add_argument("--workdir", default="/tmp/uppaal-spike")
        t.add_argument("--max-ops", type=int)
        t.add_argument("--party", choices=["A", "B"])
        t.add_argument("--drop-idle", action="store_true")
        t.add_argument("--data", choices=["control", "calls", "formula"], default="formula")
    a = ap.parse_args()
    if a.cmd == "model":
        global EMAX
        EMAX = 3    # keeps the free state space small
        with open(a.out, "w") as f:
            f.write(free_model())
        return
    steps = build(a)
    if a.cmd == "trace":
        with open(a.out, "w") as f:
            f.write(trace_model(steps, a.party))
        print(f"{len(steps)} steps")
        return
    os.makedirs(a.workdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(a.trace))[0]
    tag = os.path.basename(os.path.dirname(os.path.abspath(a.trace)))
    name = f"{tag}.{base}.{a.data}" + (f".{a.party}" if a.party else "") + \
        (f".ops{a.max_ops}" if a.max_ops else "") + (".noidle" if a.drop_idle else "")
    model = os.path.join(a.workdir, name + ".xml")
    with open(model, "w") as f:
        f.write(trace_model(steps, a.party))
    out = run_verifyta(model, "E<> Obs.done\nsup: matched")
    parts = out.split("Verifying formula")
    done_sat = len(parts) > 1 and "Formula is satisfied" in parts[1]
    mm = re.search(r"Result:\s*(\d+)", out)
    k = int(mm.group(1)) if mm else None
    print(f"{name}: {len(steps)} steps, E<> Obs.done "
          f"{'satisfied' if done_sat else 'NOT satisfied'}, max matched k = {k}")
    if k is None:
        print(out)
        return
    if k < len(steps):
        print(f"  rejected step {k}: {steps[k].describe()}")
    # witness of the longest matched prefix
    target = "Obs.done" if k == len(steps) else f"Obs.step_{k}"
    prefix = os.path.join(a.workdir, name)
    run_verifyta(model, f"E<> {target}", ["-t1", "-f", prefix])
    if os.path.exists(prefix + "-1"):     # verifyta 5 writes prefix-1, the GUI wants .xtr
        os.replace(prefix + "-1", prefix + ".xtr")
    print(f"  model {model}, witness {prefix}.xtr")


if __name__ == "__main__":
    main()
