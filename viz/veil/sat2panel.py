#!/usr/bin/env python3
"""Turn the Lean output of a Veil `sat trace` query into the JSON of a model checker result,
so that `panel.html` shows it.

The states and actions are Veil's. The field `sent` prints as `<unrepresentable>` in trace
queries and is left out. With `--rejected TEXT`, the result is marked as a violation with the
text TEXT: use it for the step that has no model, as found by `trace2veil.py search`.

Usage: python3 -I viz/veil/sat2panel.py QUERY.out [--rejected TEXT] > result.json
"""

import argparse
import json
import re

STATE = re.compile(r"^  State (\d+) \(via (.*)\):$")
FIELD = re.compile(r"^    (\w+) = (.*)$")
CALL = re.compile(r"^(\w+)\((.*)\)$")


def scalar(v: str):
    if v in ("true", "false"):
        return v == "true"
    return int(v) if v.isdigit() else v


def value(v: str):
    v = v.strip()
    if v.startswith("{") and "↦" in v:
        entries = []
        for part in v[1:-1].split(","):
            k, x = part.split("↦")
            entries.append({"key": scalar(k.strip()), "value": scalar(x.strip())})
        return {"$veil": "map", "entries": entries}
    return scalar(v)


def transition(t: str):
    if t == "init":
        return "after_init"
    m = CALL.match(t)
    name, args = (m.group(1), m.group(2)) if m else (t, "")
    out = []
    for a in filter(None, (x.strip() for x in args.split(","))):
        k, x = a.split("=", 1)
        out.append({"name": k.strip(), "value": scalar(x.strip())})
    return {"$veil": "ctor", "type": "Label", "name": name, "args": out}


def parse(text: str):
    states, cur, last = [], None, None
    for line in text.splitlines():
        m = STATE.match(line)
        if m:
            cur = {"index": int(m.group(1)), "transition": transition(m.group(2)),
                   "fields": {"$veil": "record", "type": "State", "fields": []}}
            states.append(cur)
            last = None
            continue
        m = FIELD.match(line)
        if cur is not None and m:
            last = [m.group(1), m.group(2)]
            cur["fields"]["fields"].append(last)
        elif cur is not None and last is not None and line.startswith("      "):
            last[1] += " " + line.strip()  # a value printed over several lines
        elif cur is not None and not line.startswith("    "):
            cur = None
    for s in states:
        s["fields"]["fields"] = [{"name": n, "value": value(v)}
                                 for n, v in s["fields"]["fields"] if n != "sent"]
    return states


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="Lean output of a satisfiable `sat trace` query (a .out file "
                                "of trace2veil.py)")
    ap.add_argument("--rejected", metavar="TEXT", help="mark the result as a violation")
    a = ap.parse_args()
    with open(a.out) as f:
        states = parse(f.read())
    result = {"result": "found_violation" if a.rejected else "no_violation",
              "trace": {"theory": {"$veil": "record", "type": "Theory", "fields": []},
                        "states": states}}
    if a.rejected:
        result["violation"] = {"kind": "safety_failure", "violates": [a.rejected]}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
