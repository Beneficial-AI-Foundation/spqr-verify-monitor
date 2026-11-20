"""Check whether the ciphertext MAC inputs of a sender hold only `ct2`.

For each `hmac` call whose input starts with the ciphertext MAC prefix
(PROTOCOL_INFO || ":ciphertext" || 8 epoch bytes), look for an `mlkem.encaps2` call in the
same operation. If there is one, the call counts as a match when the rest of the input is
exactly the 128-byte `ct2` that `encaps2` returned, and as a mismatch otherwise. Calls in
operations with no `encaps2` (the receiver side) are counted apart.

Usage: python3 -I docs/monitor-tools/check_suffix.py DIR
"""

import glob
import json
import sys

PREFIX_HEX = b"Signal_PQCKA_V1_MLKEM768:ciphertext".hex()
PREFIX_LEN = len(PREFIX_HEX) + 16    # hex digits of the prefix and the 8 epoch bytes
CT2_HEX_LEN = 256


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    ok = bad = nomatch = 0
    for path in glob.glob(sys.argv[1] + "/*.jsonl"):
        with open(path) as f:
            events = [json.loads(line) for line in f]
        enc = {}
        for e in events:
            if e.get("f") == "mlkem.encaps2":
                r = e["ret"]
                enc[(e["s"], e["p"], e["op"])] = r if isinstance(r, str) else json.dumps(r)
        for e in events:
            if e.get("f") != "hmac" or not e["args"][1].startswith(PREFIX_HEX):
                continue
            k = (e["s"], e["p"], e["op"])
            if k not in enc:
                nomatch += 1
                continue
            suffix = e["args"][1][PREFIX_LEN:]
            if len(suffix) == CT2_HEX_LEN and suffix in enc[k]:
                ok += 1
            else:
                bad += 1
    print("sender MACs whose data is exactly the encaps2 ct2:", ok, "mismatch:", bad,
          "receiver-side (no encaps2 in op):", nomatch)


if __name__ == "__main__":
    main()
