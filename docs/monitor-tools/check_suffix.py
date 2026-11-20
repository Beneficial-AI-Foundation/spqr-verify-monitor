import json, sys, glob
dom = b"Signal_PQCKA_V1_MLKEM768:ciphertext".hex()
ok = bad = nomatch = 0
for f in glob.glob(sys.argv[1] + "/*.jsonl"):
    ev = [json.loads(l) for l in open(f)]
    enc = {}
    for e in ev:
        if e.get("f") == "mlkem.encaps2":
            r = e["ret"]; enc[(e["s"], e["p"], e["op"])] = r if isinstance(r, str) else json.dumps(r)
    for e in ev:
        if e.get("f") == "hmac" and e["args"][1].startswith(dom):
            k = (e["s"], e["p"], e["op"])
            if k not in enc: nomatch += 1; continue
            suffix = e["args"][1][43*2:]
            if suffix in enc[k] and len(suffix) == 256: ok += 1
            else: bad += 1
print("sender MACs whose data is exactly the encaps2 ct2:", ok, "mismatch:", bad, "receiver-side (no encaps2 in op):", nomatch)
