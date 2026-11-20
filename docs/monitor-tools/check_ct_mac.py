import json, sys, glob, collections
dom = b"Signal_PQCKA_V1_MLKEM768:ciphertext".hex()
for d in sys.argv[1:]:
    lens = collections.Counter(); be = le = 0
    for f in glob.glob(d + "/*.jsonl"):
        for line in open(f):
            e = json.loads(line)
            if e.get("f") != "hmac" or not e["args"][1].startswith(dom): continue
            data = bytes.fromhex(e["args"][1]); lens[len(data)] += 1
            ep = data[35:43]
            if int.from_bytes(ep, "big") < 2**32: be += 1
            if int.from_bytes(ep, "little") < 2**32 and int.from_bytes(ep, "big") >= 2**32: le += 1
    print(d, "ciphertext-hmac input lengths:", dict(lens), "big-endian epochs:", be, "little-endian epochs:", le)
