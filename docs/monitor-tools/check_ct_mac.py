"""Count the ciphertext MAC inputs in the monitor traces of one or more directories.

For each directory, print how many `hmac` calls have input that starts with the ciphertext
MAC prefix (PROTOCOL_INFO || ":ciphertext"), grouped by input length, and how many of them
read the 8 epoch bytes after that prefix as a small number (below 2**32) in big-endian or only
in little-endian order. With `ct1 || ct2` the input is 1131 bytes; with `ct2` only, 171.

Usage: python3 -I docs/monitor-tools/check_ct_mac.py DIR [DIR ...]
"""

import collections
import glob
import json
import sys

PREFIX = b"Signal_PQCKA_V1_MLKEM768:ciphertext"
PREFIX_HEX = PREFIX.hex()


def check_dir(d):
    lens = collections.Counter()
    be = le = 0
    for path in glob.glob(d + "/*.jsonl"):
        with open(path) as f:
            for line in f:
                e = json.loads(line)
                if e.get("f") != "hmac" or not e["args"][1].startswith(PREFIX_HEX):
                    continue
                data = bytes.fromhex(e["args"][1])
                lens[len(data)] += 1
                ep = data[len(PREFIX):len(PREFIX) + 8]
                if int.from_bytes(ep, "big") < 2**32:
                    be += 1
                elif int.from_bytes(ep, "little") < 2**32:
                    le += 1
    print(d, "ciphertext-hmac input lengths:", dict(lens), "big-endian epochs:", be,
          "little-endian epochs:", le)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for d in sys.argv[1:]:
        check_dir(d)


if __name__ == "__main__":
    main()
