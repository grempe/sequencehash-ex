#!/usr/bin/env python3
"""Generate long-customizer vectors with the upstream Python reference.

The C2SP/CCTV vectors never use a customization string longer than the hash
block size, so the "hash the customizer first" branch of Derive is not
exercised by them. This script fills that gap using trailofbits/sequencehash-py.

Usage: python3 -I generate.py /path/to/sequencehash-py > long_customizer.json

Inputs are derived deterministically from SHA-256 so the output is
reproducible.
"""

import hashlib
import json
import subprocess
import sys
import warnings

sys.path.insert(0, sys.argv[1])
import sequencehash  # noqa: E402

ALGORITHMS = ["sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"]


def det_bytes(label: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{label}/{counter}".encode()).digest()
        counter += 1
    return out[:length]


def main() -> None:
    revision = subprocess.run(
        ["git", "-C", sys.argv[1], "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    vectors = []
    warnings.simplefilter("ignore")
    for name in ALGORITHMS:
        block_size = hashlib.new(name).block_size
        for function_id in (1, 2):
            for cust_len in (block_size + 1, 2 * block_size + 7):
                label = f"{name}/{function_id}/{cust_len}"
                key = det_bytes(label + "/key", block_size + 9) if function_id == 1 else b""
                customizer = det_bytes(label + "/customizer", cust_len)
                inputs = [det_bytes(label + f"/input/{i}", i * 5) for i in range(4)]
                if function_id == 1:
                    obj = sequencehash.SequenceMAC.new(key, digestmod=name)
                else:
                    obj = sequencehash.SequenceHash.new(name)
                for item in inputs:
                    obj.add(item)
                vectors.append({
                    "hash_name": name,
                    "function_id": function_id,
                    "key": key.hex(),
                    "customizer": customizer.hex(),
                    "inputs": [i.hex() for i in inputs],
                    "final_output": obj.result_with_customizer(customizer).hex(),
                })
    json.dump({"source": f"trailofbits/sequencehash-py@{revision}", "vectors": vectors},
              sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
