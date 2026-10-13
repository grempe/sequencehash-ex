#!/usr/bin/env python3
"""Differential-testing oracle backed by trailofbits/sequencehash-py.

Usage: python3 -I oracle.py /path/to/sequencehash-py

Reads one request per line on stdin and writes one response line to stdout.
A request is tab-separated, with every byte string hex-encoded:

    algorithm <TAB> key <TAB> customizer [<TAB> input]...

An empty key field means SequenceHash; anything else means SequenceMAC. The
response is the hex-encoded output, or "error" if the reference rejected the
request (for example, a SequenceMAC key shorter than 32 bytes).
"""

import sys
import warnings

sys.path.insert(0, sys.argv[1])
import sequencehash  # noqa: E402

# The reference warns about key lengths that differ from the output length.
warnings.simplefilter("ignore")

for line in sys.stdin:
    algorithm, key, customizer, *inputs = line.rstrip("\n").split("\t")
    try:
        if key:
            function = sequencehash.SequenceMAC.new(bytes.fromhex(key), digestmod=algorithm)
        else:
            function = sequencehash.SequenceHash.new(algorithm)
        for item in inputs:
            function.add(bytes.fromhex(item))
        response = function.result_with_customizer(bytes.fromhex(customizer)).hex()
    except ValueError:
        response = "error"
    sys.stdout.write(response + "\n")
    sys.stdout.flush()
