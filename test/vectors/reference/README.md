# Reference vectors

`long_customizer.json` covers customization strings longer than the hash
block size, which the C2SP/CCTV vectors do not include. It was generated with
the upstream Python implementation (revision recorded in the file's `source`
field) by `generate.py`:

    python3 -I generate.py /path/to/sequencehash-py > long_customizer.json
