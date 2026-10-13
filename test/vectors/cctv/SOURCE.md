# C2SP/CCTV SequenceHash test vectors

Copied unmodified from <https://github.com/C2SP/CCTV/tree/main/sequencehash>
at commit `50a8ecf2a220f4c8bdc4f085789b8e85c26829e7` (2026-09-25).

The CCTV repository does not include a license file. These files are used
only by this project's test suite and are not part of the Hex package.

`SHA256SUMS` records each file's checksum; the test suite verifies it, so an
accidental edit fails the build. To update, replace the JSON files, regenerate
the checksums with `sha256sum hash/*.json mac/*.json > SHA256SUMS`, and update
the commit above.

Format (from the CCTV README): each file is a JSON list of objects with
`hash_name`, `function_id` (1 = SequenceMAC, 2 = SequenceHash), `key`,
`customizer`, `inputs` (all hex), the flags `may_fail`, `must_fail` and
`may_warn`, and the expected `final_output`, `inner_hash`, `inner_header`
and `outer_header` (hex).
