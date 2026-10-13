# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `SequenceHash`: SequenceHash with streaming (`new/1`, `add/2`, `result/1`,
  `result_with_customizer/2`) and one-shot (`hash/3`) APIs.
- `SequenceHash.MAC`: SequenceMAC with the same APIs plus `mac/4` and
  constant-time `verify/5` and `verify_result/3`.
- `SequenceHash.Encoding` and `SequenceHash.SequenceFunction`: the
  specification's primitives, with its examples as doctests.
- Support for SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b and BLAKE2s.
- Conformance tests against all C2SP/CCTV vectors, plus reference vectors for
  long customization strings.
- Benchee benchmarks in `bench/`.
