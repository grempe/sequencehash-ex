# SequenceHash

[![CI](https://github.com/grempe/sequencehash-ex/actions/workflows/ci.yml/badge.svg)](https://github.com/grempe/sequencehash-ex/actions/workflows/ci.yml)

An Elixir implementation of [SequenceHash and SequenceMAC](https://c2sp.org/sequencehash),
hash constructions that hash a *sequence* of byte strings unambiguously. It
uses only OTP's `:crypto` and has no runtime dependencies.

Hashing several values by concatenating them is ambiguous: `"Test 0Test 1"`
can be split as `["Test 0", "Test 1"]` or `["Test 0Test", " 1"]`, and plain
SHA-256 gives both the same hash. SequenceHash length-encodes every item, so
moving a boundary between items always changes the result:

```elixir
iex> SequenceHash.hash(:sha256, ["Test 0", "Test 1", "Test 2"]) |> Base.encode16(case: :lower)
"6eea7264b266d35bd5e483ef042189d2cebe51f9e8b764b90b0f9c82185de7ca"

iex> SequenceHash.hash(:sha256, ["Test 0Test 1Test 2"]) |> Base.encode16(case: :lower)
"1469d91e90c1d9c6189f576822e900f5cc8c3cdbd2ec51256df649d37c1688f7"
```

It also prevents length-extension attacks, supports customization strings for
domain separation, and has a keyed variant, SequenceMAC. See the
[announcement post](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
for the background.

This library passes all 4,992 [C2SP/CCTV test vectors](https://github.com/C2SP/CCTV/tree/main/sequencehash)
and the examples from the specification and the announcement post.

## Installation

```elixir
def deps do
  [
    {:sequencehash, "~> 0.1"}
  ]
end
```

Requires Elixir 1.18+ and Erlang/OTP 26+.

## Usage

### SequenceHash

```elixir
# One call
SequenceHash.hash(:sha256, ["first", "second"])

# Streaming: the hasher is an immutable value, so it pipes
SequenceHash.new(:sha512)
|> SequenceHash.add("first")
|> SequenceHash.add("second")
|> SequenceHash.result()
```

### Customization strings

Bind a hash to one purpose, such as one step of a protocol. Different
customizers give unrelated outputs:

```elixir
SequenceHash.hash(:sha256, inputs, customizer: "my-protocol/round-1")

hasher = Enum.reduce(inputs, SequenceHash.new(:sha256), &SequenceHash.add(&2, &1))
SequenceHash.result_with_customizer(hasher, "my-protocol/round-2")
```

### SequenceMAC

Keys must be at least 32 bytes. A key as long as the hash output is
recommended; longer keys add no security.

```elixir
key = :crypto.strong_rand_bytes(32)

{:ok, tag} = SequenceHash.MAC.mac(:sha256, key, ["first", "second"], customizer: "ctx")

# Constant-time verification
true = SequenceHash.MAC.verify(:sha256, key, ["first", "second"], tag, customizer: "ctx")

# Streaming
mac = SequenceHash.MAC.new!(:sha256, key) |> SequenceHash.MAC.add("first")
mac = SequenceHash.MAC.add(mac, "second")
SequenceHash.MAC.result_with_customizer(mac, "ctx")

# Constant-time verification of a streamed MAC
true = SequenceHash.MAC.verify_result(mac, tag, customizer: "ctx")

SequenceHash.MAC.new(:sha256, "short")
#=> {:error, :key_too_short}
```

## Supported hash functions

`:sha256`, `:sha512`, `:sha3_256`, `:sha3_512`, `:blake2b` (BLAKE2b-512) and
`:blake2s` (BLAKE2s-256): the hash functions covered by the C2SP test vectors.

Everything else raises `ArgumentError`. That includes SHA-1, MD5 and any hash
with output shorter than 32 bytes. The specification allows implementations to
reject such hashes as long as they say so.

## Security notes

- **Inputs are binaries only.** iodata is rejected because a nested list would
  be flattened and concatenated, which is the ambiguity this library exists to
  prevent.
- **Compare MAC tags with `SequenceHash.MAC.verify/5` or
  `SequenceHash.MAC.verify_result/3`**, not `==`.
- **Keys stay out of error messages.** Functions that take a key check it in
  the function body and raise errors that don't include it, so a bad call
  (such as swapped arguments or a charlist key) can't copy the key into logs
  or crash reports.
- **Treat a MAC state as secret.** It has absorbed the derived key. Its
  `Inspect` output hides the key-dependent fields, but don't log it or send it
  elsewhere.
- **No zeroization.** The specification says implementations SHOULD erase keys
  from memory. The BEAM's immutable, garbage-collected binaries make that
  impossible to do reliably, so this library does not try. The key is never
  stored in the hasher (only its length), and derived key blocks are
  short-lived.
- **Length limits.** The specification allows up to 2^128 - 1 items of up to
  2^128 - 1 bytes. BEAM binaries are far smaller than that, so the practical
  limit is the underlying hash's total input limit (2^61 - 1 bytes for
  SHA-256). This library does not track the total.
- **Key length warnings.** The specification allows warning when a MAC key
  length differs from the hash output length. This library doesn't warn at
  runtime; follow the guidance in the `SequenceHash.MAC` docs.
- SequenceHash is not a password hash. For passwords use Argon2, bcrypt or
  scrypt.

## Reading the code

The code is organized to be checked against the specification:

| Module                           | Specification section                     |
|----------------------------------|-------------------------------------------|
| `SequenceHash.Encoding`          | EncodeMSBF, EncodeLSBF, Pad, Encode, Derive |
| `SequenceHash.SequenceFunction`  | Header blocks, SequenceFunction           |
| `SequenceHash`                   | SequenceHash                              |
| `SequenceHash.MAC`               | SequenceMAC                               |
| `SequenceHash.Algorithm`         | Hash function support, block sizes        |

The specification's own examples are doctests, and
`test/sequence_hash/property_test.exs` states the security properties as
property tests.

## Development

```sh
mix deps.get
mix check   # format, unused deps, compile, Credo, audits, Dialyzer, tests with 100% coverage
```

### Benchmarks

```sh
mix run bench/sequence_hash_bench.exs
BENCH_ALGORITHMS=sha256,sha3_256 BENCH_TIME=5 mix run bench/sequence_hash_bench.exs
```

The benchmarks compare `SequenceHash.hash/3` and `SequenceHash.MAC.mac/4`
with `:crypto.hash/2` over the same bytes, for one small input, one large
input and many small inputs. The difference is the fixed cost of the
construction: two hash computations, the key and header blocks, and a
16-byte length suffix per input.

### Differential tests

An opt-in suite feeds the same generated inputs to this library and to the
upstream [Python](https://github.com/trailofbits/sequencehash-py) and
[Rust](https://github.com/trailofbits/sequencehash-rs) implementations, and
requires identical hashes, tags and key rejections. It needs Python 3 and
Cargo, so `mix test` and `mix check` skip it.

```sh
SEQUENCEHASH_PY=/path/to/sequencehash-py mix test.differential
SEQUENCEHASH_ORACLES=rust SEQUENCEHASH_RUNS=10000 mix test.differential --seed 1
```

The test vectors are vendored under `test/vectors` (see the `SOURCE.md` and
`README.md` files there) and are not included in the Hex package.

## License

Apache-2.0. See [LICENSE](https://github.com/grempe/sequencehash-ex/blob/main/LICENSE).
