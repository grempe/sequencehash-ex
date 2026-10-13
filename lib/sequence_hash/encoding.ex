defmodule SequenceHash.Encoding do
  @moduledoc """
  The byte-level support functions from the SequenceHash specification.

  Each function here corresponds to one named function in the specification's
  "Support functions and general requirements" section, and its doctests are
  the specification's own examples. None of them touch secret state except
  `derive/3`, which processes keys.

  Lengths and counts are encoded as fixed-width 128-bit integers. Values
  outside `0..2^128 - 1` are rejected, as the specification requires; on the
  BEAM a binary can never come close to that limit, so in practice the guards
  only reject negative numbers and programming errors.
  """

  import Bitwise

  alias SequenceHash.Algorithm

  @max_uint128 (1 <<< 128) - 1

  @doc "The largest value `encode_msbf/1` and `encode_lsbf/1` accept: `2^128 - 1`."
  @spec max_uint128() :: pos_integer()
  def max_uint128, do: @max_uint128

  defguardp is_uint128(n) when is_integer(n) and n >= 0 and n <= @max_uint128

  @doc """
  `EncodeMSBF`: encodes an unsigned 128-bit integer as 16 bytes, most
  significant byte first (big-endian).

      iex> SequenceHash.Encoding.encode_msbf(1) |> Base.encode16(case: :lower)
      "00000000000000000000000000000001"

      iex> SequenceHash.Encoding.encode_msbf(170141183460469231731687303715884105728) |> Base.encode16(case: :lower)
      "80000000000000000000000000000000"

      iex> SequenceHash.Encoding.encode_msbf(82056233853955569762636142348112307994) |> Base.encode16(case: :lower)
      "3dbb74aeac45747d1c1a44915219271a"

  Negative values and values of `2^128` or more are rejected:

      iex> SequenceHash.Encoding.encode_msbf(-1)
      ** (FunctionClauseError) no function clause matching in SequenceHash.Encoding.encode_msbf/1

      iex> SequenceHash.Encoding.encode_msbf(340282366920938463463374607431768211456)
      ** (FunctionClauseError) no function clause matching in SequenceHash.Encoding.encode_msbf/1
  """
  @spec encode_msbf(non_neg_integer()) :: <<_::128>>
  def encode_msbf(n) when is_uint128(n), do: <<n::unsigned-big-integer-size(128)>>

  @doc """
  `EncodeLSBF`: encodes an unsigned 128-bit integer as 16 bytes, least
  significant byte first (little-endian).

      iex> SequenceHash.Encoding.encode_lsbf(1) |> Base.encode16(case: :lower)
      "01000000000000000000000000000000"

      iex> SequenceHash.Encoding.encode_lsbf(170141183460469231731687303715884105728) |> Base.encode16(case: :lower)
      "00000000000000000000000000000080"

      iex> SequenceHash.Encoding.encode_lsbf(82056233853955569762636142348112307994) |> Base.encode16(case: :lower)
      "1a27195291441a1c7d7445acae74bb3d"

      iex> SequenceHash.Encoding.encode_lsbf(-1)
      ** (FunctionClauseError) no function clause matching in SequenceHash.Encoding.encode_lsbf/1
  """
  @spec encode_lsbf(non_neg_integer()) :: <<_::128>>
  def encode_lsbf(n) when is_uint128(n), do: <<n::unsigned-little-integer-size(128)>>

  @doc """
  `Pad`: right-pads `data` with zero bytes to the smallest *positive* multiple
  of `block_size`.

  Non-empty data that is already a multiple of `block_size` is returned
  unchanged. The empty string becomes one full block of zeros, so the result
  is never empty.

      iex> SequenceHash.Encoding.pad("", 4)
      <<0, 0, 0, 0>>

      iex> SequenceHash.Encoding.pad("JJJ", 4)
      <<"JJJ", 0>>

      iex> SequenceHash.Encoding.pad("WWWW", 4)
      "WWWW"

      iex> SequenceHash.Encoding.pad("WWWWW", 4)
      <<"WWWWW", 0, 0, 0>>
  """
  @spec pad(binary(), pos_integer()) :: binary()
  def pad(data, block_size)
      when is_binary(data) and is_integer(block_size) and block_size > 0 do
    case rem(byte_size(data), block_size) do
      0 when data != "" -> data
      remainder -> data <> zeros(block_size - remainder)
    end
  end

  @doc """
  `Encode`: the unambiguous encoding of one input, `data || EncodeLSBF(len(data))`.

  Returned as iodata so that large inputs are passed to the hash without being
  copied. Empty inputs are *not* ignored; they encode as a zero length.

      iex> SequenceHash.Encoding.encode("") |> IO.iodata_to_binary() |> Base.encode16(case: :lower)
      "00000000000000000000000000000000"

      iex> SequenceHash.Encoding.encode("AAA") |> IO.iodata_to_binary() |> Base.encode16(case: :lower)
      "41414103000000000000000000000000000000"

      iex> SequenceHash.Encoding.encode("SEQUENCEHASH") |> IO.iodata_to_binary() |> Base.encode16(case: :lower)
      "53455155454e4345484153480c000000000000000000000000000000"
  """
  @spec encode(binary()) :: [binary(), ...]
  def encode(data) when is_binary(data), do: [data, encode_lsbf(byte_size(data))]

  @doc """
  `Derive`: turns a key or customization string into exactly one block.

  Inputs no longer than the block size are padded; longer inputs are hashed
  first and then padded. The first byte of the block is XORed with `tweak`.
  This mirrors HMAC key processing; the key *length* is committed separately
  in the header blocks, which is what prevents HMAC-style key pseudocollisions.

      iex> SequenceHash.Encoding.derive("", :sha256, 0x00) == :binary.copy(<<0>>, 64)
      true

      iex> SequenceHash.Encoding.derive(String.duplicate("W", 64), :sha256, 0xFF) |> Base.encode16(case: :lower)
      "a8575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757"

      iex> SequenceHash.Encoding.derive(String.duplicate("W", 65), :sha256, 0x5A) |> Base.encode16(case: :lower)
      "f26baffba4cd6018bebed0b8ed10bbe3ea892a8dfb03b992d2e270b3eb9faa8a0000000000000000000000000000000000000000000000000000000000000000"

  Because `input` is often a key, invalid arguments raise an `ArgumentError`
  that does not include them, rather than a `FunctionClauseError`, which would
  carry the key into logs and crash reports.
  """
  @spec derive(binary(), Algorithm.t(), byte()) :: binary()
  def derive(input, algorithm, tweak) do
    if not is_binary(input), do: raise(ArgumentError, "Derive input must be a binary")

    if not (is_integer(tweak) and tweak in 0..255),
      do: raise(ArgumentError, "Derive tweak must be an integer in 0..255")

    block_size = Algorithm.block_size(algorithm)

    reduced =
      if byte_size(input) <= block_size,
        do: input,
        else: :crypto.hash(algorithm, input)

    <<first, rest::binary>> = pad(reduced, block_size)
    <<bxor(first, tweak), rest::binary>>
  end

  defp zeros(count), do: :binary.copy(<<0>>, count)
end
