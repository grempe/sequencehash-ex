defmodule SequenceHash.Algorithm do
  @moduledoc """
  The underlying hash functions this library accepts.

  The specification allows SequenceHash and SequenceMAC to be built on almost
  any hash function, and lets implementations reject hash functions that are
  insecure or have short outputs, provided the rejection is documented
  (spec section "Hash function support").

  This library accepts exactly the hash functions covered by the C2SP/CCTV
  test vectors whose output is at least 32 bytes:

  | Algorithm   | Block size `b` (bytes) | Output length `L` (bytes) |
  |-------------|------------------------|---------------------------|
  | `:sha256`   | 64                     | 32                        |
  | `:sha512`   | 128                    | 64                        |
  | `:sha3_256` | 136                    | 32                        |
  | `:sha3_512` | 72                     | 64                        |
  | `:blake2b`  | 128                    | 64                        |
  | `:blake2s`  | 64                     | 32                        |

  The sizes are copied from the specification's "Block size guidance" table.
  For SHA-3 the block size is the sponge *rate*. `:blake2b` and `:blake2s` are
  the OTP `:crypto` names for BLAKE2b-512 and BLAKE2s-256.

  Everything else is rejected with an `ArgumentError`. That includes SHA-1
  (`:sha`), MD5, and any hash whose output is shorter than 32 bytes, so the
  specification's warnings about "short hashes" never apply.
  """

  @sizes %{
    sha256: %{block_size: 64, output_size: 32},
    sha512: %{block_size: 128, output_size: 64},
    sha3_256: %{block_size: 136, output_size: 32},
    sha3_512: %{block_size: 72, output_size: 64},
    blake2b: %{block_size: 128, output_size: 64},
    blake2s: %{block_size: 64, output_size: 32}
  }

  @supported Map.keys(@sizes)

  @typedoc "A supported underlying hash function, named as in `:crypto`."
  @type t :: :sha256 | :sha512 | :sha3_256 | :sha3_512 | :blake2b | :blake2s

  @doc """
  Guard that is true when `algorithm` is a supported hash function.
  """
  defguard is_supported(algorithm) when algorithm in @supported

  @doc """
  Lists the supported hash functions.

      iex> SequenceHash.Algorithm.supported()
      [:blake2b, :blake2s, :sha256, :sha3_256, :sha3_512, :sha512]
  """
  @spec supported() :: [t()]
  def supported, do: Enum.sort(@supported)

  @doc """
  Returns the block size `b` of `algorithm`, in bytes.

      iex> SequenceHash.Algorithm.block_size(:sha3_256)
      136
  """
  @spec block_size(t()) :: pos_integer()
  def block_size(algorithm), do: fetch!(algorithm).block_size

  @doc """
  Returns the output length `L` of `algorithm`, in bytes.

      iex> SequenceHash.Algorithm.output_size(:blake2b)
      64
  """
  @spec output_size(t()) :: pos_integer()
  def output_size(algorithm), do: fetch!(algorithm).output_size

  @doc """
  Returns `algorithm` unchanged if it is supported, otherwise raises.

      iex> SequenceHash.Algorithm.validate!(:sha256)
      :sha256

      iex> SequenceHash.Algorithm.validate!(:sha)
      ** (ArgumentError) unsupported hash algorithm :sha; supported algorithms are [:blake2b, :blake2s, :sha256, :sha3_256, :sha3_512, :sha512]
  """
  @spec validate!(term()) :: t()
  def validate!(algorithm) when is_supported(algorithm), do: algorithm

  def validate!(algorithm) do
    raise ArgumentError,
          "unsupported hash algorithm #{inspect(algorithm)}; " <>
            "supported algorithms are #{inspect(supported())}"
  end

  defp fetch!(algorithm), do: Map.fetch!(@sizes, validate!(algorithm))
end
