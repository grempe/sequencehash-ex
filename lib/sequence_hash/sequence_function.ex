defmodule SequenceHash.SequenceFunction do
  @moduledoc """
  `SequenceFunction`: the construction both SequenceHash and SequenceMAC are
  built on (spec section "SequenceFunction").

  Given a hash function `H` with block size `b` and output length `L`, a key
  `K` (empty for SequenceHash), a customization string `S`, a function
  indicator `F` and inputs `M_1 .. M_n`:

      SequenceFunction(H, K, S, F; M_1, ..., M_n) =
          H( K_O || HeaderO(b, F, S, K) || S' || EncodeMSBF(n) || EncodeMSBF(L) ||
             H( K_I || HeaderI(b, F, K) || Encode(M_1) || ... || Encode(M_n) ) )

  where `K_I = Derive(K, H, 0x55)`, `K_O = Derive(K, H, 0xaa)` and
  `S' = Derive(S, H, 0x00)`.

  ## How this module maps to the formula

    * `new/3` absorbs `K_I || HeaderI` into the inner hash state and `K_O`
      into the outer hash state. The key itself is not kept, only its length.
    * `add/2` absorbs `Encode(M_i)` into the inner state and counts `n`.
    * `result/2` finishes the inner hash and feeds the outer hash. It works
      on copies, so the state can keep growing or be finished again with a
      different customization string.

  `:crypto` hash states are persistent: `:crypto.hash_update/2` returns a new
  state and leaves the old one valid. That is what makes this struct an
  ordinary immutable value.

  ## Secret material

  For SequenceMAC, `inner` and `outer` have absorbed the derived key blocks,
  so the struct is as sensitive as the key. Its `Inspect` output omits them.
  The BEAM cannot reliably zeroize memory, so derived key blocks are not
  wiped (the specification says SHOULD); they are short-lived binaries that
  are reclaimed by garbage collection.

  Most callers should use `SequenceHash` or `SequenceHash.MAC` instead of this
  module. It is public so that auditors can check each step against the
  specification and so the test suite can check the intermediate values in the
  C2SP/CCTV vectors.
  """

  alias SequenceHash.{Algorithm, Encoding}

  @derive {Inspect, only: [:algorithm, :function_id, :key_length, :count]}
  @enforce_keys [:algorithm, :function_id, :key_length, :inner, :outer]
  defstruct [:algorithm, :function_id, :key_length, :inner, :outer, count: 0]

  @typedoc "Function indicator `F`: `1` for SequenceMAC, `2` for SequenceHash."
  @type function_id :: 1 | 2

  @typedoc "A SequenceFunction computation in progress."
  @type t :: %__MODULE__{
          algorithm: Algorithm.t(),
          function_id: function_id(),
          key_length: non_neg_integer(),
          inner: :crypto.hash_state(),
          outer: :crypto.hash_state(),
          count: non_neg_integer()
        }

  @f_seqmac 1
  @f_seqhsh 2

  @tweak_inner 0x55
  @tweak_outer 0xAA
  @tweak_customizer 0x00

  @doc "Function indicator `F_SEQMAC`."
  @spec f_seqmac() :: 1
  def f_seqmac, do: @f_seqmac

  @doc "Function indicator `F_SEQHSH`."
  @spec f_seqhsh() :: 2
  def f_seqhsh, do: @f_seqhsh

  @doc """
  Starts a computation for `algorithm`, `function_id` and `key`.

  This does not enforce the SequenceMAC minimum key length; that rule lives in
  `SequenceHash.MAC.new/2`.
  """
  @spec new(Algorithm.t(), function_id(), binary()) :: t()
  def new(algorithm, function_id, key)
      when function_id in [@f_seqmac, @f_seqhsh] and is_binary(key) do
    block_size = Algorithm.block_size(algorithm)

    inner =
      algorithm
      |> :crypto.hash_init()
      |> :crypto.hash_update([
        Encoding.derive(key, algorithm, @tweak_inner),
        inner_header(block_size, function_id, byte_size(key))
      ])

    outer =
      algorithm
      |> :crypto.hash_init()
      |> :crypto.hash_update(Encoding.derive(key, algorithm, @tweak_outer))

    %__MODULE__{
      algorithm: algorithm,
      function_id: function_id,
      key_length: byte_size(key),
      inner: inner,
      outer: outer
    }
  end

  @doc """
  Adds one input `M_i` as a separate, length-encoded item.
  """
  @spec add(t(), binary()) :: t()
  def add(%__MODULE__{count: count} = state, message) when is_binary(message) do
    if count >= Encoding.max_uint128() do
      raise ArgumentError, "SequenceFunction cannot accept more than 2^128 - 1 inputs"
    end

    %{state | inner: :crypto.hash_update(state.inner, Encoding.encode(message)), count: count + 1}
  end

  @doc """
  Returns the inner hash `H(K_I || HeaderI || Encode(M_1) || ...)`.

  It does not depend on the customization string, which is why the
  specification notes it can be reused across customizers.
  """
  @spec inner_hash(t()) :: binary()
  def inner_hash(%__MODULE__{inner: inner}), do: :crypto.hash_final(inner)

  @doc """
  Returns the final output for `customizer`.
  """
  @spec result(t(), binary()) :: binary()
  def result(%__MODULE__{} = state, customizer) when is_binary(customizer) do
    %__MODULE__{algorithm: algorithm, function_id: function_id, key_length: key_length} = state
    block_size = Algorithm.block_size(algorithm)

    state.outer
    |> :crypto.hash_update([
      outer_header(block_size, function_id, byte_size(customizer), key_length),
      Encoding.derive(customizer, algorithm, @tweak_customizer),
      Encoding.encode_msbf(state.count),
      Encoding.encode_msbf(Algorithm.output_size(algorithm)),
      inner_hash(state)
    ])
    |> :crypto.hash_final()
  end

  @doc """
  `HeaderI(b, F, K)`: the inner header block.

      iex> SequenceHash.SequenceFunction.inner_header(64, 2, 0) |> Base.encode16(case: :lower)
      "5345514853485f490000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000"
  """
  @spec inner_header(pos_integer(), function_id(), non_neg_integer()) :: binary()
  def inner_header(block_size, function_id, key_length) do
    Encoding.pad(
      "SEQHSH_I" <> Encoding.encode_msbf(function_id) <> Encoding.encode_msbf(key_length),
      block_size
    )
  end

  @doc """
  `HeaderO(b, F, S, K)`: the outer header block.

  It always differs from the inner header in its first eight bytes, so the
  inner and outer hashes never process the same byte sequence, even for
  SequenceHash where the key is empty.

      iex> SequenceHash.SequenceFunction.outer_header(64, 1, 4, 32) |> Base.encode16(case: :lower)
      "5345514853485f4f0000000000000000000000000000000100000000000000000000000000000004000000000000000000000000000000200000000000000000"
  """
  @spec outer_header(pos_integer(), function_id(), non_neg_integer(), non_neg_integer()) ::
          binary()
  def outer_header(block_size, function_id, customizer_length, key_length) do
    Encoding.pad(
      "SEQHSH_O" <>
        Encoding.encode_msbf(function_id) <>
        Encoding.encode_msbf(customizer_length) <>
        Encoding.encode_msbf(key_length),
      block_size
    )
  end
end
