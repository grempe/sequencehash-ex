defmodule SequenceHash.MAC do
  @moduledoc """
  SequenceMAC: the keyed variant of `SequenceHash`.

  It has the same properties as SequenceHash (unambiguous inputs, optional
  customization strings, no length extension) and adds a secret key. Unlike
  HMAC, the key length is committed in the computation, so a long key and its
  hash, or a key and the same key with trailing zero bytes, are different keys.

      iex> key = :binary.copy(<<0x2A>>, 32)
      iex> {:ok, tag} = SequenceHash.MAC.mac(:sha256, key, ["Test 0", "Test 1"])
      iex> SequenceHash.MAC.verify(:sha256, key, ["Test 0", "Test 1"], tag)
      true
      iex> SequenceHash.MAC.verify(:sha256, key, ["Test 0Test 1"], tag)
      false

  ## Keys

  Keys must be at least 32 bytes; shorter keys are rejected, as the
  specification requires. The specification and the SequenceHash authors
  recommend a key as long as the hash output (`output_size/1`). Longer keys
  add no security, because the security level is capped by the output
  length. This library does not warn about key lengths at runtime.

  ## Handling secrets

  A MAC state has absorbed the derived key, so treat it like the key: don't
  log it or send it elsewhere. Its `Inspect` output hides the key-dependent
  fields. The BEAM cannot reliably erase memory, so keys and derived key
  blocks are not zeroized (a SHOULD in the specification); they are released
  by garbage collection.

  Compare tags with `verify/5` or `verify_result/3`, which use a
  constant-time comparison, rather than `==`.

  Functions that take a key check it in the function body and raise an
  `ArgumentError` that does not include it. A guard failure would raise a
  `FunctionClauseError` carrying the arguments, which Logger and crash
  reports print.
  """

  alias SequenceHash.{Algorithm, SequenceFunction}

  @min_key_length 32

  @enforce_keys [:function]
  defstruct [:function]

  @typedoc "A SequenceMAC computation in progress."
  @opaque t :: %__MODULE__{function: SequenceFunction.t()}

  @doc "The minimum SequenceMAC key length, in bytes."
  @spec min_key_length() :: 32
  def min_key_length, do: @min_key_length

  @doc """
  Starts a new SequenceMAC with `algorithm` and `key`.

  Returns `{:error, :key_too_short}` if `key` is shorter than 32 bytes. Raises
  `ArgumentError` for an unsupported algorithm or a key that is not a binary.

      iex> {:ok, _mac} = SequenceHash.MAC.new(:sha256, :binary.copy(<<1>>, 32))

      iex> SequenceHash.MAC.new(:sha256, "too short")
      {:error, :key_too_short}
  """
  @spec new(Algorithm.t(), binary()) :: {:ok, t()} | {:error, :key_too_short}
  def new(algorithm, key) do
    algorithm = Algorithm.validate!(algorithm)

    cond do
      not is_binary(key) ->
        raise ArgumentError, "SequenceMAC keys must be binaries"

      byte_size(key) < @min_key_length ->
        {:error, :key_too_short}

      true ->
        {:ok,
         %__MODULE__{function: SequenceFunction.new(algorithm, SequenceFunction.f_seqmac(), key)}}
    end
  end

  @doc """
  Like `new/2`, but raises `ArgumentError` if the key is too short.

      iex> SequenceHash.MAC.new!(:sha256, "too short")
      ** (ArgumentError) SequenceMAC keys must be at least 32 bytes
  """
  @spec new!(Algorithm.t(), binary()) :: t()
  def new!(algorithm, key) do
    case new(algorithm, key) do
      {:ok, mac} ->
        mac

      {:error, :key_too_short} ->
        raise ArgumentError, "SequenceMAC keys must be at least #{@min_key_length} bytes"
    end
  end

  @doc """
  Adds `data` as the next item in the sequence. See `SequenceHash.add/2`.
  """
  @spec add(t(), binary()) :: t()
  def add(%__MODULE__{function: function} = mac, data) when is_binary(data) do
    %{mac | function: SequenceFunction.add(function, data)}
  end

  @doc """
  Returns the tag using an empty customization string.
  """
  @spec result(t()) :: binary()
  def result(%__MODULE__{} = mac), do: result_with_customizer(mac, "")

  @doc """
  Returns the tag using `customizer` as the customization string.
  """
  @spec result_with_customizer(t(), binary()) :: binary()
  def result_with_customizer(%__MODULE__{function: function}, customizer)
      when is_binary(customizer) do
    SequenceFunction.result(function, customizer)
  end

  @doc """
  Computes the tag of `inputs` in one call.

  ## Options

    * `:customizer` - the customization string (default `""`).

  ## Examples

      iex> key = Base.decode16!("c5d6670f20adad622292a404dc5496cd6692fee636b5935a18451c985b7277bc9cacbc26e5473f85cfc6a64e96d0b98e7b9b604eaebc8899971e1a97dc3caa3a", case: :lower)
      iex> {:ok, tag} = SequenceHash.MAC.mac(:sha256, key, ["Test 0", "", "Test 1"])
      iex> Base.encode16(tag, case: :lower)
      "6faf7818842f5a208dc306afe83ed7bea5b3fadc2a617c2208e836709f925889"
  """
  @spec mac(Algorithm.t(), binary(), Enumerable.t(binary()), keyword()) ::
          {:ok, binary()} | {:error, :key_too_short}
  def mac(algorithm, key, inputs, opts \\ []) do
    [customizer: customizer] = Keyword.validate!(opts, customizer: "")

    with {:ok, mac} <- new(algorithm, key) do
      {:ok, mac |> add_all(inputs) |> result_with_customizer(customizer)}
    end
  end

  @doc """
  Checks `tag` against the tag of `inputs`, in constant time.

  Returns `false` for a tag that is not a binary of the right length, such as
  `nil` from a missing header. Raises `ArgumentError` if the key is too short
  or the algorithm is unsupported, since those are configuration errors
  rather than verification failures.

  ## Options

    * `:customizer` - the customization string (default `""`).
  """
  @spec verify(Algorithm.t(), binary(), Enumerable.t(binary()), term(), keyword()) ::
          boolean()
  def verify(algorithm, key, inputs, tag, opts \\ []) do
    algorithm
    |> new!(key)
    |> add_all(inputs)
    |> verify_result(tag, opts)
  end

  @doc """
  Checks `tag` against the tag of a MAC built with `new/2` and `add/2`, in
  constant time.

  Use this rather than comparing `result/1` with `==`, which can return early
  and leak how much of a forged tag is correct. Returns `false` for a tag that
  is not a binary of the right length.

  ## Options

    * `:customizer` - the customization string (default `""`).

  ## Examples

      iex> key = :binary.copy(<<0x2A>>, 32)
      iex> {:ok, tag} = SequenceHash.MAC.mac(:sha256, key, ["header", "body"])
      iex> mac = SequenceHash.MAC.new!(:sha256, key) |> SequenceHash.MAC.add("header")
      iex> mac |> SequenceHash.MAC.add("body") |> SequenceHash.MAC.verify_result(tag)
      true
      iex> SequenceHash.MAC.verify_result(mac, tag)
      false
  """
  @spec verify_result(t(), term(), keyword()) :: boolean()
  def verify_result(%__MODULE__{} = mac, tag, opts \\ []) do
    [customizer: customizer] = Keyword.validate!(opts, customizer: "")
    expected = result_with_customizer(mac, customizer)

    is_binary(tag) and byte_size(tag) == byte_size(expected) and
      :crypto.hash_equals(expected, tag)
  end

  @doc """
  Returns the output (tag) length of the underlying hash, in bytes.
  """
  @spec output_size(t()) :: pos_integer()
  def output_size(%__MODULE__{function: function}), do: Algorithm.output_size(function.algorithm)

  @doc """
  Returns the block size of the underlying hash, in bytes.
  """
  @spec block_size(t()) :: pos_integer()
  def block_size(%__MODULE__{function: function}), do: Algorithm.block_size(function.algorithm)

  defp add_all(%__MODULE__{function: function} = mac, inputs) do
    %{mac | function: SequenceFunction.add_all(function, inputs)}
  end
end
