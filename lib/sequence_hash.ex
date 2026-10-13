defmodule SequenceHash do
  @moduledoc """
  SequenceHash: unambiguous hashing of a *sequence* of byte strings.

  Hashing several values by concatenating them is ambiguous: `"ab" <> "c"` and
  `"a" <> "bc"` are the same bytes, so they get the same hash. SequenceHash
  length-encodes every input, so each `add/2` is a separate item and shifting
  the boundaries between inputs always changes the result:

      iex> a = SequenceHash.hash(:sha256, ["Test 0", "Test 1", "Test 2"])
      iex> b = SequenceHash.hash(:sha256, ["Test 0Test 1Test 2"])
      iex> a == b
      false

  It is defined in the C2SP specification at <https://c2sp.org/sequencehash>
  and works with any supported hash function (see `SequenceHash.Algorithm`).
  Like HMAC, it uses a double-hash construction, so its outputs are not
  subject to length-extension attacks even when the underlying hash is.

  For a keyed MAC with the same properties, see `SequenceHash.MAC`.

  ## Streaming

  A hasher is an immutable value. `add/2` returns a new hasher, so it pipes
  naturally and earlier values stay usable:

      iex> SequenceHash.new(:sha256)
      ...> |> SequenceHash.add("Test 0")
      ...> |> SequenceHash.add("Test 1")
      ...> |> SequenceHash.add("Test 2")
      ...> |> SequenceHash.result()
      ...> |> Base.encode16(case: :lower)
      "6eea7264b266d35bd5e483ef042189d2cebe51f9e8b764b90b0f9c82185de7ca"

  ## Customization strings

  A customization string binds a hash to one purpose, such as one step of a
  protocol. Different customizers give unrelated outputs for the same inputs:

      iex> hasher = SequenceHash.new(:sha256) |> SequenceHash.add("Test 0")
      iex> SequenceHash.result_with_customizer(hasher, "CUST 0") |> Base.encode16(case: :lower)
      "3e54b5cd60ef78773dcf14c5f65ed593726a981f2c80045db7fac03015cc07ad"
      iex> SequenceHash.result_with_customizer(hasher, "CUST 1") |> Base.encode16(case: :lower)
      "3c5b12ea6952714fed499796a743b103de97575fc938aab7d154cc6c605984a9"

  ## Inputs and limits

  Inputs must be binaries. iodata is deliberately not accepted: a nested list
  would be flattened and concatenated, which is exactly the ambiguity this
  construction exists to prevent.

  The specification allows up to `2^128 - 1` inputs of up to `2^128 - 1`
  bytes. On the BEAM a single binary is far smaller than that, so the only
  practical limit is the total input limit of the underlying hash (for
  example `2^61 - 1` bytes for SHA-256). This library does not track the
  total, which the specification permits.
  """

  alias SequenceHash.{Algorithm, SequenceFunction}

  @enforce_keys [:function]
  defstruct [:function]

  @typedoc "A SequenceHash computation in progress."
  @opaque t :: %__MODULE__{function: SequenceFunction.t()}

  @doc """
  Starts a new SequenceHash using `algorithm` as the underlying hash.

  Raises `ArgumentError` for an unsupported algorithm.

      iex> SequenceHash.new(:sha256) |> SequenceHash.output_size()
      32

      iex> SequenceHash.new(:md5)
      ** (ArgumentError) unsupported hash algorithm :md5; supported algorithms are [:blake2b, :blake2s, :sha256, :sha3_256, :sha3_512, :sha512]
  """
  @spec new(Algorithm.t()) :: t()
  def new(algorithm) do
    algorithm = Algorithm.validate!(algorithm)
    %__MODULE__{function: SequenceFunction.new(algorithm, SequenceFunction.f_seqhsh(), "")}
  end

  @doc """
  Adds `data` as the next item in the sequence.

  Each call adds one length-encoded item, so adding `"ab"` then `"cd"` is not
  the same as adding `"abcd"`. Empty binaries are items too.
  """
  @spec add(t(), binary()) :: t()
  def add(%__MODULE__{function: function} = hasher, data) when is_binary(data) do
    %{hasher | function: SequenceFunction.add(function, data)}
  end

  @doc """
  Returns the hash using an empty customization string.

  The hasher is not consumed: you can keep adding to it, or call this again.
  """
  @spec result(t()) :: binary()
  def result(%__MODULE__{} = hasher), do: result_with_customizer(hasher, "")

  @doc """
  Returns the hash using `customizer` as the customization string.
  """
  @spec result_with_customizer(t(), binary()) :: binary()
  def result_with_customizer(%__MODULE__{function: function}, customizer)
      when is_binary(customizer) do
    SequenceFunction.result(function, customizer)
  end

  @doc """
  Hashes `inputs` in one call.

  `inputs` is any enumerable of binaries, such as a list or a stream.

  ## Options

    * `:customizer` - the customization string (default `""`).

  ## Examples

      iex> SequenceHash.hash(:sha256, ["", <<1>>, <<2, 2>>, <<3, 3, 3>>]) |> Base.encode16(case: :lower)
      "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144"

      iex> SequenceHash.hash(:sha256, ["Test 0"], customizer: "CUST 2") |> Base.encode16(case: :lower)
      "706af798b32b12c9f508c16c3411b594227f79936a3cc521e6e1f362b1ef3a38"
  """
  @spec hash(Algorithm.t(), Enumerable.t(binary()), keyword()) :: binary()
  def hash(algorithm, inputs, opts \\ []) do
    [customizer: customizer] = Keyword.validate!(opts, customizer: "")

    algorithm
    |> new()
    |> add_all(inputs)
    |> result_with_customizer(customizer)
  end

  @doc """
  Returns the output length of the underlying hash, in bytes.
  """
  @spec output_size(t()) :: pos_integer()
  def output_size(%__MODULE__{function: function}), do: Algorithm.output_size(function.algorithm)

  @doc """
  Returns the block size of the underlying hash, in bytes.

      iex> SequenceHash.new(:sha512) |> SequenceHash.block_size()
      128
  """
  @spec block_size(t()) :: pos_integer()
  def block_size(%__MODULE__{function: function}), do: Algorithm.block_size(function.algorithm)

  defp add_all(hasher, inputs), do: Enum.reduce(inputs, hasher, &add(&2, &1))
end
