defmodule SequenceHash.PropertyTest do
  @moduledoc """
  Executable statements of the properties SequenceHash is meant to provide.

  Each property is checked against generated inputs with StreamData. They are
  written to be read by an auditor as claims about the implementation.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias SequenceHash.{Algorithm, Encoding, MAC}

  defp algorithm, do: member_of(Algorithm.supported())
  defp inputs, do: list_of(binary(max_length: 40), max_length: 6)
  defp key, do: binary(min_length: 32, max_length: 200)

  describe "unambiguous encoding" do
    property "splitting one input in two changes the hash" do
      check all algorithm <- algorithm(),
                data <- binary(min_length: 1, max_length: 64),
                at <- integer(0..byte_size(data)) do
        {left, right} = :erlang.split_binary(data, at)
        refute SequenceHash.hash(algorithm, [left, right]) == SequenceHash.hash(algorithm, [data])
      end
    end

    property "any two different splittings of the same bytes hash differently" do
      check all algorithm <- algorithm(),
                data <- binary(max_length: 32),
                cuts_a <- list_of(integer(0..byte_size(data)), max_length: 4),
                cuts_b <- list_of(integer(0..byte_size(data)), max_length: 4) do
        a = split(data, cuts_a)
        b = split(data, cuts_b)

        # Both sequences concatenate to the same bytes...
        assert IO.iodata_to_binary(a) == IO.iodata_to_binary(b)
        # ...so only the item boundaries differ, and that alone must matter.
        if a != b, do: refute(SequenceHash.hash(algorithm, a) == SequenceHash.hash(algorithm, b))
      end
    end

    property "different sequences hash differently" do
      check all algorithm <- algorithm(), a <- inputs(), b <- inputs(), a != b do
        refute SequenceHash.hash(algorithm, a) == SequenceHash.hash(algorithm, b)
      end
    end

    property "appending an empty input changes the hash" do
      check all algorithm <- algorithm(), items <- inputs() do
        refute SequenceHash.hash(algorithm, items ++ [""]) == SequenceHash.hash(algorithm, items)
      end
    end

    property "order matters" do
      check all algorithm <- algorithm(),
                a <- binary(max_length: 16),
                b <- binary(max_length: 16),
                a != b do
        refute SequenceHash.hash(algorithm, [a, b]) == SequenceHash.hash(algorithm, [b, a])
      end
    end
  end

  describe "API consistency" do
    property "streaming and one-shot agree, and result/1 leaves the state usable" do
      check all algorithm <- algorithm(), items <- inputs(), customizer <- binary(max_length: 300) do
        hasher = Enum.reduce(items, SequenceHash.new(algorithm), &SequenceHash.add(&2, &1))
        expected = SequenceHash.hash(algorithm, items, customizer: customizer)

        assert SequenceHash.result_with_customizer(hasher, customizer) == expected
        assert SequenceHash.result_with_customizer(hasher, customizer) == expected
        assert byte_size(expected) == Algorithm.output_size(algorithm)
      end
    end

    property "MAC verify accepts its own tags" do
      check all algorithm <- algorithm(),
                key <- key(),
                items <- inputs(),
                customizer <- binary(max_length: 40) do
        {:ok, tag} = MAC.mac(algorithm, key, items, customizer: customizer)
        assert MAC.verify(algorithm, key, items, tag, customizer: customizer)
      end
    end
  end

  describe "domain separation" do
    property "different customizers give different hashes" do
      check all algorithm <- algorithm(),
                items <- inputs(),
                c1 <- binary(max_length: 200),
                c2 <- binary(max_length: 200),
                c1 != c2 do
        refute SequenceHash.hash(algorithm, items, customizer: c1) ==
                 SequenceHash.hash(algorithm, items, customizer: c2)
      end
    end

    property "a MAC never equals the plain hash of the same inputs" do
      check all algorithm <- algorithm(), key <- key(), items <- inputs() do
        {:ok, tag} = MAC.mac(algorithm, key, items)
        refute tag == SequenceHash.hash(algorithm, items)
      end
    end

    property "appending zero bytes to a key changes the tag" do
      check all algorithm <- algorithm(), key <- key(), zeros <- integer(1..8), items <- inputs() do
        {:ok, a} = MAC.mac(algorithm, key, items)
        {:ok, b} = MAC.mac(algorithm, key <> :binary.copy(<<0>>, zeros), items)
        refute a == b
      end
    end
  end

  describe "support functions (spec invariants)" do
    property "EncodeMSBF and EncodeLSBF are 16-byte, reversible and mirror images" do
      check all n <- integer_up_to_2_128() do
        msbf = Encoding.encode_msbf(n)
        lsbf = Encoding.encode_lsbf(n)

        assert byte_size(msbf) == 16
        assert :binary.decode_unsigned(msbf, :big) == n
        assert :binary.decode_unsigned(lsbf, :little) == n
        assert lsbf == msbf |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()
      end
    end

    property "Pad output is non-empty, a multiple of b, starts with the input, adds fewer than b zeros" do
      check all data <- binary(max_length: 300), b <- integer(1..200) do
        padded = Encoding.pad(data, b)

        assert byte_size(padded) > 0
        assert rem(byte_size(padded), b) == 0
        assert binary_part(padded, 0, byte_size(data)) == data
        added = byte_size(padded) - byte_size(data)
        assert added < b or data == ""
        assert binary_part(padded, byte_size(data), added) == :binary.copy(<<0>>, added)
      end
    end

    property "Derive always returns exactly one block" do
      check all algorithm <- algorithm(),
                input <- binary(max_length: 400),
                tweak <- integer(0..255) do
        assert byte_size(Encoding.derive(input, algorithm, tweak)) ==
                 Algorithm.block_size(algorithm)
      end
    end

    property "Encode appends the little-endian length" do
      check all data <- binary(max_length: 100) do
        encoded = data |> Encoding.encode() |> IO.iodata_to_binary()
        assert encoded == data <> <<byte_size(data)::little-size(128)>>
      end
    end
  end

  # Splits `data` at the given offsets (sorted, duplicates allowed, which
  # produces empty items).
  defp split(data, cuts) do
    {items, rest, _} =
      cuts
      |> Enum.sort()
      |> Enum.reduce({[], data, 0}, fn cut, {items, rest, offset} ->
        {item, rest} = :erlang.split_binary(rest, cut - offset)
        {[item | items], rest, cut}
      end)

    Enum.reverse([rest | items])
  end

  # Integers biased toward the edges of the 128-bit range.
  defp integer_up_to_2_128 do
    max = (1 <<< 128) - 1

    one_of([
      integer(0..1000),
      integer((max - 1000)..max),
      map(binary(length: 16), &:binary.decode_unsigned/1)
    ])
  end
end
