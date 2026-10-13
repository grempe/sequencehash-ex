defmodule SequenceHash.SequenceFunctionTest do
  use ExUnit.Case, async: true

  alias SequenceHash.{Encoding, SequenceFunction}

  doctest SequenceFunction

  defp hex(binary), do: Base.encode16(binary, case: :lower)
  defp unhex(string), do: Base.decode16!(string, case: :lower)

  describe "spec worked example: SequenceHash with SHA-256" do
    setup do
      state =
        Enum.reduce(
          ["", <<1>>, <<2, 2>>, <<3, 3, 3>>],
          SequenceFunction.new(:sha256, 2, ""),
          fn m, acc ->
            SequenceFunction.add(acc, m)
          end
        )

      %{state: state}
    end

    test "inner header", _ do
      assert hex(SequenceFunction.inner_header(64, 2, 0)) ==
               "5345514853485f4900000000000000000000000000000002" <> String.duplicate("00", 40)
    end

    test "outer header", _ do
      assert hex(SequenceFunction.outer_header(64, 2, 0, 0)) ==
               "5345514853485f4f00000000000000000000000000000002" <> String.duplicate("00", 40)
    end

    test "inner hash", %{state: state} do
      assert hex(SequenceFunction.inner_hash(state)) ==
               "5af952c4c997d8339b92dd870ce384a75f07fdf3fa65af70f5755fab12b634c6"
    end

    test "final output", %{state: state} do
      assert hex(SequenceFunction.result(state, "")) ==
               "fe550c163f7ce3e8f636ca8770333c4ce33a1d8424b4f383036d424929111144"
    end
  end

  describe "spec worked example: SequenceMAC with SHA-256" do
    setup do
      key = unhex("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91")

      inputs = [
        unhex("74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1"),
        unhex("f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9"),
        unhex("bd121635c5c732")
      ]

      state =
        Enum.reduce(inputs, SequenceFunction.new(:sha256, 1, key), &SequenceFunction.add(&2, &1))

      %{state: state}
    end

    test "inner and outer headers", _ do
      assert hex(SequenceFunction.outer_header(64, 1, 4, 32)) ==
               "5345514853485f4f0000000000000000000000000000000100000000000000000000000000000004000000000000000000000000000000200000000000000000"

      assert hex(SequenceFunction.inner_header(64, 1, 32)) ==
               "5345514853485f490000000000000000000000000000000100000000000000000000000000000020000000000000000000000000000000000000000000000000"
    end

    test "inner hash", %{state: state} do
      assert hex(SequenceFunction.inner_hash(state)) ==
               "f0ee9b4254b026b8200639073bd393aaf83c093f70fe2949aa0c05b33a9bf46d"
    end

    test "final output with a 4-byte zero customizer", %{state: state} do
      assert hex(SequenceFunction.result(state, <<0, 0, 0, 0>>)) ==
               "484ad123ab6f1fea03ac9ae765a38bd34128367f408eada7ff8c21b3cd8515c3"
    end
  end

  test "function indicators" do
    assert SequenceFunction.f_seqmac() == 1
    assert SequenceFunction.f_seqhsh() == 2
  end

  test "rejects function indicators other than 1 and 2" do
    for id <- [0, 3, -1, nil] do
      assert_raise ArgumentError, ~r/function indicator/, fn ->
        SequenceFunction.new(:sha256, id, "")
      end
    end
  end

  describe "key rules" do
    test "SequenceMAC keys must be at least 32 bytes" do
      for length <- [0, 1, 31] do
        assert_raise ArgumentError, ~r/at least 32 bytes/, fn ->
          SequenceFunction.new(:sha256, 1, :binary.copy(<<1>>, length))
        end
      end

      assert %SequenceFunction{key_length: 32} =
               SequenceFunction.new(:sha256, 1, :binary.copy(<<1>>, 32))
    end

    test "SequenceHash takes no key" do
      assert_raise ArgumentError, ~r/does not take a key/, fn ->
        SequenceFunction.new(:sha256, 2, :binary.copy(<<1>>, 32))
      end
    end

    test "keys must be binaries" do
      for id <- [1, 2], bad <- [~c"0123456789012345678901234567890123", nil] do
        assert_raise ArgumentError, ~r/keys must be binaries/, fn ->
          SequenceFunction.new(:sha256, id, bad)
        end
      end
    end
  end

  describe "add_all/2" do
    test "matches add/2 one input at a time, across batch boundaries" do
      # Sizes chosen so batches fill and flush at different points.
      inputs =
        for size <- [0, 1, 70_000, 5, 65_519, 65_520, 0, 200_000, 3],
            do: :binary.copy(<<7>>, size)

      start = SequenceFunction.new(:sha256, 2, "")
      one_by_one = Enum.reduce(inputs, start, &SequenceFunction.add(&2, &1))
      batched = SequenceFunction.add_all(start, inputs)

      assert batched.count == length(inputs)
      assert SequenceFunction.result(batched, "") == SequenceFunction.result(one_by_one, "")
    end

    test "many small inputs" do
      inputs = for i <- 1..5_000, do: Integer.to_string(i)
      start = SequenceFunction.new(:blake2s, 2, "")

      assert SequenceFunction.add_all(start, inputs) |> SequenceFunction.inner_hash() ==
               Enum.reduce(inputs, start, &SequenceFunction.add(&2, &1))
               |> SequenceFunction.inner_hash()
    end

    test "an empty enumerable adds nothing" do
      start = SequenceFunction.new(:sha256, 2, "")
      assert SequenceFunction.add_all(start, []) == start
    end

    test "refuses more than 2^128 - 1 inputs" do
      state = %{SequenceFunction.new(:sha256, 2, "") | count: Encoding.max_uint128()}

      assert_raise ArgumentError, ~r/more than 2\^128 - 1 inputs/, fn ->
        SequenceFunction.add_all(state, [""])
      end
    end
  end

  test "refuses more than 2^128 - 1 inputs" do
    state = %{SequenceFunction.new(:sha256, 2, "") | count: Encoding.max_uint128()}

    assert_raise ArgumentError, ~r/more than 2\^128 - 1 inputs/, fn ->
      SequenceFunction.add(state, "")
    end
  end

  test "inspect never shows the keyed hash states" do
    state = SequenceFunction.new(:sha256, 1, :binary.copy(<<7>>, 32))
    output = inspect(state)

    assert output ==
             "#SequenceHash.SequenceFunction<algorithm: :sha256, function_id: 1, key_length: 32, count: 0, ...>"
  end
end
