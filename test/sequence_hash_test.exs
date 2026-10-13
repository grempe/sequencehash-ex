defmodule SequenceHashTest do
  use ExUnit.Case, async: true

  doctest SequenceHash

  defp hex(binary), do: Base.encode16(binary, case: :lower)

  # Known answers from the Trail of Bits announcement post
  # ("SequenceHash: multihashing for the rest of us", 2026-10-02).
  describe "blog post known answers (SHA-256)" do
    test "shifting input boundaries changes the result" do
      assert hex(SequenceHash.hash(:sha256, ["Test 0", "Test 1", "Test 2"])) ==
               "6eea7264b266d35bd5e483ef042189d2cebe51f9e8b764b90b0f9c82185de7ca"

      assert hex(SequenceHash.hash(:sha256, ["Test 0Test 1Test 2"])) ==
               "1469d91e90c1d9c6189f576822e900f5cc8c3cdbd2ec51256df649d37c1688f7"

      assert hex(SequenceHash.hash(:sha256, ["Test 0", "Test 1Test 2"])) ==
               "1800a2188e126c79dac8f7cf7e38a66e3f797654c15a5e49248a94d4e99bcaae"
    end

    test "customization strings" do
      for {customizer, expected} <- [
            {"CUST 0", "3e54b5cd60ef78773dcf14c5f65ed593726a981f2c80045db7fac03015cc07ad"},
            {"CUST 1", "3c5b12ea6952714fed499796a743b103de97575fc938aab7d154cc6c605984a9"},
            {"CUST 2", "706af798b32b12c9f508c16c3411b594227f79936a3cc521e6e1f362b1ef3a38"}
          ] do
        assert hex(SequenceHash.hash(:sha256, ["Test 0"], customizer: customizer)) == expected
      end
    end
  end

  describe "streaming API" do
    test "matches the one-shot API" do
      hasher = SequenceHash.new(:blake2b) |> SequenceHash.add("a") |> SequenceHash.add("")
      assert SequenceHash.result(hasher) == SequenceHash.hash(:blake2b, ["a", ""])

      assert SequenceHash.result_with_customizer(hasher, "c") ==
               SequenceHash.hash(:blake2b, ["a", ""], customizer: "c")
    end

    test "result does not consume the hasher" do
      hasher = SequenceHash.new(:sha256) |> SequenceHash.add("x")
      first = SequenceHash.result(hasher)

      assert SequenceHash.result(hasher) == first

      assert SequenceHash.result(SequenceHash.add(hasher, "y")) ==
               SequenceHash.hash(:sha256, ["x", "y"])
    end

    test "earlier values are unaffected by later adds" do
      base = SequenceHash.new(:sha256)
      _extended = SequenceHash.add(base, "x")
      assert SequenceHash.result(base) == SequenceHash.hash(:sha256, [])
    end

    test "sizes" do
      hasher = SequenceHash.new(:sha3_256)
      assert SequenceHash.output_size(hasher) == 32
      assert SequenceHash.block_size(hasher) == 136
    end
  end

  describe "input validation" do
    test "only binaries are accepted as inputs" do
      hasher = SequenceHash.new(:sha256)

      for bad <- [["a", "b"], ~c"ab", :ab, 1, nil] do
        assert_raise FunctionClauseError, fn -> SequenceHash.add(hasher, bad) end
      end

      for bad <- [["a"], ~c"a", nil] do
        assert_raise ArgumentError, ~r/inputs must be binaries/, fn ->
          SequenceHash.hash(:sha256, ["ok", bad])
        end
      end
    end

    test "customizers must be binaries" do
      hasher = SequenceHash.new(:sha256)

      for bad <- [~c"c", :c, nil] do
        assert_raise FunctionClauseError, fn ->
          SequenceHash.result_with_customizer(hasher, bad)
        end
      end
    end

    test "customizers that derive to the same block still differ" do
      # Derive pads short customizers with zeros and hashes long ones, so
      # "", <<0>> and <<0, 0>> derive to the same block, and so do a customizer
      # longer than the block size and its hash. Only the customizer length
      # in the outer header separates them.
      long = :binary.copy(<<0x41>>, 65)

      for algorithm <- SequenceHash.Algorithm.supported() do
        hasher = SequenceHash.new(algorithm) |> SequenceHash.add("m")
        long = :binary.copy(<<0x41>>, SequenceHash.block_size(hasher) + 1)

        outputs =
          for customizer <- ["", <<0>>, <<0, 0>>, long, :crypto.hash(algorithm, long)] do
            SequenceHash.result_with_customizer(hasher, customizer)
          end

        assert outputs == Enum.uniq(outputs), inspect(algorithm)
      end

      key = :binary.copy(<<1>>, 32)

      tags =
        for customizer <- ["", <<0>>, <<0, 0>>, long, :crypto.hash(:sha256, long)] do
          {:ok, tag} = SequenceHash.MAC.mac(:sha256, key, ["m"], customizer: customizer)
          tag
        end

      assert tags == Enum.uniq(tags)
    end

    test "unknown options are rejected" do
      assert_raise ArgumentError, fn -> SequenceHash.hash(:sha256, [], key: "k") end
    end

    test "enumerables other than lists are accepted" do
      assert SequenceHash.hash(:sha256, Stream.map(1..3, &Integer.to_string/1)) ==
               SequenceHash.hash(:sha256, ["1", "2", "3"])
    end
  end

  test "inspect does not expose hash states" do
    refute inspect(SequenceHash.new(:sha256)) =~ "Reference"
  end
end
