defmodule SequenceHash.MACTest do
  use ExUnit.Case, async: true

  alias SequenceHash.MAC

  doctest MAC

  defp hex(binary), do: Base.encode16(binary, case: :lower)
  defp unhex(string), do: Base.decode16!(string, case: :lower)

  @key32 :binary.copy(<<0x42>>, 32)

  describe "spec worked example" do
    test "SHA-256, 32-byte key, 4-byte zero customizer" do
      key = unhex("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91")

      inputs = [
        unhex("74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1"),
        unhex("f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9"),
        unhex("bd121635c5c732")
      ]

      assert {:ok, tag} = MAC.mac(:sha256, key, inputs, customizer: <<0, 0, 0, 0>>)
      assert hex(tag) == "484ad123ab6f1fea03ac9ae765a38bd34128367f408eada7ff8c21b3cd8515c3"
    end
  end

  # Known answers from the Trail of Bits announcement post.
  describe "blog post known answers (SHA-256, 64-byte key)" do
    setup do
      key =
        unhex(
          "c5d6670f20adad622292a404dc5496cd6692fee636b5935a18451c985b7277bc" <>
            "9cacbc26e5473f85cfc6a64e96d0b98e7b9b604eaebc8899971e1a97dc3caa3a"
        )

      %{key: key}
    end

    test "shifting input boundaries changes the tag", %{key: key} do
      for {inputs, expected} <- [
            {["Test 0", "Test 1"],
             "9a24e4209dad98d2e1f1eecd62aa2908234f1eed2963395292fd9718129fe258"},
            {["Test 0Test 1"],
             "4e4b71b8bb7b2c80e9f9ca89cb8bff43cd77cc5b530fc5f163069e5dda2876cb"},
            {["Test 0", "", "Test 1"],
             "6faf7818842f5a208dc306afe83ed7bea5b3fadc2a617c2208e836709f925889"}
          ] do
        mac = Enum.reduce(inputs, MAC.new!(:sha256, key), &MAC.add(&2, &1))
        assert hex(MAC.result(mac)) == expected
      end
    end
  end

  describe "keys" do
    test "keys shorter than 32 bytes are rejected" do
      for length <- [0, 1, 16, 31] do
        key = :binary.copy(<<1>>, length)
        assert MAC.new(:sha256, key) == {:error, :key_too_short}
        assert MAC.mac(:sha256, key, []) == {:error, :key_too_short}
        assert_raise ArgumentError, ~r/at least 32 bytes/, fn -> MAC.new!(:sha256, key) end
      end
    end

    test "a 32-byte key is accepted" do
      assert {:ok, _} = MAC.new(:sha256, :binary.copy(<<1>>, 32))
      assert MAC.min_key_length() == 32
    end

    test "trailing zero bytes make a different key" do
      {:ok, a} = MAC.mac(:sha256, @key32, ["m"])
      {:ok, b} = MAC.mac(:sha256, @key32 <> <<0>>, ["m"])
      refute a == b
    end

    test "a long key and its hash are different keys" do
      long_key = :binary.copy(<<9>>, 100)
      {:ok, a} = MAC.mac(:sha256, long_key, ["m"])
      {:ok, b} = MAC.mac(:sha256, :crypto.hash(:sha256, long_key), ["m"])
      refute a == b
    end

    test "unsupported algorithms raise even with a valid key" do
      assert_raise ArgumentError, fn -> MAC.new(:sha, @key32) end
    end

    test "keys must be binaries" do
      for bad <- [~c"0123456789012345678901234567890123", :key, nil] do
        assert_raise FunctionClauseError, fn -> MAC.new(:sha256, bad) end
      end
    end
  end

  describe "verify/5" do
    setup do
      {:ok, tag} = MAC.mac(:sha512, @key32, ["a", "b"], customizer: "ctx")
      %{tag: tag}
    end

    test "accepts the correct tag", %{tag: tag} do
      assert MAC.verify(:sha512, @key32, ["a", "b"], tag, customizer: "ctx")
    end

    test "rejects changed inputs, customizer, key or tag", %{tag: tag} do
      refute MAC.verify(:sha512, @key32, ["ab"], tag, customizer: "ctx")
      refute MAC.verify(:sha512, @key32, ["a", "b"], tag)
      refute MAC.verify(:sha512, :binary.copy(<<0x43>>, 32), ["a", "b"], tag, customizer: "ctx")

      <<first, rest::binary>> = tag

      refute MAC.verify(:sha512, @key32, ["a", "b"], <<Bitwise.bxor(first, 1), rest::binary>>,
               customizer: "ctx"
             )
    end

    test "rejects tags of the wrong length", %{tag: tag} do
      refute MAC.verify(:sha512, @key32, ["a", "b"], binary_part(tag, 0, 32), customizer: "ctx")
      refute MAC.verify(:sha512, @key32, ["a", "b"], "", customizer: "ctx")
    end

    test "raises on configuration errors" do
      assert_raise ArgumentError, fn -> MAC.verify(:sha512, "short", ["a"], "tag") end
      assert_raise ArgumentError, fn -> MAC.verify(:sha512, @key32, ["a"], "tag", key: "x") end
    end
  end

  describe "streaming API" do
    test "matches the one-shot API and is not consumed by result" do
      mac = MAC.new!(:blake2s, @key32) |> MAC.add("x") |> MAC.add("y")
      {:ok, expected} = MAC.mac(:blake2s, @key32, ["x", "y"], customizer: "c")

      assert MAC.result_with_customizer(mac, "c") == expected
      assert MAC.result_with_customizer(mac, "c") == expected
    end

    test "sizes" do
      mac = MAC.new!(:sha3_512, @key32)
      assert MAC.output_size(mac) == 64
      assert MAC.block_size(mac) == 72
    end

    test "only binaries are accepted" do
      mac = MAC.new!(:sha256, @key32)

      for bad <- [["a"], ~c"a", nil] do
        assert_raise FunctionClauseError, fn -> MAC.add(mac, bad) end
        assert_raise FunctionClauseError, fn -> MAC.result_with_customizer(mac, bad) end
      end
    end
  end

  test "SequenceMAC and SequenceHash never agree on the same inputs" do
    # Different function indicators separate the two even when every other
    # parameter matches, so a MAC can never be mistaken for a hash.
    {:ok, tag} = MAC.mac(:sha256, @key32, ["m"])
    refute tag == SequenceHash.hash(:sha256, ["m"])
  end

  test "inspect does not expose key-dependent state" do
    output = inspect(MAC.new!(:sha256, @key32))
    refute output =~ "Reference"
    refute output =~ "inner"
    refute output =~ "outer"
  end
end
