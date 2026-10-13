defmodule SequenceHash.EncodingTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias SequenceHash.Encoding

  doctest Encoding

  defp hex(binary), do: Base.encode16(IO.iodata_to_binary(binary), case: :lower)

  describe "encode_msbf/1 and encode_lsbf/1" do
    test "spec examples for zero" do
      assert hex(Encoding.encode_msbf(0)) == String.duplicate("00", 16)
      assert hex(Encoding.encode_lsbf(0)) == String.duplicate("00", 16)
    end

    test "accept the full unsigned 128-bit range and nothing else" do
      max = (1 <<< 128) - 1
      assert Encoding.max_uint128() == max
      assert Encoding.encode_msbf(max) == :binary.copy(<<0xFF>>, 16)
      assert Encoding.encode_lsbf(max) == :binary.copy(<<0xFF>>, 16)

      for bad <- [-1, max + 1, 1.0, "1", nil] do
        assert_raise FunctionClauseError, fn -> Encoding.encode_msbf(bad) end
        assert_raise FunctionClauseError, fn -> Encoding.encode_lsbf(bad) end
      end
    end

    test "spec example for EncodeLSBF(-1) and EncodeLSBF(2^128)" do
      assert_raise FunctionClauseError, fn -> Encoding.encode_lsbf(1 <<< 128) end
    end
  end

  describe "pad/2 (spec examples with b = 64)" do
    test "empty string becomes one block of zeros" do
      assert Encoding.pad("", 64) == :binary.copy(<<0>>, 64)
    end

    test "short input is zero-padded" do
      assert hex(Encoding.pad("JJJ", 64)) == "4a4a4a" <> String.duplicate("00", 61)
    end

    test "exact multiple is unchanged" do
      w64 = String.duplicate("W", 64)
      assert Encoding.pad(w64, 64) == w64
    end

    test "one byte over a block pads to two blocks" do
      assert Encoding.pad(String.duplicate("W", 65), 64) ==
               String.duplicate("W", 65) <> :binary.copy(<<0>>, 63)
    end

    test "rejects a non-positive block size" do
      assert_raise FunctionClauseError, fn -> Encoding.pad("x", 0) end
    end
  end

  describe "derive/3" do
    test "rejects tweaks outside a byte" do
      assert_raise FunctionClauseError, fn -> Encoding.derive("", :sha256, 256) end
      assert_raise FunctionClauseError, fn -> Encoding.derive("", :sha256, -1) end
    end

    test "rejects unsupported algorithms" do
      assert_raise ArgumentError, fn -> Encoding.derive("", :sha, 0) end
    end

    test "spec worked example: K_I and K_O for a 32-byte key" do
      key =
        Base.decode16!("27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91",
          case: :lower
        )

      padding = String.duplicate("00", 32)

      assert hex(Encoding.derive(key, :sha256, 0x55)) ==
               "72ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91" <> padding

      assert hex(Encoding.derive(key, :sha256, 0xAA)) ==
               "8dece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91" <> padding
    end
  end
end
