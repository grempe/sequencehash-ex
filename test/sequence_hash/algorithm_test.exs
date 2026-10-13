defmodule SequenceHash.AlgorithmTest do
  use ExUnit.Case, async: true

  alias SequenceHash.Algorithm

  doctest Algorithm

  describe "sizes" do
    # The block and output sizes are copied from the specification. This test
    # checks that the local :crypto (OpenSSL) agrees and supports each hash.
    test "match :crypto.hash_info/1 for every supported algorithm" do
      for algorithm <- Algorithm.supported() do
        info = :crypto.hash_info(algorithm)
        assert Algorithm.block_size(algorithm) == info.block_size, inspect(algorithm)
        assert Algorithm.output_size(algorithm) == info.size, inspect(algorithm)
      end
    end

    test "every supported algorithm has an output of at least 32 bytes" do
      for algorithm <- Algorithm.supported() do
        assert Algorithm.output_size(algorithm) >= 32
      end
    end
  end

  describe "rejection" do
    test "insecure, short and unknown hashes are rejected" do
      for algorithm <- [:sha, :md5, :md4, :sha224, :sha3_224, :ripemd160, :sha384, nil] do
        assert_raise ArgumentError, ~r/unsupported hash algorithm/, fn ->
          Algorithm.validate!(algorithm)
        end
      end
    end

    test "values that are not atoms are rejected without being echoed" do
      for {value, kind} <- [
            {"secret key", "a binary"},
            {~c"secret", "a list"},
            {{:secret}, "a term"}
          ] do
        error = assert_raise ArgumentError, fn -> Algorithm.validate!(value) end
        assert Exception.message(error) =~ "must be an atom, got #{kind}"
        refute Exception.message(error) =~ "secret"
      end
    end

    test "size lookups reject unsupported hashes" do
      assert_raise ArgumentError, fn -> Algorithm.block_size(:sha) end
      assert_raise ArgumentError, fn -> Algorithm.output_size(:sha) end
    end

    test "is_supported/1 works as a guard" do
      require Algorithm

      check = fn
        algorithm when Algorithm.is_supported(algorithm) -> true
        _ -> false
      end

      assert check.(:sha256)
      refute check.(:sha)
    end
  end
end
