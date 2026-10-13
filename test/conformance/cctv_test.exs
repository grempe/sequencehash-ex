defmodule SequenceHash.Conformance.CCTVTest do
  @moduledoc """
  Runs every C2SP/CCTV SequenceHash vector (see test/vectors/cctv/SOURCE.md).

  Each vector is checked at every stage the vectors record: the inner header,
  the outer header, the inner hash and the final output, so a failure points
  at the step that broke.
  """
  use ExUnit.Case, async: true

  alias SequenceHash.{Algorithm, MAC, SequenceFunction}
  alias SequenceHash.Test.Vectors

  import Vectors, only: [hex: 1]

  for path <- Vectors.cctv_files(), do: @external_resource(path)
  @external_resource Path.join(Vectors.root(), "cctv/SHA256SUMS")

  test "vendored vector files match their recorded checksums" do
    dir = Path.join(Vectors.root(), "cctv")

    entries =
      dir
      |> Path.join("SHA256SUMS")
      |> File.read!()
      |> String.split("\n", trim: true)
      |> Enum.map(&String.split(&1, ~r/\s+/, parts: 2))

    assert length(entries) == length(Vectors.cctv_files())

    for [checksum, file] <- entries do
      actual = :crypto.hash(:sha256, File.read!(Path.join(dir, file)))
      assert Base.encode16(actual, case: :lower) == checksum, file
    end
  end

  for {file, vectors} <- Vectors.cctv(), {vector, index} <- Enum.with_index(vectors) do
    @vector vector
    @tag cctv: true
    test "#{file} ##{index}" do
      check(@vector)
    end
  end

  # SHA-1 is rejected by this library. The CCTV marks every SHA-1 vector as
  # may_fail, so rejecting it is compliant.
  defp check(%{"hash_name" => "sha1", "may_fail" => true}) do
    assert_raise ArgumentError, fn -> SequenceHash.new(:sha) end
  end

  # Keys shorter than 32 bytes must be rejected.
  defp check(%{"must_fail" => true, "function_id" => 1} = vector) do
    assert MAC.new(Vectors.algorithm(vector["hash_name"]), hex(vector["key"])) ==
             {:error, :key_too_short}
  end

  defp check(%{"must_fail" => false} = vector) do
    algorithm = Vectors.algorithm(vector["hash_name"])
    key = hex(vector["key"])
    customizer = hex(vector["customizer"])
    inputs = Enum.map(vector["inputs"], &hex/1)
    function_id = vector["function_id"]
    block_size = Algorithm.block_size(algorithm)

    assert SequenceFunction.inner_header(block_size, function_id, byte_size(key)) ==
             hex(vector["inner_header"])

    assert SequenceFunction.outer_header(
             block_size,
             function_id,
             byte_size(customizer),
             byte_size(key)
           ) ==
             hex(vector["outer_header"])

    state =
      Enum.reduce(
        inputs,
        SequenceFunction.new(algorithm, function_id, key),
        &SequenceFunction.add(&2, &1)
      )

    assert SequenceFunction.inner_hash(state) == hex(vector["inner_hash"])

    expected = hex(vector["final_output"])
    assert public_api(function_id, algorithm, key, inputs, customizer) == expected
  end

  defp public_api(2, algorithm, "", inputs, customizer) do
    SequenceHash.hash(algorithm, inputs, customizer: customizer)
  end

  defp public_api(1, algorithm, key, inputs, customizer) do
    {:ok, tag} = MAC.mac(algorithm, key, inputs, customizer: customizer)
    assert MAC.verify(algorithm, key, inputs, tag, customizer: customizer)
    tag
  end
end
