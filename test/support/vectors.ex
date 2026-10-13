defmodule SequenceHash.Test.Vectors do
  @moduledoc false
  # Loads the vendored test vector files under test/vectors.

  @root Path.expand("../vectors", __DIR__)

  def root, do: @root

  @doc "All CCTV vector files as `{relative_path, [vector]}`."
  def cctv do
    for path <- cctv_files() do
      {Path.relative_to(path, Path.join(@root, "cctv")), path |> File.read!() |> JSON.decode!()}
    end
  end

  def cctv_files, do: Path.wildcard(Path.join(@root, "cctv/{hash,mac}/*.json"))

  @doc "The reference vectors for long customization strings."
  def long_customizer do
    @root |> Path.join("reference/long_customizer.json") |> File.read!() |> JSON.decode!()
  end

  @doc "Maps a vector's hash name to its `:crypto` algorithm name."
  def algorithm("sha1"), do: :sha
  def algorithm(name), do: String.to_existing_atom(name)

  def hex(string), do: Base.decode16!(string, case: :mixed)
end
