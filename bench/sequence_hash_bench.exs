# Benchmarks for SequenceHash and SequenceMAC.
#
#     mix run bench/sequence_hash_bench.exs
#
# Each scenario runs against the same inputs hashed directly with `:crypto`
# (`:crypto.hash/2` over the concatenated inputs), so the numbers show the
# overhead SequenceHash adds on top of the underlying hash: two hash
# computations, the header and key blocks, and one length suffix per input.
#
# Set BENCH_ALGORITHMS to a comma-separated list to narrow the run, for
# example `BENCH_ALGORITHMS=sha256,blake2b`, and BENCH_TIME to the seconds
# spent on each job (default 2).

algorithms =
  case System.get_env("BENCH_ALGORITHMS") do
    nil -> [:sha256, :blake2b]
    list -> list |> String.split(",", trim: true) |> Enum.map(&String.to_existing_atom/1)
  end

time = String.to_integer(System.get_env("BENCH_TIME", "2"))

inputs = %{
  "1 x 32 B" => [:crypto.strong_rand_bytes(32)],
  "1 x 1 MiB" => [:crypto.strong_rand_bytes(1024 * 1024)],
  "1,000 x 32 B" => for(_ <- 1..1_000, do: :crypto.strong_rand_bytes(32))
}

key = :crypto.strong_rand_bytes(32)

common = [time: time, warmup: 1, memory_time: 0.5, inputs: inputs, print: [fast_warning: false]]

for algorithm <- algorithms do
  IO.puts("\n## #{algorithm}\n")

  Benchee.run(
    %{
      ":crypto.hash (baseline)" => fn items -> :crypto.hash(algorithm, items) end,
      "SequenceHash.hash/2" => fn items -> SequenceHash.hash(algorithm, items) end,
      "SequenceHash.MAC.mac/3" => fn items -> SequenceHash.MAC.mac(algorithm, key, items) end
    },
    common
  )
end

IO.puts("\n## Setup cost: new/1 then result/1 with no inputs\n")

Benchee.run(
  Map.new(algorithms, fn algorithm ->
    {"#{algorithm}", fn -> algorithm |> SequenceHash.new() |> SequenceHash.result() end}
  end),
  Keyword.delete(common, :inputs)
)
