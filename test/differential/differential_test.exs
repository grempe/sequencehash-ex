defmodule SequenceHash.DifferentialTest do
  @moduledoc """
  Differential tests against the upstream reference implementations.

  Every generated case is computed by this library and by each reference
  oracle, and the outputs must be identical. The oracles wrap
  trailofbits/sequencehash-py (`oracle.py`) and trailofbits/sequencehash-rs
  (`oracle_rs/`), which share a line protocol described in `oracle.py`.

  These tests need Python and Rust, so they are excluded by default. Run them
  with:

      SEQUENCEHASH_PY=/path/to/sequencehash-py mix test.differential

  Environment variables:

    * `SEQUENCEHASH_PY` - path to a sequencehash-py checkout (required when
      the Python oracle is selected).
    * `SEQUENCEHASH_ORACLES` - comma-separated oracles to compare against
      (default `python,rust`).
    * `SEQUENCEHASH_RUNS` - generated cases per property (default `1000`).

  The Rust oracle pins its sequencehash-rs revision in `oracle_rs/Cargo.toml`
  and is built with Cargo on first use. As with every test, `--seed` replays
  a run.
  """
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias SequenceHash.{Algorithm, MAC}

  @moduletag :differential
  @moduletag timeout: :infinity

  @here __DIR__
  @oracles ~w(python rust)

  setup_all do
    oracles = selected_oracles()
    %{commands: Map.new(oracles, &{&1, prepare!(&1)})}
  end

  # Ports deliver replies to the process that opened them, so each test
  # starts its own oracles. They exit when the test process does.
  setup %{commands: commands} do
    %{oracles: Map.new(commands, fn {name, command} -> {name, open(command)} end)}
  end

  property "SequenceHash matches the references", %{oracles: oracles} do
    check all algorithm <- algorithm(),
              customizer <- customizer(algorithm),
              inputs <- inputs(),
              max_runs: runs() do
      expected = SequenceHash.hash(algorithm, inputs, customizer: customizer)

      for {name, port} <- oracles do
        assert {name, ask(port, algorithm, "", customizer, inputs)} == {name, hex(expected)}
      end
    end
  end

  property "SequenceMAC matches the references, including key rejection", %{oracles: oracles} do
    check all algorithm <- algorithm(),
              key <- key(algorithm),
              customizer <- customizer(algorithm),
              inputs <- inputs(),
              max_runs: runs() do
      case MAC.mac(algorithm, key, inputs, customizer: customizer) do
        {:ok, tag} ->
          for {name, port} <- oracles do
            answer = ask(port, algorithm, key, customizer, inputs)
            assert {name, answer} == {name, hex(tag)}
            # The reference's tag must also pass our constant-time check.
            assert MAC.verify(algorithm, key, inputs, Base.decode16!(answer, case: :lower),
                     customizer: customizer
                   )
          end

        {:error, :key_too_short} ->
          for {name, port} <- oracles do
            assert {name, ask(port, algorithm, key, customizer, inputs)} == {name, "error"}
          end
      end
    end
  end

  ## Generators
  #
  # Lengths are biased towards the block-size boundaries where key and
  # customizer derivation switch between padding and hashing.

  defp algorithm, do: member_of(Algorithm.supported())

  defp inputs do
    list_of(binary_of_length(one_of([integer(0..8), integer(0..300)])), max_length: 8)
  end

  defp customizer(algorithm) do
    b = Algorithm.block_size(algorithm)
    binary_of_length(one_of([member_of([0, 1, b - 1, b, b + 1, 2 * b]), integer(0..(3 * b))]))
  end

  # Mostly valid keys, around the output and block sizes, plus some keys
  # shorter than the 32-byte minimum, which every implementation must reject.
  defp key(algorithm) do
    b = Algorithm.block_size(algorithm)
    l = Algorithm.output_size(algorithm)
    min = MAC.min_key_length()

    lengths =
      frequency([
        {3, member_of([min, l, b - 1, b, b + 1, 2 * b])},
        {3, integer(min..(3 * b))},
        {1, integer(1..(min - 1))}
      ])

    binary_of_length(lengths)
  end

  defp binary_of_length(lengths), do: bind(lengths, &binary(length: &1))

  ## Oracles

  defp selected_oracles do
    names =
      "SEQUENCEHASH_ORACLES" |> System.get_env("python,rust") |> String.split(",", trim: true)

    case names -- @oracles do
      [] -> names
      unknown -> flunk("unknown oracles #{inspect(unknown)}; choose from #{inspect(@oracles)}")
    end
  end

  # Returns `{executable, args}` for an oracle, building it if needed.
  defp prepare!("python") do
    checkout =
      System.get_env("SEQUENCEHASH_PY") ||
        flunk("set SEQUENCEHASH_PY to a sequencehash-py checkout, or SEQUENCEHASH_ORACLES=rust")

    unless File.regular?(Path.join(checkout, "sequencehash.py")) do
      flunk("no sequencehash.py in SEQUENCEHASH_PY=#{checkout}")
    end

    {find!("python3"), ["-I", Path.join(@here, "oracle.py"), checkout]}
  end

  defp prepare!("rust") do
    target = Path.join(Mix.Project.build_path(), "oracle_rs")

    {output, status} =
      System.cmd(find!("cargo"), ["build", "--release", "--quiet", "--locked"],
        cd: Path.join(@here, "oracle_rs"),
        env: [{"CARGO_TARGET_DIR", target}],
        stderr_to_stdout: true
      )

    if status != 0, do: flunk("building the Rust oracle failed:\n#{output}")
    {Path.join(target, "release/sequencehash-oracle"), []}
  end

  defp find!(program) do
    System.find_executable(program) || flunk("#{program} not found on PATH")
  end

  defp open({executable, args}) do
    Port.open({:spawn_executable, executable}, [:binary, :exit_status, line: 65_536, args: args])
  end

  defp ask(port, algorithm, key, customizer, inputs) do
    fields = [Atom.to_string(algorithm), hex(key), hex(customizer) | Enum.map(inputs, &hex/1)]
    true = Port.command(port, [Enum.intersperse(fields, ?\t), ?\n])
    receive_line(port, [])
  end

  defp receive_line(port, acc) do
    receive do
      {^port, {:data, {:noeol, chunk}}} -> receive_line(port, [acc | chunk])
      {^port, {:data, {:eol, chunk}}} -> IO.iodata_to_binary([acc | chunk])
      {^port, {:exit_status, status}} -> flunk("oracle exited with status #{status}")
    after
      30_000 -> flunk("oracle did not answer")
    end
  end

  defp runs, do: "SEQUENCEHASH_RUNS" |> System.get_env("1000") |> String.to_integer()

  defp hex(binary), do: Base.encode16(binary, case: :lower)
end
