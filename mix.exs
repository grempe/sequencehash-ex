defmodule SequenceHash.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/grempe/sequencehash-ex"

  def project do
    [
      app: :sequencehash,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "SequenceHash",
      source_url: @source_url,
      test_coverage: [
        summary: [threshold: 100],
        ignore_modules: [SequenceHash.Test.Vectors]
      ],
      dialyzer: [
        plt_local_path: "priv/plts",
        plt_add_apps: [:ex_unit, :stream_data],
        flags: [:error_handling, :extra_return, :missing_return, :unmatched_returns]
      ]
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  def cli do
    [preferred_envs: [check: :test]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  # `mix check` runs every gate that CI runs, in the test environment.
  defp aliases do
    [
      check: [
        "format --check-formatted",
        "deps.unlock --check-unused",
        # Hex's tasks are not found after `compile --force` prunes code paths.
        "hex.audit",
        "compile --warnings-as-errors --force",
        "credo --strict",
        "deps.audit",
        "dialyzer",
        "test --cover --warnings-as-errors"
      ]
    ]
  end

  defp description do
    "SequenceHash and SequenceMAC (c2sp.org/sequencehash): unambiguous hashing " <>
      "and MACs of sequences of byte strings, built on OTP :crypto."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Specification" => "https://c2sp.org/sequencehash",
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"],
      groups_for_modules: [
        API: [SequenceHash, SequenceHash.MAC],
        "Specification primitives": [
          SequenceHash.Algorithm,
          SequenceHash.Encoding,
          SequenceHash.SequenceFunction
        ]
      ]
    ]
  end
end
