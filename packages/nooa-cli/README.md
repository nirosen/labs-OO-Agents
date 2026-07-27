# nooa-cli

CLI for [nemo-oo-agents](https://github.com/NVIDIA-NeMo/labs-OO-Agents). Ships the `nooa` command with subcommands for running evaluations, browsing traces, and managing config.

## Install

```bash
uv add nooa-cli

# ...with numpy/pandas/plotly/scipy/sklearn pre-loaded into the LLM REPL
uv add "nooa-cli[datascience]"
```

`nooa-cli` automatically pulls in matching `nemo-oo-agents` (the core framework). The `[datascience]` extra adds libraries the LLM can use in REPL-generated code.

## Usage

```bash
nooa --help
nooa start-dev            # launch the trace viewer
nooa eval ...             # eval pipeline runner
nooa traces ...           # inspect/manage trace files
```

See the main repo [README](https://github.com/NVIDIA-NeMo/labs-OO-Agents/blob/main/README.md) for the framework documentation.

## External Commands

Installed packages can add top-level commands without modifying `nooa-cli`.
Register a `click.Command` or `click.Group` under the `nooa.cli_commands`
entry-point group:

```toml
[project.entry-points."nooa.cli_commands"]
audit = "acme_nooa.cli:audit"
```

The entry-point name becomes the top-level command name (`nooa audit ...`).
The `cli_` prefix distinguishes these shell commands from NOOA agent slash
commands. Names must be unique across built-in and external commands;
conflicting external entries, including the built-in `completion` command, are
skipped with a warning instead of overriding a trusted command or disabling the
CLI.

External commands are loaded only when invoked. They also do not inherit
NOOA's layered secrets preload by default; a command that needs those values
must call `nooa.secrets.load_secrets_into_env()` inside its own handler.
Because discovery stays lazy, top-level `nooa --help` shows a provider
placeholder for external commands until the command itself is selected.
