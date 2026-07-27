# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""NVIDIA OO Agents CLI — extensible command-line toolkit.

Usage:
    nooa eval --config config.yaml  # Run an eval-pipeline job
    nooa start-dev                  # Start the viewer
    nooa traces delete              # Delete traces
    nooa completion install         # Set up shell completions

Adding new commands:
    Drop a .py file in nooa_cli/commands/ — see commands/_template.py
    External packages can register a nooa.cli_commands entry point.

Shell completion:
    eval "$(_NOOA_COMPLETE=bash_source nooa)"    # bash
    eval "$(_NOOA_COMPLETE=zsh_source nooa)"     # zsh
"""

import click

from .commands import discover_commands, is_external_command
from .completion import completion

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}


# `completion` just emits a shell script and doesn't need the ~1.5s core
# import cost or secrets preload. External entry-point commands are also
# excluded by default below; they can explicitly call load_secrets_into_env()
# inside their handler if they need NOOA's layered secrets.
_SKIP_SECRETS_PRELOAD = {"completion"}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(package_name="nooa-cli")
@click.pass_context
def oo(ctx):
    """OO Agents — agent toolkit.

    Extensible CLI for running agents, evaluations, and trace management.
    Add commands from nooa_cli/commands/ or installed nooa.cli_commands
    entry points.
    """
    if ctx.invoked_subcommand in _SKIP_SECRETS_PRELOAD:
        return
    if ctx.invoked_subcommand is not None and is_external_command(
        oo.commands.get(ctx.invoked_subcommand)
    ):
        return
    # Load secrets.yaml into the process env before any subcommand runs so
    # all commands (config show, eval, …) see the same API keys.
    # Non-clobbering (shell env wins) and best-effort: a broken or missing
    # secrets file must never block the CLI — but log the failure at debug
    # so it's recoverable rather than silently swallowed.
    try:
        from nooa.secrets import load_secrets_into_env

        load_secrets_into_env()
    except Exception:
        import logging

        logging.getLogger(__name__).debug(
            "Failed to preload secrets.yaml into the environment", exc_info=True
        )


def _add_top_level_command(command: click.Command, *, name: str | None = None) -> None:
    command_name = command.name if name is None else name
    if not command_name:
        raise ValueError("Top-level nooa CLI commands must have a non-empty name.")
    if command_name in oo.commands:
        raise ValueError(f"Duplicate nooa CLI command name {command_name!r}.")
    oo.add_command(command, name=command_name)


# -- Built-in infrastructure commands reserve their top-level names. ----------
_add_top_level_command(completion)

# -- Auto-discover and register commands from modules and entry points. --------
for _name, _cmd in discover_commands():
    _add_top_level_command(_cmd, name=_name)


def main():
    """Entry point for console_scripts: nooa <subcommand>."""
    oo()
