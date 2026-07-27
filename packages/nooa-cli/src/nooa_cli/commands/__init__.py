# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Auto-discovered command modules for the nooa CLI.

╔══════════════════════════════════════════════════════════════════════╗
║                    HOW TO ADD A NEW COMMAND                         ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  1. Create a new .py file in this directory (commands/)              ║
║  2. Define a click command or group                                  ║
║  3. Assign it to a module-level variable named `command`             ║
║  4. That's it — it's automatically registered.                       ║
║                                                                      ║
║  See _template.py for a copy-paste starter.                          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

Convention
----------

Each Python file in this directory that does NOT start with ``_`` is
auto-discovered and registered as a top-level subcommand of ``nooa``.

A command module **must** export a module-level variable named ``command``
that is a ``click.BaseCommand`` (either a ``@click.command()`` or a
``@click.group()``).

Optionally, you can set:
    NAME = "custom-name"      # Override the command name (default: filename)

The file name (minus ``.py``) becomes the subcommand name by default::

    commands/start_dev.py →  nooa start-dev ...

Files starting with ``_`` are ignored (private helpers, templates, etc.).

External packages can also register top-level commands without modifying this
package by publishing a ``nooa.cli_commands`` entry point whose name is the
command name and whose value loads directly to a ``click.Command`` or
``click.Group``::

    [project.entry-points."nooa.cli_commands"]
    audit = "acme_nooa.cli:audit"

Built-in modules are discovered first, then external entry points in sorted
name order. External commands are represented by lazy proxies, so installing a
plugin does not add its import cost to every ``nooa`` invocation. Built-in
commands reserve their names; conflicting external entries are skipped with a
warning rather than overriding an existing command or disabling the CLI.

Minimal example (commands/hello.py)::

    import click

    @click.command()
    @click.argument("name", default="world")
    def command(name):
        \"\"\"Say hello.\"\"\"
        click.echo(f"Hello, {name}!")

Full example with a group (commands/things.py)::

    import click

    @click.group()
    def command():
        \"\"\"Manage things.\"\"\"

    @command.command()
    def list():
        \"\"\"List all things.\"\"\"
        click.echo("thing-1\\nthing-2")

    @command.command()
    @click.argument("name")
    def create(name):
        \"\"\"Create a new thing.\"\"\"
        click.echo(f"Created {name}")
"""

import importlib
import logging
import pkgutil
from collections.abc import Iterator
from importlib import metadata
from typing import Any

import click
from click.shell_completion import CompletionItem

EXTERNAL_COMMAND_ENTRY_POINT_GROUP = "nooa.cli_commands"
RESERVED_COMMAND_NAMES = frozenset({"completion"})

logger = logging.getLogger(__name__)


def _entry_point_distribution_name(entry_point: metadata.EntryPoint) -> str:
    dist = getattr(entry_point, "dist", None)
    name = getattr(dist, "name", None)
    if isinstance(name, str) and name:
        return name
    return "<unknown distribution>"


def _entry_point_source(entry_point: metadata.EntryPoint) -> str:
    return (
        f"entry point {entry_point.name!r} ({entry_point.value!r}) "
        f"from {_entry_point_distribution_name(entry_point)!r} "
        f"in group {EXTERNAL_COMMAND_ENTRY_POINT_GROUP!r}"
    )


def _entry_point_sort_key(entry_point: metadata.EntryPoint) -> tuple[str, str, str]:
    return (
        entry_point.name,
        _entry_point_distribution_name(entry_point).casefold(),
        entry_point.value,
    )


def _validate_command_name(name: object, *, source: str) -> str:
    if not isinstance(name, str) or not name:
        raise TypeError(f"{source}: command name must be a non-empty str, got {name!r}.")
    return name


def _validate_command(
    name: object,
    command: object,
    *,
    source: str,
) -> tuple[str, click.Command]:
    validated_name = _validate_command_name(name, source=source)

    if not isinstance(command, click.Command):
        raise TypeError(
            f"{source}: command must be a click.Command or click.Group, "
            f"got {type(command).__name__}. Use @click.command() or @click.group()."
        )

    return validated_name, command


class _LazyExternalCommand(click.Command):
    """Click command proxy that loads an external entry point on first use."""

    def __init__(self, entry_point: metadata.EntryPoint) -> None:
        self._entry_point = entry_point
        self._loaded_command: click.Command | None = None
        self._load_error: Exception | None = None
        super().__init__(
            name=entry_point.name,
            help=f"External command from {_entry_point_distribution_name(entry_point)}.",
        )

    def _load_command(self) -> click.Command:
        if self._loaded_command is not None:
            return self._loaded_command

        source = _entry_point_source(self._entry_point)
        if self._load_error is not None:
            raise click.ClickException(f"{source} failed to load: {self._load_error}") from self._load_error

        try:
            command = self._entry_point.load()
            _, validated_command = _validate_command(
                self._entry_point.name,
                command,
                source=source,
            )
        except Exception as exc:
            self._load_error = exc
            logger.warning("%s failed to load", source, exc_info=True)
            raise click.ClickException(f"{source} failed to load: {exc}") from exc

        self._loaded_command = validated_command
        return validated_command

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: click.Context | None = None,
        **extra: Any,
    ) -> click.Context:
        return self._load_command().make_context(info_name, args, parent=parent, **extra)

    def invoke(self, ctx: click.Context) -> Any:
        return self._load_command().invoke(ctx)

    def shell_complete(self, ctx: click.Context, incomplete: str) -> list[CompletionItem]:
        try:
            command = self._load_command()
        except click.ClickException:
            return []
        return command.shell_complete(ctx, incomplete)


def is_external_command(command: click.Command | None) -> bool:
    """Return whether ``command`` is a lazily loaded external CLI entry point."""
    return isinstance(command, _LazyExternalCommand)


def _discover_builtin_commands() -> Iterator[tuple[str, click.Command, str]]:
    package_path = __path__
    package_name = __name__

    for module_info in sorted(pkgutil.iter_modules(package_path), key=lambda info: info.name):
        # Skip private modules (_template, _helpers, etc.)
        if module_info.name.startswith("_"):
            continue

        module = importlib.import_module(f"{package_name}.{module_info.name}")

        # The module must export `command`
        cmd = getattr(module, "command", None)
        if cmd is None:
            continue

        source = f"commands/{module_info.name}.py"
        name = getattr(module, "NAME", module_info.name)
        validated_name, validated_command = _validate_command(name, cmd, source=source)
        yield validated_name, validated_command, source


def _discover_external_commands(
    occupied_sources: dict[str, str],
) -> Iterator[tuple[str, click.Command, str]]:
    try:
        entry_points = metadata.entry_points(group=EXTERNAL_COMMAND_ENTRY_POINT_GROUP)
    except Exception:
        logger.warning("Failed to enumerate external CLI command entry points", exc_info=True)
        return

    for entry_point in sorted(entry_points, key=_entry_point_sort_key):
        source = _entry_point_source(entry_point)
        try:
            name = _validate_command_name(entry_point.name, source=source)
        except TypeError:
            logger.warning("Skipping %s because its command name is invalid", source, exc_info=True)
            continue

        previous_source = occupied_sources.get(name)
        if previous_source is not None:
            logger.warning(
                "Skipping %s because command name %r conflicts with %s",
                source,
                name,
                previous_source,
            )
            continue

        occupied_sources[name] = source
        yield name, _LazyExternalCommand(entry_point), source


def discover_commands() -> Iterator[tuple[str, click.Command]]:
    """Yield built-in and external ``(name, command)`` pairs.

    Scans this directory for Python modules, imports each one, and looks for a
    ``command`` attribute that is a ``click.Command`` or ``click.Group``. Then
    it registers installed ``nooa.cli_commands`` entry points as lazy command
    proxies in stable name and distribution order.

    Modules starting with ``_`` are skipped (private / template files).
    Built-in duplicate names raise ``ValueError`` because they indicate a repo
    bug. External entries that collide with built-ins, reserved infrastructure
    commands, or another external package are skipped with a warning so a
    third-party install cannot replace a trusted command or disable the CLI.
    """
    occupied_sources = dict.fromkeys(RESERVED_COMMAND_NAMES, "reserved infrastructure command")
    for name, command, source in _discover_builtin_commands():
        previous_source = occupied_sources.get(name)
        if previous_source is not None:
            raise ValueError(
                f"Duplicate nooa CLI command name {name!r}: "
                f"{source} conflicts with {previous_source}."
            )
        occupied_sources[name] = source
        yield name, command

    for name, command, _source in _discover_external_commands(occupied_sources):
        yield name, command
