# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for built-in and external nooa CLI command discovery."""

import logging
from dataclasses import dataclass
from typing import Any

import click
import pytest
from click.testing import CliRunner


@click.command()
def _alpha_command() -> None:
    click.echo("alpha")


@click.command()
def _zeta_command() -> None:
    click.echo("zeta")


@dataclass
class _FakeDistribution:
    name: str


@dataclass
class _FakeEntryPoint:
    name: str
    value: str
    loaded: Any
    distribution_name: str = "test-plugin"
    load_calls: int = 0

    @property
    def dist(self) -> _FakeDistribution:
        return _FakeDistribution(self.distribution_name)

    def load(self) -> Any:
        self.load_calls += 1
        return self.loaded


def _patch_entry_points(monkeypatch: pytest.MonkeyPatch, *entry_points: _FakeEntryPoint):
    import nooa_cli.commands as command_module

    def fake_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == command_module.EXTERNAL_COMMAND_ENTRY_POINT_GROUP
        return list(entry_points)

    monkeypatch.setattr(command_module.metadata, "entry_points", fake_entry_points)
    return command_module


def test_external_commands_are_lazy_and_discovered_in_stable_name_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zeta_entry_point = _FakeEntryPoint("zeta", "pkg.cli:zeta", _zeta_command)
    alpha_entry_point = _FakeEntryPoint("alpha", "pkg.cli:alpha", _alpha_command)
    command_module = _patch_entry_points(monkeypatch, zeta_entry_point, alpha_entry_point)

    commands = list(command_module.discover_commands())
    names = [name for name, _ in commands]

    assert names[-2:] == ["alpha", "zeta"]
    assert alpha_entry_point.load_calls == 0
    assert zeta_entry_point.load_calls == 0
    assert command_module.is_external_command(dict(commands)["alpha"])
    assert command_module.is_external_command(dict(commands)["zeta"])


def test_external_command_loads_only_when_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    entry_point = _FakeEntryPoint("audit", "pkg.cli:audit", _alpha_command)
    command_module = _patch_entry_points(monkeypatch, entry_point)
    command = dict(command_module.discover_commands())["audit"]

    result = CliRunner().invoke(command, [])

    assert result.exit_code == 0
    assert result.output == "alpha\n"
    assert entry_point.load_calls == 1


def test_root_help_does_not_load_external_command() -> None:
    import nooa_cli
    import nooa_cli.commands as command_module

    entry_point = _FakeEntryPoint("external-help-test", "pkg.cli:help", _alpha_command)
    command = command_module._LazyExternalCommand(entry_point)
    nooa_cli.oo.add_command(command, name=entry_point.name)
    try:
        result = CliRunner().invoke(nooa_cli.oo, ["--help"])
    finally:
        nooa_cli.oo.commands.pop(entry_point.name, None)

    assert result.exit_code == 0
    assert entry_point.name in result.output
    assert entry_point.load_calls == 0


def test_invalid_external_command_isolated_to_invocation(monkeypatch: pytest.MonkeyPatch) -> None:
    entry_point = _FakeEntryPoint("audit", "pkg.cli:audit", object())
    command_module = _patch_entry_points(monkeypatch, entry_point)
    command = dict(command_module.discover_commands())["audit"]

    result = CliRunner().invoke(command, [])

    assert result.exit_code != 0
    assert "command must be a click.Command or click.Group" in result.output


def test_external_command_load_failure_isolated_to_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenEntryPoint(_FakeEntryPoint):
        def load(self) -> Any:
            self.load_calls += 1
            raise ImportError("broken package")

    entry_point = _BrokenEntryPoint("audit", "pkg.cli:audit", None)
    command_module = _patch_entry_points(monkeypatch, entry_point)
    command = dict(command_module.discover_commands())["audit"]

    result = CliRunner().invoke(command, [])

    assert result.exit_code != 0
    assert "failed to load: broken package" in result.output


def test_broken_external_command_shell_completion_degrades_to_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenEntryPoint(_FakeEntryPoint):
        def load(self) -> Any:
            self.load_calls += 1
            raise ImportError("broken package")

    entry_point = _BrokenEntryPoint("audit", "pkg.cli:audit", None)
    command_module = _patch_entry_points(monkeypatch, entry_point)
    command = dict(command_module.discover_commands())["audit"]

    completions = command.shell_complete(click.Context(command), "--")

    assert completions == []
    assert entry_point.load_calls == 1


def test_external_entry_point_enumeration_failure_keeps_builtins_available(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import nooa_cli.commands as command_module

    def broken_entry_points(*, group: str) -> list[_FakeEntryPoint]:
        assert group == command_module.EXTERNAL_COMMAND_ENTRY_POINT_GROUP
        raise RuntimeError("broken metadata")

    monkeypatch.setattr(command_module.metadata, "entry_points", broken_entry_points)

    with caplog.at_level(logging.WARNING):
        commands = list(command_module.discover_commands())

    assert "eval" in [name for name, _ in commands]
    assert "Failed to enumerate external CLI command entry points" in caplog.text


def test_external_command_cannot_override_builtin(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    entry_point = _FakeEntryPoint("eval", "pkg.cli:eval", _alpha_command)
    command_module = _patch_entry_points(monkeypatch, entry_point)

    with caplog.at_level(logging.WARNING):
        commands = list(command_module.discover_commands())

    assert [name for name, _ in commands].count("eval") == 1
    assert entry_point.load_calls == 0
    assert "conflicts with commands/eval.py" in caplog.text


def test_external_command_collision_uses_distribution_name_tiebreak(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    later_entry_point = _FakeEntryPoint(
        "audit",
        "z_pkg.cli:audit",
        _zeta_command,
        distribution_name="z-plugin",
    )
    first_entry_point = _FakeEntryPoint(
        "audit",
        "a_pkg.cli:audit",
        _alpha_command,
        distribution_name="a-plugin",
    )
    command_module = _patch_entry_points(monkeypatch, later_entry_point, first_entry_point)

    with caplog.at_level(logging.WARNING):
        command = dict(command_module.discover_commands())["audit"]
    result = CliRunner().invoke(command, [])

    assert result.exit_code == 0
    assert result.output == "alpha\n"
    assert first_entry_point.load_calls == 1
    assert later_entry_point.load_calls == 0
    assert "z-plugin" in caplog.text
    assert "a-plugin" in caplog.text


def test_completion_name_is_reserved_for_builtin_infrastructure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    entry_point = _FakeEntryPoint("completion", "pkg.cli:completion", _alpha_command)
    command_module = _patch_entry_points(monkeypatch, entry_point)

    with caplog.at_level(logging.WARNING):
        commands = list(command_module.discover_commands())

    assert "completion" not in [name for name, _ in commands]
    assert entry_point.load_calls == 0
    assert "reserved infrastructure command" in caplog.text


def test_external_command_does_not_preload_nooa_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import nooa_cli
    import nooa_cli.commands as command_module

    import nooa.secrets

    preload_calls: list[bool] = []
    monkeypatch.setattr(
        nooa.secrets,
        "load_secrets_into_env",
        lambda: preload_calls.append(True),
    )

    entry_point = _FakeEntryPoint("external-test", "pkg.cli:external", _alpha_command)
    command = command_module._LazyExternalCommand(entry_point)
    nooa_cli.oo.add_command(command, name=entry_point.name)
    try:
        result = CliRunner().invoke(nooa_cli.oo, [entry_point.name])
    finally:
        nooa_cli.oo.commands.pop(entry_point.name, None)

    assert result.exit_code == 0
    assert preload_calls == []
