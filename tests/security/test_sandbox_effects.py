# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for sandbox construction security-effect telemetry."""

from __future__ import annotations

from typing import Any, cast

import pytest

from nooa.config import CodeActConfig
from nooa.runtime.context_vars import _pop_agent_call_id, _push_agent_call_id
from nooa.runtime.event_manager import EventManager
from nooa.runtime.sandbox.config import SandboxConfig
from nooa.runtime.sandbox.errors import SandboxUnavailable
from nooa.runtime.sandbox.executor import SandboxedExecutor
from nooa.runtime.sandbox.guards import Capabilities
from nooa.security import EffectRecord
from nooa.strategies.codeact import CodeActStrategy
from nooa.strategies.current_call import CurrentCall


@pytest.fixture
def degraded_caps(monkeypatch: pytest.MonkeyPatch) -> Capabilities:
    from nooa.runtime.sandbox import executor as executor_module

    caps = Capabilities(linux=True, landlock_abi=0, seccomp=False, rlimit=True)
    monkeypatch.setattr(executor_module, "_CAPS_CACHE", caps)
    return caps


@pytest.fixture
def enforceable_caps(monkeypatch: pytest.MonkeyPatch) -> Capabilities:
    from nooa.runtime.sandbox import executor as executor_module

    caps = Capabilities(linux=True, landlock_abi=1, seccomp=True, rlimit=True)
    monkeypatch.setattr(executor_module, "_CAPS_CACHE", caps)
    return caps


def _degraded_config(*, require: bool = False) -> SandboxConfig:
    return SandboxConfig(require=require, filesystem=True, network=False)


def test_degraded_executor_records_host_construction_state(
    degraded_caps: Capabilities,
) -> None:
    del degraded_caps
    event_manager = EventManager()
    _push_agent_call_id("agent-call-1")
    try:
        executor = SandboxedExecutor(
            object(),
            _degraded_config(),
            cell_timeout=5.0,
            event_manager=event_manager,
            construction_generation_id="generation-1",
        )
    finally:
        _pop_agent_call_id()

    try:
        assert executor.degraded_guards == [
            "filesystem (Landlock unavailable)",
            "network isolation (seccomp unavailable)",
        ]
        records = event_manager.filter(type="EffectRecord")
        assert len(records) == 1
        record = records[0]
        assert isinstance(record, EffectRecord)
        assert record.effect_type == "sandbox.degraded"
        assert record.decision == "observed"
        assert record.observer == "sandbox_executor"
        assert record.generation_id == "generation-1"
        assert record.tool_call_id == ""
        assert record.attributes == {
            "unenforceable": [
                "filesystem (Landlock unavailable)",
                "network isolation (seccomp unavailable)",
            ]
        }
        assert record.metadata["call_id"] == "agent-call-1"
    finally:
        executor.close_sync()


def test_require_true_remains_fail_closed_without_degraded_record(
    degraded_caps: Capabilities,
) -> None:
    del degraded_caps
    event_manager = EventManager()

    with pytest.raises(SandboxUnavailable):
        SandboxedExecutor(
            object(),
            _degraded_config(require=True),
            cell_timeout=5.0,
            event_manager=event_manager,
            construction_generation_id="generation-1",
        )

    assert event_manager.filter(type="EffectRecord") == []


def test_degraded_executor_without_manager_preserves_legacy_behavior(
    degraded_caps: Capabilities,
) -> None:
    del degraded_caps

    executor = SandboxedExecutor(
        object(),
        _degraded_config(),
        cell_timeout=5.0,
    )
    try:
        assert executor.degraded_guards == [
            "filesystem (Landlock unavailable)",
            "network isolation (seccomp unavailable)",
        ]
    finally:
        executor.close_sync()


def test_enforceable_executor_does_not_emit_degraded_record(
    enforceable_caps: Capabilities,
) -> None:
    del enforceable_caps
    event_manager = EventManager()

    executor = SandboxedExecutor(
        object(),
        _degraded_config(),
        cell_timeout=5.0,
        event_manager=event_manager,
        construction_generation_id="generation-1",
    )
    try:
        assert executor.degraded_guards == []
        assert event_manager.filter(type="EffectRecord") == []
    finally:
        executor.close_sync()


def test_explicit_degraded_recording_error_propagates(
    degraded_caps: Capabilities,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del degraded_caps
    event_manager = EventManager()

    def fail_add(_event: Any, *, record: bool = True) -> str:
        del record
        raise RuntimeError("sink unavailable")

    monkeypatch.setattr(event_manager, "add", fail_add)

    with pytest.raises(RuntimeError, match="sink unavailable"):
        SandboxedExecutor(
            object(),
            _degraded_config(),
            cell_timeout=5.0,
            event_manager=event_manager,
        )


def test_codeact_wires_sandbox_construction_lineage(
    degraded_caps: Capabilities,
) -> None:
    del degraded_caps

    class _Runtime:
        def __init__(self) -> None:
            self.agent = object()
            self.event_manager = EventManager()

        def get_generation_id(self) -> str:
            return "generation-from-runtime"

    runtime = _Runtime()
    strategy = CodeActStrategy(
        config=CodeActConfig(
            execution_backend="sandbox",
            sandbox=_degraded_config(),
        )
    )
    call = CurrentCall(id="call-1", method_name="run", decorator="plan")

    executor = strategy._create_sandbox_executor(cast(Any, runtime), call, {})
    try:
        records = runtime.event_manager.filter(type="EffectRecord")
        assert len(records) == 1
        record = records[0]
        assert isinstance(record, EffectRecord)
        assert record.effect_type == "sandbox.degraded"
        assert record.generation_id == "generation-from-runtime"
    finally:
        executor.close_sync()
