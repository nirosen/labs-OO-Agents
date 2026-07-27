# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for structured security-effect telemetry."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nooa.context_blocks.models import Role
from nooa.events import ExecutionResult
from nooa.runtime.actor import ActorRuntime, _pop_generation_id, _push_generation_id
from nooa.runtime.context_vars import _pop_agent_call_id, _push_agent_call_id
from nooa.runtime.event_manager import EventManager
from nooa.runtime.middleware import AgentCallContext, ExecutePythonContext
from nooa.security import EffectRecord, install_agent_call_effect_recorder, install_effect_recorder
from nooa.storage.sqlite import SQLiteEventBackend


class _MockAgent:
    pass


def test_effect_record_is_hidden_metadata_with_strict_fields() -> None:
    record = EffectRecord(effect_type="payment.process", target="invoice-42")

    assert record._role == Role.METADATA
    assert record.event_type == "EffectRecord"
    assert record.observer == ""
    with pytest.raises(ValidationError):
        EffectRecord(effect_type="payment.process", typo="not-allowed")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        EffectRecord(effect_type="payment.process", attributes={"unsafe": object()})


def test_effect_record_round_trips_through_sqlite(sqlite_conn) -> None:
    backend = SQLiteEventBackend(sqlite_conn)
    record = EffectRecord(effect_type="payment.process", target="invoice-42")

    backend.store("1", record)

    restored = backend.get("1")
    assert isinstance(restored, EffectRecord)
    assert restored.effect_type == "payment.process"


@pytest.mark.asyncio
async def test_install_effect_recorder_adds_lineage_and_call_id() -> None:
    event_manager = EventManager()
    runtime = ActorRuntime(_MockAgent())
    observed_contexts: list[ExecutePythonContext] = []

    async def observer(ctx: ExecutePythonContext) -> EffectRecord:
        observed_contexts.append(ctx)
        return EffectRecord(
            effect_type="fs.write",
            target="/tmp/report.txt",
            decision="allowed",
            attributes={"bytes": 12},
        )

    uninstall = install_effect_recorder(event_manager, observer)
    _push_agent_call_id("agent-call-1")
    _push_generation_id("generation-1")
    try:
        ctx = ExecutePythonContext(
            code="write_report()",
            params={"tool_call_id": "tool-call-1"},
            runtime=runtime,
        )

        async def core(inner: ExecutePythonContext) -> ExecutePythonContext:
            inner.result = ExecutionResult(stdout="done")
            return inner

        result = await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        _pop_generation_id()
        _pop_agent_call_id()
        uninstall()

    assert result.result is not None
    assert observed_contexts == [ctx]
    records = event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EffectRecord)
    assert record.generation_id == "generation-1"
    assert record.tool_call_id == "tool-call-1"
    assert record.observer == "execute_python_middleware"
    assert record.metadata["call_id"] == "agent-call-1"


@pytest.mark.asyncio
async def test_effect_recorder_observer_errors_propagate() -> None:
    event_manager = EventManager()

    async def observer(_ctx: ExecutePythonContext) -> EffectRecord | None:
        raise RuntimeError("sink unavailable")

    uninstall = install_effect_recorder(event_manager, observer)
    try:
        ctx = ExecutePythonContext(code="1 + 1")

        async def core(inner: ExecutePythonContext) -> ExecutePythonContext:
            inner.result = ExecutionResult(stdout="done")
            return inner

        with pytest.raises(RuntimeError, match="sink unavailable"):
            await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        uninstall()


@pytest.mark.asyncio
async def test_effect_recorder_supports_multiple_records() -> None:
    event_manager = EventManager()

    def observer(_ctx: ExecutePythonContext) -> list[EffectRecord]:
        return [
            EffectRecord(effect_type="fs.write", target="/tmp/a"),
            EffectRecord(effect_type="net.request", target="service-b"),
        ]

    uninstall = install_effect_recorder(event_manager, observer)
    try:
        ctx = ExecutePythonContext(code="do_two_things()")

        async def core(inner: ExecutePythonContext) -> ExecutePythonContext:
            inner.result = ExecutionResult(stdout="done")
            return inner

        await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        uninstall()

    records = event_manager.filter(type="EffectRecord")
    assert [record.effect_type for record in records] == ["fs.write", "net.request"]


@pytest.mark.asyncio
async def test_effect_recorder_observes_replacement_context() -> None:
    event_manager = EventManager()
    observed_contexts: list[ExecutePythonContext] = []

    def observer(ctx: ExecutePythonContext) -> EffectRecord:
        observed_contexts.append(ctx)
        return EffectRecord(effect_type="code.execute")

    uninstall = install_effect_recorder(event_manager, observer)
    try:
        original = ExecutePythonContext(code="before()")
        replacement = ExecutePythonContext(code="after()", result=ExecutionResult(stdout="done"))

        async def core(_inner: ExecutePythonContext) -> ExecutePythonContext:
            return replacement

        result = await event_manager.run_middleware("execute_python", original, core)
    finally:
        uninstall()

    assert result is replacement
    assert observed_contexts == [replacement]


@pytest.mark.asyncio
async def test_effect_recorder_observes_wrapped_execution_failure() -> None:
    event_manager = EventManager()
    observed_contexts: list[ExecutePythonContext] = []

    def observer(ctx: ExecutePythonContext) -> EffectRecord:
        observed_contexts.append(ctx)
        return EffectRecord(effect_type="code.execute", decision="denied")

    uninstall = install_effect_recorder(event_manager, observer)
    try:
        ctx = ExecutePythonContext(code="raise RuntimeError('boom')")

        async def core(_inner: ExecutePythonContext) -> ExecutePythonContext:
            raise RuntimeError("execution failed")

        with pytest.raises(RuntimeError, match="execution failed"):
            await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        uninstall()

    assert observed_contexts == [ctx]
    records = event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    assert records[0].effect_type == "code.execute"


@pytest.mark.asyncio
async def test_install_agent_call_effect_recorder_adds_call_id_and_default_observer() -> None:
    event_manager = EventManager()
    observed_contexts: list[AgentCallContext] = []

    async def observer(ctx: AgentCallContext) -> EffectRecord:
        observed_contexts.append(ctx)
        return EffectRecord(
            effect_type="identity.grant_access",
            target="token-ref-1",
            decision="allowed",
            attributes={"resource": "prod-db"},
        )

    uninstall = install_agent_call_effect_recorder(event_manager, observer)
    _push_agent_call_id("agent-call-1")
    try:
        ctx = AgentCallContext(method_name="grant_access", args=("alice", "prod-db"), kwargs={})

        async def core(inner: AgentCallContext) -> AgentCallContext:
            inner.result = {"success": True}
            return inner

        result = await event_manager.run_middleware("agent_call", ctx, core)
    finally:
        _pop_agent_call_id()
        uninstall()

    assert result.result == {"success": True}
    assert observed_contexts == [ctx]
    records = event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EffectRecord)
    assert record.effect_type == "identity.grant_access"
    assert record.observer == "agent_call_middleware"
    assert record.metadata["call_id"] == "agent-call-1"


@pytest.mark.asyncio
async def test_agent_call_effect_recorder_observer_errors_propagate() -> None:
    event_manager = EventManager()

    async def observer(_ctx: AgentCallContext) -> EffectRecord | None:
        raise RuntimeError("sink unavailable")

    uninstall = install_agent_call_effect_recorder(event_manager, observer)
    try:
        ctx = AgentCallContext(method_name="grant_access")

        async def core(inner: AgentCallContext) -> AgentCallContext:
            inner.result = {"success": True}
            return inner

        with pytest.raises(RuntimeError, match="sink unavailable"):
            await event_manager.run_middleware("agent_call", ctx, core)
    finally:
        uninstall()


@pytest.mark.asyncio
async def test_agent_call_effect_recorder_supports_multiple_records() -> None:
    event_manager = EventManager()

    def observer(_ctx: AgentCallContext) -> tuple[EffectRecord, EffectRecord]:
        return (
            EffectRecord(effect_type="identity.lookup", target="alice"),
            EffectRecord(effect_type="identity.grant_access", target="prod-db"),
        )

    uninstall = install_agent_call_effect_recorder(event_manager, observer)
    try:
        ctx = AgentCallContext(method_name="grant_access")

        async def core(inner: AgentCallContext) -> AgentCallContext:
            inner.result = {"success": True}
            return inner

        await event_manager.run_middleware("agent_call", ctx, core)
    finally:
        uninstall()

    records = event_manager.filter(type="EffectRecord")
    assert [record.effect_type for record in records] == [
        "identity.lookup",
        "identity.grant_access",
    ]


@pytest.mark.asyncio
async def test_agent_call_effect_recorder_preserves_explicit_observer() -> None:
    event_manager = EventManager()

    def observer(_ctx: AgentCallContext) -> EffectRecord:
        return EffectRecord(effect_type="identity.grant_access", observer="iam_backend")

    uninstall = install_agent_call_effect_recorder(event_manager, observer)
    try:
        ctx = AgentCallContext(method_name="grant_access")

        async def core(inner: AgentCallContext) -> AgentCallContext:
            inner.result = {"success": True}
            return inner

        await event_manager.run_middleware("agent_call", ctx, core)
    finally:
        uninstall()

    records = event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    assert records[0].observer == "iam_backend"


@pytest.mark.asyncio
async def test_agent_call_effect_recorder_observes_replacement_context() -> None:
    event_manager = EventManager()
    observed_contexts: list[AgentCallContext] = []

    def observer(ctx: AgentCallContext) -> EffectRecord:
        observed_contexts.append(ctx)
        return EffectRecord(effect_type="identity.grant_access")

    uninstall = install_agent_call_effect_recorder(event_manager, observer)
    try:
        original = AgentCallContext(method_name="before")
        replacement = AgentCallContext(method_name="after", result={"success": True})

        async def core(_inner: AgentCallContext) -> AgentCallContext:
            return replacement

        result = await event_manager.run_middleware("agent_call", original, core)
    finally:
        uninstall()

    assert result is replacement
    assert observed_contexts == [replacement]


@pytest.mark.asyncio
async def test_agent_call_effect_recorder_observes_wrapped_method_failure() -> None:
    event_manager = EventManager()
    observed_contexts: list[AgentCallContext] = []

    def observer(ctx: AgentCallContext) -> EffectRecord:
        observed_contexts.append(ctx)
        return EffectRecord(effect_type="identity.grant_access", decision="denied")

    uninstall = install_agent_call_effect_recorder(event_manager, observer)
    try:
        ctx = AgentCallContext(method_name="grant_access")

        async def core(_inner: AgentCallContext) -> AgentCallContext:
            raise RuntimeError("method failed")

        with pytest.raises(RuntimeError, match="method failed"):
            await event_manager.run_middleware("agent_call", ctx, core)
    finally:
        uninstall()

    assert observed_contexts == [ctx]
    records = event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    assert records[0].effect_type == "identity.grant_access"
