# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for built-in security observers."""

from __future__ import annotations

import pytest

from nooa import Agent
from nooa.errors import RestrictedCodeError, ValidationError, XMLFormatError
from nooa.events import ExecutionResult
from nooa.runtime.event_manager import EventManager
from nooa.runtime.middleware import ExecutePythonContext
from nooa.runtime.sandbox.errors import (
    CellMemoryError,
    CellSerializationError,
    CellTimeoutError,
    WorkerDiedError,
)
from nooa.runtime.sandbox.executor import SandboxedExecutor
from nooa.security import EffectRecord, framework_guard_observer, install_effect_recorder
from nooa.unifiedllm import FakeLLMClient


class _GuardObserverAgent(Agent, llm=FakeLLMClient()):
    pass


@pytest.mark.parametrize(
    ("error", "effect_type", "decision"),
    [
        (RestrictedCodeError("forbidden"), "code.validation", "denied"),
        (ValidationError("invalid"), "code.validation", "denied"),
        (XMLFormatError("invalid xml"), "code.validation", "denied"),
        (CellTimeoutError("timed out"), "code.timeout", "observed"),
        (CellMemoryError("memory limit"), "sandbox.memory", "observed"),
        (WorkerDiedError("worker exited"), "sandbox.worker", "observed"),
    ],
)
def test_framework_guard_observer_records_builtin_guard_outcomes(
    error: Exception,
    effect_type: str,
    decision: str,
) -> None:
    record = framework_guard_observer(
        ExecutePythonContext(
            code="dangerous()",
            result=ExecutionResult(error=error),
        )
    )

    assert record is not None
    assert record.effect_type == effect_type
    assert record.target == ""
    assert record.decision == decision
    assert record.observer == "framework_guard"
    assert record.attributes == {"error_type": type(error).__name__}


def test_framework_guard_observer_ignores_success_application_and_plumbing_errors() -> None:
    assert framework_guard_observer(ExecutePythonContext(code="1 + 1")) is None
    assert (
        framework_guard_observer(
            ExecutePythonContext(
                code="raise ValueError('bad input')",
                result=ExecutionResult(error=ValueError("bad input")),
            )
        )
        is None
    )
    assert (
        framework_guard_observer(
            ExecutePythonContext(
                code="await client.get('/slow')",
                result=ExecutionResult(error=TimeoutError("application timeout")),
            )
        )
        is None
    )
    assert (
        framework_guard_observer(
            ExecutePythonContext(
                code="return_result(unpicklable)",
                result=ExecutionResult(error=CellSerializationError("not picklable")),
            )
        )
        is None
    )


def test_framework_guard_observer_records_sandbox_synthesized_memory_error() -> None:
    executor = object.__new__(SandboxedExecutor)
    executor._disabled = False
    result = executor._synth_error(CellMemoryError("memory limit"))

    record = framework_guard_observer(ExecutePythonContext(code="allocate()", result=result))

    assert record is not None
    assert record.effect_type == "sandbox.memory"
    assert record.attributes == {"error_type": "CellMemoryError"}
    assert record.decision == "observed"


@pytest.mark.asyncio
async def test_framework_guard_observer_installs_through_effect_recorder() -> None:
    event_manager = EventManager()
    uninstall = install_effect_recorder(event_manager, framework_guard_observer)
    try:
        ctx = ExecutePythonContext(code="eval('1 + 1')")

        async def core(inner: ExecutePythonContext) -> ExecutePythonContext:
            inner.result = ExecutionResult(error=RestrictedCodeError("eval() is forbidden"))
            return inner

        await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        uninstall()

    records = event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EffectRecord)
    assert record.effect_type == "code.validation"
    assert record.observer == "framework_guard"
    assert record.decision == "denied"


@pytest.mark.asyncio
async def test_framework_guard_observer_records_real_validator_denial() -> None:
    agent = _GuardObserverAgent()
    uninstall = install_effect_recorder(agent.event_manager, framework_guard_observer)
    try:
        result = await agent.runtime.execute_code("eval('1 + 1')")
    finally:
        uninstall()

    assert isinstance(result.error, RestrictedCodeError)
    records = agent.event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EffectRecord)
    assert record.effect_type == "code.validation"
    assert record.attributes == {"error_type": "RestrictedCodeError"}
    assert record.decision == "denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("wrap_in_function", [True, False])
async def test_framework_guard_observer_records_real_inprocess_timeout(
    wrap_in_function: bool,
) -> None:
    agent = _GuardObserverAgent()
    uninstall = install_effect_recorder(agent.event_manager, framework_guard_observer)
    try:
        result = await agent.runtime.execute_code(
            "await asyncio.sleep(10)",
            wrap_in_function=wrap_in_function,
            timeout=0.01,
        )
    finally:
        uninstall()

    assert isinstance(result.error, CellTimeoutError)
    assert isinstance(result.error, TimeoutError)
    records = agent.event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EffectRecord)
    assert record.effect_type == "code.timeout"
    assert record.attributes == {"error_type": "CellTimeoutError"}
    assert record.decision == "observed"


@pytest.mark.asyncio
@pytest.mark.parametrize("wrap_in_function", [True, False])
async def test_framework_guard_observer_ignores_real_application_timeout(
    wrap_in_function: bool,
) -> None:
    agent = _GuardObserverAgent()
    uninstall = install_effect_recorder(agent.event_manager, framework_guard_observer)
    try:
        result = await agent.runtime.execute_code(
            "await asyncio.sleep(0)\nraise TimeoutError('application timeout')",
            wrap_in_function=wrap_in_function,
            timeout=1.0,
        )
    finally:
        uninstall()

    assert type(result.error) is TimeoutError
    assert agent.event_manager.filter(type="EffectRecord") == []


@pytest.mark.asyncio
async def test_framework_guard_observer_does_not_authenticate_generated_exception_origin() -> None:
    agent = _GuardObserverAgent()
    uninstall = install_effect_recorder(agent.event_manager, framework_guard_observer)
    try:
        result = await agent.runtime.execute_code(
            "from nooa.runtime.sandbox.errors import CellTimeoutError\n"
            "raise CellTimeoutError('forged timeout')"
        )
    finally:
        uninstall()

    assert isinstance(result.error, CellTimeoutError)
    records = agent.event_manager.filter(type="EffectRecord")
    assert len(records) == 1
    record = records[0]
    assert isinstance(record, EffectRecord)
    assert record.effect_type == "code.timeout"
    assert record.observer == "framework_guard"
    assert record.decision == "observed"
    assert record.attributes == {"error_type": "CellTimeoutError"}
