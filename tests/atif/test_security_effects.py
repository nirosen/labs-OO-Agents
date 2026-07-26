# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""ATIF export for hidden security-effect metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nooa import Agent, strategy
from nooa.atif import Trajectory, atif_scope
from nooa.atif.exporter import AtifExporter
from nooa.config import CodeActConfig
from nooa.events import AfterTurn, BeforeTurn, SystemPrompt, Task
from nooa.runtime.middleware import ExecutePythonContext
from nooa.security import EffectRecord, install_effect_recorder
from nooa.strategies import CodeActStrategy
from nooa.unifiedllm import FakeLLMClient, LLMResponse, ToolCall
from tests.atif.normative import assert_atif_normative


def _exec_tool_call(code: str, call_id: str = "call_exec") -> ToolCall:
    return ToolCall(id=call_id, name="execute_python", arguments=json.dumps({"code": code}))


def _ret_tool_call(result: object, call_id: str = "call_ret") -> ToolCall:
    return ToolCall(id=call_id, name="return_result", arguments=json.dumps({"result": result}))


def _resp(tool_calls: list[ToolCall] | None = None) -> LLMResponse:
    return LLMResponse(
        raw_response=None,
        content="",
        tool_calls=tool_calls or [],
        finish_reason="tool_calls" if tool_calls else "stop",
        assistant_message={"role": "assistant", "content": ""},
        usage={"prompt_tokens": 5, "completion_tokens": 1},
    )


class _SecurityEffectAgent(Agent, llm=FakeLLMClient()):
    @strategy(CodeActStrategy(config=CodeActConfig(max_iterations=3)))
    async def run(self, prompt: str) -> int:
        """Solve {prompt}."""
        ...


def test_effect_record_is_exported_in_extra_without_becoming_a_step(tmp_path: Path) -> None:
    exporter = AtifExporter(
        path=tmp_path / "trajectory.json",
        session_id="security-effects",
        agent_name="SecurityAgent",
        agent_version="0.1.0",
    )
    exporter._dispatch_event(SystemPrompt(content="system", generation_id=""))
    exporter._dispatch_event(Task(prompt="run"))
    exporter._dispatch_event(
        BeforeTurn(
            method_name="run",
            strategy="CodeActStrategy",
            generation_id="gen-1",
            parent_generation_id=None,
            turn_number=1,
        )
    )

    record = EffectRecord(
        effect_type="payment.process",
        target="invoice-42",
        decision="allowed",
        generation_id="gen-1",
        tool_call_id="tool-call-1",
        attributes={"receipt": "opaque-123"},
        metadata={"call_id": "agent-call-1"},
    )
    exporter._dispatch_event(record)
    exporter._dispatch_event(
        AfterTurn(
            method_name="run",
            strategy="CodeActStrategy",
            generation_id="gen-1",
            parent_generation_id=None,
            turn_number=1,
            is_final=True,
            success=True,
        )
    )

    loaded = Trajectory.model_validate_json(exporter.path.read_text())
    assert_atif_normative(loaded)
    assert [step.source for step in loaded.steps] == ["system", "user", "agent"]

    assert loaded.extra is not None
    root_effects = loaded.extra["security_effects"]
    assert len(root_effects) == 1
    assert root_effects[0]["effect_type"] == "payment.process"
    assert root_effects[0]["metadata"]["call_id"] == "agent-call-1"

    agent_step = loaded.steps[-1]
    assert agent_step.extra is not None
    step_effects = agent_step.extra["security_effects"]
    assert len(step_effects) == 1
    assert step_effects[0]["id"] == root_effects[0]["id"]


def test_effect_record_with_unknown_generation_stays_root_only(tmp_path: Path) -> None:
    exporter = AtifExporter(
        path=tmp_path / "trajectory.json",
        session_id="security-effects",
        agent_name="SecurityAgent",
        agent_version="0.1.0",
    )
    exporter._dispatch_event(
        BeforeTurn(
            method_name="run",
            strategy="CodeActStrategy",
            generation_id="gen-1",
            parent_generation_id=None,
            turn_number=1,
        )
    )
    exporter._dispatch_event(
        EffectRecord(
            effect_type="payment.process",
            generation_id="unknown-generation",
        )
    )
    exporter._dispatch_event(
        AfterTurn(
            method_name="run",
            strategy="CodeActStrategy",
            generation_id="gen-1",
            parent_generation_id=None,
            turn_number=1,
            is_final=True,
            success=True,
        )
    )

    loaded = Trajectory.model_validate_json(exporter.path.read_text())
    assert loaded.extra is not None
    assert len(loaded.extra["security_effects"]) == 1
    assert loaded.steps[-1].extra is not None
    assert "security_effects" not in loaded.steps[-1].extra


def test_unserializable_effect_record_metadata_does_not_break_atif(tmp_path: Path) -> None:
    exporter = AtifExporter(
        path=tmp_path / "trajectory.json",
        session_id="security-effects",
        agent_name="SecurityAgent",
        agent_version="0.1.0",
    )
    exporter._dispatch_event(
        EffectRecord(
            effect_type="payment.process",
            metadata={"unsafe": object()},
        )
    )

    assert exporter.get_trajectory().extra is None


@pytest.mark.asyncio
async def test_installed_effect_recorder_exports_real_codeact_lineage(tmp_path: Path) -> None:
    llm = FakeLLMClient(
        scripted_responses=[
            _resp(
                [
                    _exec_tool_call("x = 1 + 1", call_id="call_exec1"),
                    _ret_tool_call(2, call_id="call_ret1"),
                ]
            ),
        ]
    )
    agent = _SecurityEffectAgent(llm=llm)

    async def observer(_ctx: ExecutePythonContext) -> EffectRecord:
        return EffectRecord(effect_type="code.execute", decision="observed")

    uninstall = install_effect_recorder(agent.event_manager, observer)
    try:
        async with atif_scope(
            agent,
            path=tmp_path / "trajectory.json",
            session_id="security-effects-e2e",
            agent_name="_SecurityEffectAgent",
            agent_version="0.1.0",
        ):
            result = await agent.run("compute 1+1")
    finally:
        uninstall()

    assert result == 2
    loaded = Trajectory.model_validate_json((tmp_path / "trajectory.json").read_text())
    assert loaded.extra is not None
    effects = loaded.extra["security_effects"]
    effect_by_tool_call = {effect["tool_call_id"]: effect for effect in effects}
    assert "call_exec1" in effect_by_tool_call
    assert effect_by_tool_call["call_exec1"]["generation_id"]
    assert effect_by_tool_call["call_exec1"]["metadata"]["call_id"]
