# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the CodeAct visibility and trust boundary.

``hidden`` controls what generated code can discover from prompt and namespace
surfaces. It is not process isolation: in-process CodeAct execution still gets
the live agent instance as ``self``.
"""

from __future__ import annotations

import json
from typing import Annotated

import pytest

from nooa import Agent, hidden, strategy
from nooa.config import CodeActConfig
from nooa.prompts import build_prompt_data
from nooa.strategies import CodeActStrategy
from nooa.unifiedllm import FakeLLMClient, LLMResponse, ToolCall

_DEFAULT_LLM = FakeLLMClient()


def _execute_python_response(code: str) -> LLMResponse:
    return LLMResponse(
        raw_response=None,
        content="",
        tool_calls=[
            ToolCall(
                id="call_exec",
                name="execute_python",
                arguments=json.dumps({"code": code}),
            )
        ],
        finish_reason="tool_calls",
        assistant_message={"role": "assistant", "content": ""},
    )


class _TrustBoundaryAgent(Agent, llm=_DEFAULT_LLM):
    visible_value: str
    hidden_value: Annotated[str, hidden]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.visible_value = "public-value"
        self.hidden_value = "victim-local-value"

    @strategy(CodeActStrategy(config=CodeActConfig(execution_backend="inprocess")))
    async def run(self) -> str:
        """Return the result."""
        ...


@pytest.mark.asyncio
async def test_hidden_field_is_not_rendered_in_codeact_prompt():
    agent = _TrustBoundaryAgent()

    data = await build_prompt_data(agent.run)

    assert "visible_value" in data.system_prompt
    assert "hidden_value" not in data.system_prompt


@pytest.mark.asyncio
async def test_known_hidden_field_is_reachable_through_self_inprocess():
    llm = FakeLLMClient(
        scripted_responses=[_execute_python_response("return_result(self.hidden_value)")]
    )
    agent = _TrustBoundaryAgent(llm=llm)

    result = await agent.run()

    assert result == "victim-local-value"
