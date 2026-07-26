# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Structured security-effect telemetry."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, JsonValue

from nooa.context_blocks import Metadata


class EffectRecord(Metadata):
    """Security-relevant effect observed at a framework choke point.

    This event is observed-effect telemetry, not an in-process integrity
    boundary. CodeAct can enumerate and reach ``self.event_manager`` in-process,
    and sandboxed execution can broker the same parent-side attribute access.
    A separately trusted sink may make a copy tamper-evident; NOOA's event store
    and ATIF export alone do not provide that guarantee.

    ``attributes`` must contain sanitized values only. Event storage and ATIF
    export do not apply trace secret scrubbing.

    Cross-process SQLite readers must import ``nooa.security`` to restore this
    concrete type. Without that import, the fields survive on a generic
    :class:`Metadata` instance.
    """

    model_config = {"extra": "forbid"}

    effect_type: str = Field(
        min_length=1,
        description="Application-defined effect category, e.g. 'fs.write' or 'payment.process'.",
    )
    target: str = Field(
        default="",
        description="Sanitized target identifier for the effect, if any.",
    )
    decision: Literal["allowed", "denied", "observed"] = Field(
        default="observed",
        description="Whether the observer saw an allowed, denied, or neutral effect.",
    )
    observer: str = Field(
        default="",
        description="Observer that produced this record, if known.",
    )
    generation_id: str = Field(
        default="",
        description="Generation session ID associated with the effect.",
    )
    tool_call_id: str = Field(
        default="",
        description="Tool call ID associated with the effect, if any.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined effect details.",
    )
