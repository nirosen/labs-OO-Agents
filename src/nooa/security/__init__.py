# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security-oriented runtime primitives."""

from nooa.security.effects import EffectRecord
from nooa.security.findings import SecurityFinding
from nooa.security.install import (
    AgentCallEffectObserver,
    EffectObservation,
    EffectObserver,
    install_agent_call_effect_recorder,
    install_effect_recorder,
)
from nooa.security.receipts import SecurityReceipt
from nooa.security.sinks import (
    EffectRecordSinkBackend,
    EffectSink,
    JsonlEffectSink,
    install_effect_sink,
)

__all__ = [
    "AgentCallEffectObserver",
    "EffectObservation",
    "EffectObserver",
    "EffectRecord",
    "EffectRecordSinkBackend",
    "EffectSink",
    "JsonlEffectSink",
    "SecurityFinding",
    "SecurityReceipt",
    "install_agent_call_effect_recorder",
    "install_effect_recorder",
    "install_effect_sink",
]
