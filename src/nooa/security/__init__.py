# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security-oriented runtime primitives."""

from nooa.security.effects import EffectRecord
from nooa.security.install import EffectObservation, EffectObserver, install_effect_recorder
from nooa.security.sinks import (
    EffectRecordSinkBackend,
    EffectSink,
    JsonlEffectSink,
    install_effect_sink,
)

__all__ = [
    "EffectObservation",
    "EffectObserver",
    "EffectRecord",
    "EffectRecordSinkBackend",
    "EffectSink",
    "JsonlEffectSink",
    "install_effect_recorder",
    "install_effect_sink",
]
