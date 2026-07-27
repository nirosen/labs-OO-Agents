# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security-oriented runtime primitives."""

from nooa.security.effects import EffectRecord
from nooa.security.egress import (
    DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES,
    EFFECT_EGRESS_FRAME_KEYS,
    EFFECT_EGRESS_RECORD_EVENT_TYPE,
    EFFECT_EGRESS_RECORD_KEYS,
    EFFECT_EGRESS_SCHEMA_VERSION,
    EFFECT_EGRESS_SCHEMA_VERSION_PATTERN,
    EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE,
    MAX_EFFECT_EGRESS_JSON_INTEGER,
    MAX_EFFECT_EGRESS_SEQUENCE,
    EffectEgressFrameTooLargeError,
    EffectEgressReadResult,
    EffectEgressSinkFailedError,
    FdEffectSink,
    UnsupportedEffectEgressVersionError,
    read_effect_egress,
)
from nooa.security.install import EffectObservation, EffectObserver, install_effect_recorder
from nooa.security.sinks import (
    EffectRecordSinkBackend,
    EffectSink,
    JsonlEffectSink,
    install_effect_sink,
)

__all__ = [
    "DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES",
    "EFFECT_EGRESS_FRAME_KEYS",
    "EFFECT_EGRESS_RECORD_EVENT_TYPE",
    "EFFECT_EGRESS_RECORD_KEYS",
    "EFFECT_EGRESS_SCHEMA_VERSION",
    "EFFECT_EGRESS_SCHEMA_VERSION_PATTERN",
    "EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE",
    "MAX_EFFECT_EGRESS_JSON_INTEGER",
    "MAX_EFFECT_EGRESS_SEQUENCE",
    "EffectEgressFrameTooLargeError",
    "EffectEgressReadResult",
    "EffectEgressSinkFailedError",
    "EffectObservation",
    "EffectObserver",
    "EffectRecord",
    "EffectRecordSinkBackend",
    "EffectSink",
    "FdEffectSink",
    "JsonlEffectSink",
    "UnsupportedEffectEgressVersionError",
    "install_effect_recorder",
    "install_effect_sink",
    "read_effect_egress",
]
