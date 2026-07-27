# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Built-in observers for guard-shaped ``execute_python`` outcomes."""

from __future__ import annotations

from typing import Literal

from nooa.errors import ValidationError
from nooa.runtime.middleware import ExecutePythonContext
from nooa.runtime.sandbox.errors import (
    CellMemoryError,
    CellTimeoutError,
    WorkerDiedError,
)
from nooa.security.effects import EffectRecord

_GUARD_EFFECT_TYPES: tuple[
    tuple[type[Exception], str, Literal["denied", "observed"]],
    ...,
] = (
    (ValidationError, "code.validation", "denied"),
    (CellTimeoutError, "code.timeout", "observed"),
    (CellMemoryError, "sandbox.memory", "observed"),
    (WorkerDiedError, "sandbox.worker", "observed"),
)


def framework_guard_observer(ctx: ExecutePythonContext) -> EffectRecord | None:
    """Return hidden telemetry for typed ``execute_python`` guard-shaped outcomes.

    Install this with :func:`nooa.security.install_effect_recorder`. The
    observer classifies mapped error types already present on
    ``ctx.result.error``: code validation failures, runtime cell timeouts, and
    sandbox resource/worker failures. Ordinary application exceptions outside
    those mapped types and sandbox serialization plumbing failures are
    intentionally ignored.

    This is evidence of a NOOA guard outcome, not a vulnerability detector and
    not an enforcement boundary. It also does not authenticate exception
    origin: generated code that can construct one of these public exception
    classes can mint an indistinguishable record. The record omits raw
    exception text because built-in observers must not copy arbitrary runtime
    data into ``EffectRecord.attributes`` without application-specific
    sanitization. A timeout record proves only that ``ctx.result.error`` carried
    ``CellTimeoutError``; it does not prove that a runtime deadline fired or
    that generated code stopped. Existing runtime semantics still allow code
    that catches cancellation to continue.
    """
    if ctx.result is None or ctx.result.error is None:
        return None

    error = ctx.result.error
    for error_type, effect_type, decision in _GUARD_EFFECT_TYPES:
        if isinstance(error, error_type):
            return EffectRecord(
                effect_type=effect_type,
                decision=decision,
                observer="framework_guard",
                attributes={"error_type": type(error).__name__},
            )
    return None
