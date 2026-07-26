# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Middleware installer for structured security-effect telemetry."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING

from nooa.runtime.middleware import MIDDLEWARE_EXECUTE_PYTHON
from nooa.security.effects import EffectRecord

if TYPE_CHECKING:
    from nooa.runtime.event_manager import EventManager
    from nooa.runtime.middleware import ExecutePythonContext, ExecutePythonNext


EffectObservation = EffectRecord | Sequence[EffectRecord] | None
EffectObserver = Callable[
    ["ExecutePythonContext"], "EffectObservation | Awaitable[EffectObservation]"
]


def _enrich_record(record: EffectRecord, ctx: ExecutePythonContext) -> EffectRecord:
    """Fill runtime lineage fields that the observer did not set explicitly."""
    updates: dict[str, str] = {}
    runtime = ctx.runtime
    if not record.generation_id and runtime is not None:
        updates["generation_id"] = runtime.get_generation_id() or ""
    if not record.tool_call_id:
        tool_call_id = ctx.params.get("tool_call_id")
        if isinstance(tool_call_id, str):
            updates["tool_call_id"] = tool_call_id
    if not record.observer:
        updates["observer"] = "execute_python_middleware"
    return record.model_copy(update=updates) if updates else record


def _normalize_records(observed: EffectObservation) -> tuple[EffectRecord, ...]:
    """Normalize one observer result into a tuple of validated records."""
    if observed is None:
        return ()
    if isinstance(observed, EffectRecord):
        return (observed,)
    records = tuple(observed)
    if not all(isinstance(record, EffectRecord) for record in records):
        raise TypeError(
            "effect observer must return EffectRecord, a sequence of EffectRecord, or None"
        )
    return records


def install_effect_recorder(
    event_manager: EventManager,
    observer: EffectObserver,
) -> Callable[[], None]:
    """Install host-side effect observation on ``execute_python`` calls.

    The observer runs from the wrapped code cell's ``finally`` path and may
    return zero, one, or many :class:`EffectRecord` instances. Each record is
    added to ``event_manager`` as hidden metadata and receives the current
    agent ``call_id`` through the normal ``EventManager.add()`` path. The hook
    runs for every ``execute_python`` invocation, including framework prefill
    cells, so observers should filter on ``ctx.params`` or ``ctx.code`` when
    they only want application effects.

    This installer does not make the event manager tamper-resistant. It avoids
    adding a model-visible recording builtin, but authoritative security
    decisions still require a separately trusted sink or backend receipt.

    Observer exceptions propagate because this is middleware, not an ``on()``
    subscriber. Applications can therefore fail closed on evidence collection
    after an effect attempt instead of silently losing evidence; this does not
    retroactively prevent an effect that already occurred. On wrapped-execution
    failures, ``ctx.result`` may still be ``None``; if the observer also raises
    while another exception is unwinding, the observer exception is propagated.
    """

    async def _observe(ctx: ExecutePythonContext) -> None:
        observed = observer(ctx)
        if inspect.isawaitable(observed):
            observed = await observed
        for record in _normalize_records(observed):
            event_manager.add(_enrich_record(record, ctx))

    async def _record_effect(
        ctx: ExecutePythonContext,
        nxt: ExecutePythonNext,
    ) -> ExecutePythonContext:
        observed_ctx = ctx
        try:
            observed_ctx = await nxt(ctx)
            return observed_ctx
        finally:
            await _observe(observed_ctx)

    return event_manager.intercept(MIDDLEWARE_EXECUTE_PYTHON, _record_effect)
