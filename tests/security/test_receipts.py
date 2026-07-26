# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for out-of-band security receipt transport."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nooa.events import ExecutionResult
from nooa.runtime.event_manager import EventManager
from nooa.runtime.middleware import ExecutePythonContext
from nooa.security import SecurityReceipt, install_effect_recorder


def _receipt(**updates: object) -> SecurityReceipt:
    fields = {
        "receipt_id": "audit-1",
        "receipt_type": "payment.accepted",
        "source": "payment_backend.audit",
        "target": "invoice-42",
        "effect_type": "payment.process",
        "issued_at": "2026-07-26T12:00:00Z",
        "attributes": {"amount": 12, "currency": "USD", "accepted": True},
    }
    fields.update(updates)
    return SecurityReceipt.model_validate(fields)


def test_security_receipt_is_strict_json_transport() -> None:
    receipt = _receipt()

    assert receipt.schema_version == "nooa-receipt-v1"
    assert receipt.receipt_id == "audit-1"
    assert receipt.receipt_type == "payment.accepted"
    assert receipt.source == "payment_backend.audit"
    assert receipt.target == "invoice-42"
    assert receipt.effect_type == "payment.process"
    assert receipt.issued_at == "2026-07-26T12:00:00Z"
    assert receipt.attributes == {"amount": 12, "currency": "USD", "accepted": True}

    with pytest.raises(ValidationError):
        _receipt(typo="not-allowed")
    with pytest.raises(ValidationError):
        _receipt(schema_version="nooa-receipt-v2")
    with pytest.raises(ValidationError):
        _receipt(attributes={"unsafe": object()})


def test_security_receipt_defaults_round_trip_and_freeze_field_bindings() -> None:
    receipt = SecurityReceipt(
        receipt_id="audit-2",
        receipt_type="review.rejected",
        source="review_backend.audit",
    )

    assert receipt.target == ""
    assert receipt.effect_type == ""
    assert receipt.issued_at == ""
    assert receipt.attributes == {}
    assert SecurityReceipt.model_validate_json(receipt.model_dump_json()) == receipt

    with pytest.raises(ValidationError):
        receipt.receipt_id = "audit-3"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_effect_recorder_does_not_accept_security_receipts() -> None:
    event_manager = EventManager()

    def observer(_ctx: ExecutePythonContext) -> SecurityReceipt:
        return _receipt()

    uninstall = install_effect_recorder(event_manager, observer)  # type: ignore[arg-type]
    try:
        ctx = ExecutePythonContext(code="process_payment()")

        async def core(inner: ExecutePythonContext) -> ExecutePythonContext:
            inner.result = ExecutionResult(stdout="done")
            return inner

        with pytest.raises(TypeError, match="effect observer must return EffectRecord"):
            await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        uninstall()
