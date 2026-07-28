# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for out-of-band security receipt transport."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nooa.events import ExecutionResult
from nooa.runtime.event_manager import EventManager
from nooa.runtime.middleware import ExecutePythonContext
from nooa.security import (
    RECEIPT_SCOPE_SIGNALS,
    ReceiptScopeError,
    ReceiptScopeValidation,
    SecurityReceipt,
    install_effect_recorder,
    receipt_scope_signals,
    require_valid_receipt_scope,
    validate_receipt_scope,
)


def _receipt(**updates: object) -> SecurityReceipt:
    fields = {
        "receipt_id": "audit-1",
        "receipt_type": "payment.accepted",
        "source": "payment_backend.audit",
        "run_id": "run-20260727-identity-1",
        "target": "invoice-42",
        "effect_type": "payment.process",
        "issued_at": "2026-07-26T12:00:00Z",
        "attributes": {"amount": 12, "currency": "USD", "accepted": True},
    }
    fields.update(updates)
    return SecurityReceipt.model_validate(fields)


def test_security_receipt_is_strict_json_transport() -> None:
    receipt = _receipt()

    assert set(receipt.model_dump(mode="json")) == {
        "schema_version",
        "receipt_id",
        "receipt_type",
        "source",
        "run_id",
        "target",
        "effect_type",
        "issued_at",
        "attributes",
    }
    assert receipt.schema_version == "nooa-receipt-v1"
    assert receipt.receipt_id == "audit-1"
    assert receipt.receipt_type == "payment.accepted"
    assert receipt.source == "payment_backend.audit"
    assert receipt.run_id == "run-20260727-identity-1"
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
    assert receipt.run_id == ""
    assert receipt.attributes == {}
    assert SecurityReceipt.model_validate_json(receipt.model_dump_json()) == receipt

    with pytest.raises(ValidationError):
        receipt.receipt_id = "audit-3"  # type: ignore[misc]


def test_validate_receipt_scope_materializes_once_and_preserves_order() -> None:
    source = iter(
        (
            _receipt(receipt_id="audit-1"),
            _receipt(receipt_id="audit-2"),
        )
    )

    validation = validate_receipt_scope(
        source,
        expected_run_id="run-20260727-identity-1",
    )

    assert tuple(source) == ()
    assert [receipt.receipt_id for receipt in validation.receipts] == ["audit-1", "audit-2"]
    assert validation.expected_run_id == "run-20260727-identity-1"
    assert validation.missing_run_id_receipt_ids == ()
    assert validation.mismatched_run_id_receipt_ids == ()
    assert receipt_scope_signals(validation) == ()
    assert require_valid_receipt_scope(validation) is validation.receipts


def test_validate_receipt_scope_reports_canonical_run_scope_diagnostics() -> None:
    validation = validate_receipt_scope(
        (
            _receipt(receipt_id="audit-current"),
            _receipt(receipt_id="audit-missing", run_id=""),
            _receipt(receipt_id="audit-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    assert validation.missing_run_id_receipt_ids == ("audit-missing",)
    assert validation.mismatched_run_id_receipt_ids == ("audit-stale",)
    assert receipt_scope_signals(validation) == ("missing_run_id", "run_id_mismatch")
    assert RECEIPT_SCOPE_SIGNALS == ("missing_run_id", "run_id_mismatch")


@pytest.mark.parametrize(
    ("receipts", "expected_signals", "expected_missing_ids", "expected_mismatched_ids"),
    [
        pytest.param(
            (
                _receipt(receipt_id="audit-missing-1", run_id=""),
                _receipt(receipt_id="audit-missing-2", run_id=""),
            ),
            ("missing_run_id",),
            ("audit-missing-1", "audit-missing-2"),
            (),
            id="missing-only",
        ),
        pytest.param(
            (
                _receipt(receipt_id="audit-stale-1", run_id="run-prior"),
                _receipt(receipt_id="audit-stale-2", run_id="run-other"),
            ),
            ("run_id_mismatch",),
            (),
            ("audit-stale-1", "audit-stale-2"),
            id="mismatch-only",
        ),
    ],
)
def test_validate_receipt_scope_preserves_each_single_signal_category(
    receipts: tuple[SecurityReceipt, ...],
    expected_signals: tuple[str, ...],
    expected_missing_ids: tuple[str, ...],
    expected_mismatched_ids: tuple[str, ...],
) -> None:
    validation = validate_receipt_scope(
        receipts,
        expected_run_id="run-20260727-identity-1",
    )

    assert receipt_scope_signals(validation) == expected_signals
    assert validation.missing_run_id_receipt_ids == expected_missing_ids
    assert validation.mismatched_run_id_receipt_ids == expected_mismatched_ids


def test_require_valid_receipt_scope_raises_structured_error() -> None:
    validation = validate_receipt_scope(
        (
            _receipt(receipt_id="audit-missing", run_id=""),
            _receipt(receipt_id="audit-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    with pytest.raises(ReceiptScopeError) as exc_info:
        require_valid_receipt_scope(validation)

    error = exc_info.value
    assert error.reasons == ("missing_run_id", "run_id_mismatch")
    assert error.expected_run_id == "run-20260727-identity-1"
    assert error.missing_run_id_receipt_ids == ("audit-missing",)
    assert error.mismatched_run_id_receipt_ids == ("audit-stale",)
    assert not isinstance(error, ValueError)


def test_empty_receipt_scope_passes_without_claiming_coverage() -> None:
    validation = validate_receipt_scope((), expected_run_id="run-20260727-identity-1")

    assert validation.receipts == ()
    assert receipt_scope_signals(validation) == ()
    assert require_valid_receipt_scope(validation) == ()


@pytest.mark.parametrize("expected_run_id", ["", None, 0])
def test_validate_receipt_scope_rejects_invalid_expected_run_id(expected_run_id: object) -> None:
    error_type = ValueError if expected_run_id == "" else TypeError
    with pytest.raises(error_type):
        validate_receipt_scope(
            (),
            expected_run_id=expected_run_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("receipts", ["not-a-bundle", b"not-a-bundle", [object()]])
def test_validate_receipt_scope_rejects_non_receipt_inputs(receipts: object) -> None:
    with pytest.raises(TypeError, match="SecurityReceipt"):
        validate_receipt_scope(
            receipts,  # type: ignore[arg-type]
            expected_run_id="run-20260727-identity-1",
        )


def test_receipt_scope_helpers_reject_non_validation_inputs_and_clean_error() -> None:
    with pytest.raises(TypeError, match="expected ReceiptScopeValidation"):
        receipt_scope_signals("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptScopeValidation"):
        require_valid_receipt_scope("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptScopeValidation"):
        ReceiptScopeError("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one scope signal"):
        ReceiptScopeError(ReceiptScopeValidation(receipts=(), expected_run_id="run-1"))


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
