# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for detector-facing security evidence transport."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nooa.security import (
    DetectorInput,
    EffectEgressIncompleteError,
    EffectEgressReadResult,
    EffectRecord,
    SecurityReceipt,
    detector_input_from_egress,
)


def _effect(**updates: object) -> EffectRecord:
    fields = {
        "effect_type": "payment.process",
        "target": "invoice-42",
        "decision": "allowed",
        "attributes": {"request_id": "req-42"},
    }
    fields.update(updates)
    return EffectRecord.model_validate(fields)


def _receipt(**updates: object) -> SecurityReceipt:
    fields = {
        "receipt_id": "receipt-42",
        "receipt_type": "payment.accepted",
        "source": "payment-backend-audit",
        "run_id": "run-42",
        "target": "invoice-42",
        "effect_type": "payment.process",
        "attributes": {"request_id": "req-42"},
    }
    fields.update(updates)
    return SecurityReceipt.model_validate(fields)


def test_detector_input_is_strict_json_transport() -> None:
    effect = _effect()
    receipt = _receipt()
    bundle = DetectorInput(
        input_id="input-42",
        run_id="run-42",
        effects=(effect,),
        receipts=(receipt,),
        receipt_source="payment-backend-audit",
        receipt_coverage="asserted_complete",
        attributes={"collector": "pipe-7"},
    )

    assert set(bundle.model_dump(mode="json")) == {
        "schema_version",
        "input_id",
        "run_id",
        "effects",
        "effect_egress_completeness_signals",
        "effect_egress_completeness_gate_passed",
        "receipts",
        "receipt_source",
        "receipt_coverage",
        "attributes",
    }
    assert bundle.schema_version == "nooa-detector-input-v1"
    assert bundle.input_id == "input-42"
    assert bundle.run_id == "run-42"
    assert bundle.effects == (effect,)
    assert bundle.receipts == (receipt,)
    assert bundle.effect_egress_completeness_signals == ()
    assert bundle.effect_egress_completeness_gate_passed is False
    assert bundle.receipt_source == "payment-backend-audit"
    assert bundle.receipt_coverage == "asserted_complete"
    assert bundle.attributes == {"collector": "pipe-7"}

    with pytest.raises(ValidationError):
        DetectorInput(input_id="input-42", typo="not-allowed")
    with pytest.raises(ValidationError):
        DetectorInput(input_id="input-42", schema_version="nooa-detector-input-v2")
    with pytest.raises(ValidationError):
        DetectorInput(input_id="input-42", attributes={"unsafe": object()})
    with pytest.raises(ValidationError):
        DetectorInput(input_id="input-42", receipt_coverage="verified")


def test_detector_input_defaults_round_trip_and_freeze_field_bindings() -> None:
    bundle = DetectorInput(input_id="input-empty")

    assert bundle.run_id == ""
    assert bundle.effects == ()
    assert bundle.effect_egress_completeness_signals == ()
    assert bundle.effect_egress_completeness_gate_passed is False
    assert bundle.receipts == ()
    assert bundle.receipt_source == ""
    assert bundle.receipt_coverage == "unknown"
    assert bundle.attributes == {}
    assert DetectorInput.model_validate_json(bundle.model_dump_json()) == bundle

    with pytest.raises(ValidationError):
        bundle.input_id = "input-mutated"  # type: ignore[misc]


@pytest.mark.parametrize(
    "signals",
    [
        ("truncated", "first_sequence_error"),
        ("truncated", "truncated"),
        ("first_sequence_error", "first_sequence_error"),
    ],
)
def test_detector_input_refuses_noncanonical_completeness_signals(
    signals: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError, match="canonical unique order"):
        DetectorInput(
            input_id="input-degraded",
            effect_egress_completeness_signals=signals,
        )


def test_detector_input_refuses_passed_gate_with_degraded_signals() -> None:
    with pytest.raises(ValidationError, match="cannot be true"):
        DetectorInput(
            input_id="input-degraded",
            effect_egress_completeness_signals=("truncated",),
            effect_egress_completeness_gate_passed=True,
        )


def test_detector_input_from_egress_preserves_clean_collector_facts() -> None:
    effect = _effect()
    receipt = _receipt()
    bundle = detector_input_from_egress(
        EffectEgressReadResult(records=(effect,)),
        input_id="input-42",
        run_id="run-42",
        receipts=(receipt,),
        receipt_source="payment-backend-audit",
        receipt_coverage="asserted_complete",
    )

    assert bundle.effects == (effect,)
    assert bundle.effect_egress_completeness_signals == ()
    assert bundle.effect_egress_completeness_gate_passed is True
    assert bundle.receipts == (receipt,)
    assert bundle.receipt_source == "payment-backend-audit"
    assert bundle.receipt_coverage == "asserted_complete"


def test_detector_input_from_egress_fails_closed_by_default() -> None:
    egress = EffectEgressReadResult(records=(_effect(),), truncated=True)

    with pytest.raises(EffectEgressIncompleteError) as exc_info:
        detector_input_from_egress(egress, input_id="input-degraded")

    assert exc_info.value.reasons == ("truncated",)


def test_detector_input_from_egress_can_preserve_degraded_diagnostics() -> None:
    effect = _effect()
    bundle = detector_input_from_egress(
        EffectEgressReadResult(
            records=(effect,),
            first_sequence_error=(0, 2),
            truncated=True,
        ),
        input_id="input-degraded",
        require_complete=False,
    )

    assert bundle.effects == (effect,)
    assert bundle.effect_egress_completeness_signals == (
        "first_sequence_error",
        "truncated",
    )
    assert bundle.effect_egress_completeness_gate_passed is False


def test_detector_input_preserves_other_run_receipts_without_join_semantics() -> None:
    stale_receipt = _receipt(run_id="run-prior")
    bundle = DetectorInput(
        input_id="input-current",
        run_id="run-current",
        effects=(_effect(),),
        receipts=(stale_receipt,),
        receipt_source="payment-backend-audit",
        receipt_coverage="asserted_complete",
    )

    assert bundle.run_id == "run-current"
    assert bundle.receipts[0].run_id == "run-prior"


def test_detector_input_from_egress_rejects_non_read_result() -> None:
    with pytest.raises(TypeError, match="expected EffectEgressReadResult"):
        detector_input_from_egress("not-a-read-result", input_id="input-42")  # type: ignore[arg-type]


@pytest.mark.parametrize("require_complete", [0, 1, "false", None])
def test_detector_input_from_egress_rejects_non_boolean_require_complete(
    require_complete: object,
) -> None:
    with pytest.raises(TypeError, match="expected bool require_complete"):
        detector_input_from_egress(
            EffectEgressReadResult(records=()),
            input_id="input-42",
            require_complete=require_complete,  # type: ignore[arg-type]
        )
