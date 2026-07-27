# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the out-of-process detector harness example."""

from __future__ import annotations

from io import BytesIO

import pytest
from pydantic import ValidationError

from examples.security_hardening.approval_authority import (
    AuthorityReceiptDocument,
    AuthoritySummary,
)
from examples.security_hardening.detector_harness import (
    DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    DetectedScenario,
    DetectorReceiptInputTooLargeError,
    DetectorReport,
    read_receipt_document,
    run_detected_scenario,
    score_detector_input,
)
from examples.security_hardening.identity_approval import EFFECT_TYPE
from nooa.security import DetectorInput, EffectRecord


def _scoreable_input(**updates: object) -> DetectorInput:
    fields = {
        "input_id": "detector-input-vulnerable_attack",
        "run_id": "identity-approval-demo/vulnerable_attack",
        "effects": (
            EffectRecord(
                effect_type=EFFECT_TYPE,
                target="contractor@prod-db",
                decision="allowed",
                attributes={"request_id": "req-attack"},
            ),
        ),
        "effect_egress_completeness_gate_passed": True,
        "receipt_source": "approval-authority",
        "receipt_coverage": "asserted_complete",
    }
    fields.update(updates)
    return DetectorInput.model_validate(fields)


def test_detector_report_is_strict_and_self_consistent() -> None:
    report = DetectorReport(
        detector_input_id="detector-input-1",
        run_id="run-1",
        scored=True,
    )

    assert report.schema_version == "nooa-detector-harness-example-v2"
    assert report.findings == ()
    assert report.refusal_reason is None

    with pytest.raises(ValidationError):
        DetectorReport(detector_input_id="detector-input-1", scored=True, typo="not-allowed")
    with pytest.raises(ValidationError, match="cannot carry refusal_reason"):
        DetectorReport(
            detector_input_id="detector-input-1",
            scored=True,
            refusal_reason="not allowed",
        )
    with pytest.raises(ValidationError, match="cannot be true"):
        DetectorReport(
            detector_input_id="detector-input-1",
            effect_egress_completeness_signals=("truncated",),
            effect_egress_completeness_gate_passed=True,
            scored=True,
        )
    with pytest.raises(ValidationError, match="canonical unique order"):
        DetectorReport(
            detector_input_id="detector-input-1",
            effect_egress_completeness_signals=("truncated", "first_sequence_error"),
            scored=True,
        )
    with pytest.raises(ValidationError, match="issued_token_count must match receipt_count"):
        DetectorReport(
            detector_input_id="detector-input-1",
            receipt_count=1,
            issued_token_count=0,
            scored=True,
        )
    with pytest.raises(ValidationError, match="requires refusal_reason"):
        DetectorReport(detector_input_id="detector-input-1", scored=False)


def test_score_detector_input_emits_identity_finding() -> None:
    detector_input = _scoreable_input()

    report = score_detector_input(detector_input)

    assert report.detector_input_id == detector_input.input_id
    assert report.run_id == detector_input.run_id
    assert report.scored is True
    assert report.effect_egress_completeness_gate_passed is True
    assert report.receipt_source == "approval-authority"
    assert report.receipt_coverage == "asserted_complete"
    assert report.receipt_count == 0
    assert report.issued_token_count == 0
    assert report.findings[0].evidence_refs == (
        detector_input.input_id,
        detector_input.effects[0].id,
    )
    assert report.refusal_reason is None


@pytest.mark.parametrize(
    ("detector_input", "expected_reason"),
    [
        (
            _scoreable_input(effect_egress_completeness_gate_passed=False),
            "effect_egress_completeness_gate_passed=True",
        ),
        (
            _scoreable_input(receipt_coverage="unknown"),
            "receipt_coverage='asserted_complete'",
        ),
    ],
    ids=["unchecked-egress", "unknown-receipt-coverage"],
)
def test_score_detector_input_reports_policy_refusal(
    detector_input: DetectorInput,
    expected_reason: str,
) -> None:
    report = score_detector_input(detector_input)

    assert report.scored is False
    assert report.findings == ()
    assert report.refusal_reason is not None
    assert expected_reason in report.refusal_reason


def test_read_receipt_document_round_trips_json_and_rejects_over_bound_payload() -> None:
    document = AuthorityReceiptDocument(issued_token_count=0)
    payload = document.model_dump_json().encode("utf-8")

    assert read_receipt_document(BytesIO(payload)) == document

    with pytest.raises(DetectorReceiptInputTooLargeError) as exc_info:
        read_receipt_document(BytesIO(payload), max_receipt_bytes=len(payload) - 1)

    assert exc_info.value.max_receipt_bytes == len(payload) - 1


@pytest.mark.parametrize("max_receipt_bytes", [0, -1, True, 1.5, "1024"])
def test_read_receipt_document_rejects_invalid_budget(max_receipt_bytes: object) -> None:
    expected_exception = (
        TypeError
        if not isinstance(max_receipt_bytes, int) or isinstance(max_receipt_bytes, bool)
        else ValueError
    )
    with pytest.raises(expected_exception):
        read_receipt_document(
            BytesIO(b"{}"),
            max_receipt_bytes=max_receipt_bytes,  # type: ignore[arg-type]
        )


def test_detected_vulnerable_scenario_scores_authority_empty_receipts_and_emits_finding() -> None:
    result = run_detected_scenario("vulnerable_attack")

    assert result.victim is not None
    assert result.authority is not None
    assert result.victim_returncode == 0
    assert result.authority_returncode == 0
    assert result.detector_returncode == 0
    assert result.victim.self_reported_collector_read_endpoint_open is False
    assert result.victim.self_reported_receipt_read_endpoint_open is False
    assert result.victim.self_reported_receipt_write_endpoint_open is False
    assert result.victim.self_reported_approval_request_read_endpoint_open is False
    assert result.victim.self_reported_approval_response_write_endpoint_open is False
    assert result.authority.request_count == 1
    assert result.authority.issued_token_count == 0
    assert result.authority.receipt_count == 0
    assert result.authority.receipt_ids == ()
    assert result.detector.detector_input_id == "detector-input-vulnerable_attack"
    assert result.detector.scored is True
    assert result.detector.effect_egress_completeness_signals == ()
    assert result.detector.effect_egress_completeness_gate_passed is True
    assert result.detector.receipt_source == "approval-authority"
    assert result.detector.receipt_coverage == "asserted_complete"
    assert result.detector.receipt_count == 0
    assert result.detector.issued_token_count == 0
    assert len(result.detector.findings) == 1


def test_detected_authorized_scenario_uses_authority_receipt_and_emits_no_finding() -> None:
    result = run_detected_scenario("hardened_authorized")

    assert result.victim is not None
    assert result.authority is not None
    assert result.victim.decision == "allowed"
    assert result.authority.request_count == 1
    assert result.authority.issued_token_count == 1
    assert result.authority.receipt_count == 1
    assert result.authority.receipt_ids == ("authority-receipt-req-approved",)
    assert result.detector.scored is True
    assert result.detector.receipt_source == "approval-authority"
    assert result.detector.receipt_count == 1
    assert result.detector.issued_token_count == 1
    assert result.detector.findings == ()


def test_detected_partial_tail_crash_preserves_refusal_outside_victim() -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        victim_fault="partial_tail_crash",
    )

    assert result.victim is None
    assert result.authority is not None
    assert result.victim_returncode == 3
    assert result.authority_returncode == 0
    assert result.detector_returncode == 0
    assert result.detector.scored is False
    assert result.detector.effect_egress_completeness_signals == ("truncated",)
    assert result.detector.effect_egress_completeness_gate_passed is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "effect_egress_completeness_gate_passed=True" in result.detector.refusal_reason


def test_detected_scenario_fails_closed_on_oversized_receipt_document() -> None:
    with pytest.raises(RuntimeError, match="detector subprocess failed"):
        run_detected_scenario("hardened_authorized", max_receipt_bytes=1)


def test_detected_scenario_fails_closed_when_authority_exits_before_receipt_document() -> None:
    with pytest.raises(RuntimeError, match="authority subprocess failed"):
        run_detected_scenario("hardened_authorized", authority_fault="exit_before_receipt")


def test_detected_scenario_rejects_nonzero_detector_returncode() -> None:
    with pytest.raises(ValidationError, match="successful detector subprocess"):
        DetectedScenario(
            detector=DetectorReport(detector_input_id="detector-input-1", scored=True),
            victim_returncode=3,
            authority=AuthoritySummary(
                request_count=0,
                issued_token_count=0,
                receipt_count=0,
            ),
            authority_returncode=0,
            detector_returncode=1,
        )


def test_detected_scenario_rejects_nonzero_authority_returncode() -> None:
    with pytest.raises(ValidationError, match="successful authority subprocess"):
        DetectedScenario(
            detector=DetectorReport(detector_input_id="detector-input-1", scored=True),
            victim_returncode=3,
            authority_returncode=1,
            detector_returncode=0,
        )


def test_default_receipt_budget_is_large_enough_for_authority_document() -> None:
    payload = AuthorityReceiptDocument(issued_token_count=0).model_dump_json()

    assert len(payload.encode("utf-8")) < DEFAULT_DETECTOR_RECEIPT_MAX_BYTES
