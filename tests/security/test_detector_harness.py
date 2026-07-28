# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the out-of-process detector harness example."""

from __future__ import annotations

import os
from tempfile import TemporaryFile

import pytest
from pydantic import ValidationError

from examples.security_hardening.approval_authority import (
    AuthoritySummary,
)
from examples.security_hardening.data_export import EXPORT_EFFECT_TYPE
from examples.security_hardening.detector_harness import (
    DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    DetectedScenario,
    DetectorReport,
    receipt_scope_gated_scorer,
    run_detected_scenario,
    score_detector_input,
    score_fd,
)
from examples.security_hardening.effect_collector import run_collected_scenario
from examples.security_hardening.identity_approval import (
    EFFECT_TYPE,
    detect_grants_without_approval,
)
from nooa.security import (
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
    DetectorInput,
    EffectRecord,
    FdEffectSink,
    ReceiptBundle,
    SecurityReceipt,
    write_receipt_bundle,
)


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


def _report_fields(**updates: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "victim_profile": "identity_approval",
        "scorer_name": "identity-approval-scorer",
        "detector_input_id": "detector-input-1",
    }
    fields.update(updates)
    return fields


def test_detector_report_is_strict_and_self_consistent() -> None:
    report = DetectorReport(
        **_report_fields(),
        run_id="run-1",
        scored=True,
    )

    assert report.schema_version == "nooa-detector-harness-example-v3"
    assert report.victim_profile == "identity_approval"
    assert report.scorer_name == "identity-approval-scorer"
    assert report.findings == ()
    assert report.refusal_reason is None

    with pytest.raises(ValidationError):
        DetectorReport(**_report_fields(typo="not-allowed"), scored=True)
    with pytest.raises(ValidationError, match="cannot carry refusal_reason"):
        DetectorReport(
            **_report_fields(),
            scored=True,
            refusal_reason="not allowed",
        )
    with pytest.raises(ValidationError, match="cannot be true"):
        DetectorReport(
            **_report_fields(),
            effect_egress_completeness_signals=("truncated",),
            effect_egress_completeness_gate_passed=True,
            scored=True,
        )
    with pytest.raises(ValidationError, match="canonical unique order"):
        DetectorReport(
            **_report_fields(),
            effect_egress_completeness_signals=("truncated", "first_sequence_error"),
            scored=True,
        )
    with pytest.raises(ValidationError, match="receipt_bundle_completeness_signals"):
        DetectorReport(
            **_report_fields(),
            receipt_bundle_completeness_signals=("receipt_count_mismatch", "truncated"),
            scored=True,
        )
    with pytest.raises(ValidationError, match="receipt_bundle_completeness_gate_passed"):
        DetectorReport(
            **_report_fields(),
            receipt_bundle_completeness_signals=("truncated",),
            receipt_bundle_completeness_gate_passed=True,
            scored=True,
        )
    with pytest.raises(ValidationError, match="requires refusal_reason"):
        DetectorReport(**_report_fields(), scored=False)
    with pytest.raises(ValidationError, match="scorer_name must match victim_profile"):
        DetectorReport(
            **_report_fields(scorer_name="data-export-scorer"),
            scored=True,
        )


def test_score_detector_input_emits_identity_finding() -> None:
    detector_input = _scoreable_input()

    report = score_detector_input(detector_input)

    assert report.detector_input_id == detector_input.input_id
    assert report.run_id == detector_input.run_id
    assert report.victim_profile == "identity_approval"
    assert report.scorer_name == "identity-approval-scorer"
    assert report.scored is True
    assert report.effect_egress_completeness_gate_passed is True
    assert report.receipt_bundle_completeness_signals == ()
    assert report.receipt_bundle_completeness_gate_passed is False
    assert report.receipt_source == "approval-authority"
    assert report.receipt_coverage == "asserted_complete"
    assert report.receipt_count == 0
    assert report.declared_receipt_count is None
    assert report.findings[0].evidence_refs == (
        detector_input.input_id,
        detector_input.effects[0].id,
    )
    assert report.refusal_reason is None


def test_receipt_scope_gated_scorer_turns_off_run_drop_into_refusal() -> None:
    stale_receipt = SecurityReceipt(
        receipt_id="authority-receipt-req-attack",
        receipt_type="identity.approval",
        source="approval-authority",
        run_id="identity-approval-demo/stale",
        target="contractor@prod-db",
        effect_type=EFFECT_TYPE,
        attributes={"request_id": "req-attack"},
    )
    detector_input = _scoreable_input(receipts=(stale_receipt,))

    direct_report = score_detector_input(detector_input)
    gated_report = score_detector_input(
        detector_input,
        scorer=receipt_scope_gated_scorer(
            detect_grants_without_approval,
            expected_run_id=detector_input.run_id,
        ),
    )

    assert direct_report.scored is True
    assert len(direct_report.findings) == 1
    assert gated_report.scored is False
    assert gated_report.findings == ()
    assert gated_report.refusal_reason is not None
    assert "detector receipt scope gate refused input" in gated_report.refusal_reason
    assert "mismatched_run_id_receipt_ids=('authority-receipt-req-attack',)" in (
        gated_report.refusal_reason
    )


def test_score_fd_keeps_receipt_free_profile_on_direct_scorer_path() -> None:
    stale_receipt = SecurityReceipt(
        receipt_id="authority-receipt-export-attack",
        receipt_type="identity.approval",
        source="approval-authority",
        run_id="identity-approval-demo/stale",
        target="external://untrusted-bucket",
        effect_type=EXPORT_EFFECT_TYPE,
        attributes={"request_id": "export-attack"},
    )
    receipt_bundle = ReceiptBundle(
        receipt_source="approval-authority",
        receipt_coverage="asserted_complete",
        declared_receipt_count=1,
        receipts=(stale_receipt,),
    )
    with TemporaryFile() as effect_fh, TemporaryFile() as receipt_fh:
        sink = FdEffectSink(
            effect_fh.fileno(),
            schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2,
        )
        sink(
            EffectRecord(
                effect_type=EXPORT_EFFECT_TYPE,
                target="external://untrusted-bucket",
                decision="allowed",
                attributes={"request_id": "export-attack"},
            )
        )
        sink.close()
        effect_fh.seek(0)
        write_receipt_bundle(receipt_fh, receipt_bundle)
        receipt_fh.seek(0)

        report = score_fd(
            os.dup(effect_fh.fileno()),
            os.dup(receipt_fh.fileno()),
            profile_name="data_export",
            run_id="data-export-demo/export_vulnerable_attack",
            input_id="detector-input-export_vulnerable_attack",
        )

    assert report.scored is True
    assert report.refusal_reason is None
    assert len(report.findings) == 1


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


def test_detected_vulnerable_scenario_scores_authority_empty_receipts_and_emits_finding() -> None:
    result = run_detected_scenario("vulnerable_attack")

    assert result.victim_profile == "identity_approval"
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
    assert result.detector.victim_profile == "identity_approval"
    assert result.detector.scorer_name == "identity-approval-scorer"
    assert result.detector.scored is True
    assert result.detector.effect_egress_completeness_signals == ()
    assert result.detector.effect_egress_completeness_gate_passed is True
    assert result.detector.receipt_bundle_completeness_signals == ()
    assert result.detector.receipt_bundle_completeness_gate_passed is True
    assert result.detector.receipt_source == "approval-authority"
    assert result.detector.receipt_coverage == "asserted_complete"
    assert result.detector.receipt_count == 0
    assert result.detector.declared_receipt_count == 0
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
    assert result.detector.declared_receipt_count == 1
    assert result.detector.receipt_bundle_completeness_signals == ()
    assert result.detector.receipt_bundle_completeness_gate_passed is True
    assert result.detector.findings == ()


def test_detected_authorized_stale_receipt_scope_refuses_before_policy() -> None:
    result = run_detected_scenario(
        "hardened_authorized",
        authority_fault="stale_receipt_run_id",
    )

    assert result.victim is not None
    assert result.authority is not None
    assert result.victim.decision == "allowed"
    assert result.authority.issued_token_count == 1
    assert result.authority.receipt_count == 1
    assert result.detector.receipt_count == 1
    assert result.detector.declared_receipt_count == 1
    assert result.detector.scored is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "detector receipt scope gate refused input" in result.detector.refusal_reason
    assert "mismatched_run_id_receipt_ids=('authority-receipt-req-approved',)" in (
        result.detector.refusal_reason
    )


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
    assert result.detector.effect_egress_completeness_signals == (
        "truncated",
        "missing_stream_end",
    )
    assert result.detector.effect_egress_completeness_gate_passed is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "effect_egress_completeness_gate_passed=True" in result.detector.refusal_reason


def test_detected_truncated_receipt_bundle_refuses_before_scope_or_policy() -> None:
    result = run_detected_scenario(
        "hardened_authorized",
        authority_fault="truncate_receipt_document",
    )

    assert result.victim is not None
    assert result.authority is not None
    assert result.victim.decision == "allowed"
    assert result.authority.issued_token_count == 1
    assert result.detector.effect_egress_completeness_signals == ()
    assert result.detector.effect_egress_completeness_gate_passed is True
    assert result.detector.receipt_bundle_completeness_signals == ("truncated",)
    assert result.detector.receipt_bundle_completeness_gate_passed is False
    assert result.detector.receipt_count == 0
    assert result.detector.declared_receipt_count is None
    assert result.detector.scored is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "detector receipt bundle completeness gate refused input" in (
        result.detector.refusal_reason
    )
    assert "truncated=True" in result.detector.refusal_reason
    assert "detector receipt scope gate refused input" not in result.detector.refusal_reason


def test_detected_receipt_count_mismatch_refuses_before_scope_or_policy() -> None:
    result = run_detected_scenario(
        "hardened_authorized",
        authority_fault="drop_receipt_count_mismatch",
    )

    assert result.victim is not None
    assert result.authority is not None
    assert result.victim.decision == "allowed"
    assert result.authority.issued_token_count == 1
    assert result.authority.receipt_count == 1
    assert result.detector.effect_egress_completeness_signals == ()
    assert result.detector.effect_egress_completeness_gate_passed is True
    assert result.detector.receipt_bundle_completeness_signals == (
        "receipt_count_mismatch",
    )
    assert result.detector.receipt_bundle_completeness_gate_passed is False
    assert result.detector.receipt_count == 0
    assert result.detector.declared_receipt_count == 1
    assert result.detector.scored is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "detector receipt bundle completeness gate refused input" in (
        result.detector.refusal_reason
    )
    assert "declared_receipt_count=1" in result.detector.refusal_reason
    assert "receipt_count=0" in result.detector.refusal_reason
    assert "detector receipt scope gate refused input" not in result.detector.refusal_reason


def test_detected_scenario_fails_closed_on_oversized_receipt_document() -> None:
    with pytest.raises(RuntimeError, match="detector subprocess failed"):
        run_detected_scenario("hardened_authorized", max_receipt_bytes=1)


def test_detected_exit_between_frames_refuses_missing_stream_end() -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        victim_fault="exit_between_frames",
    )

    assert result.victim is None
    assert result.victim_returncode == 5
    assert result.detector.scored is False
    assert result.detector.effect_egress_completeness_signals == ("missing_stream_end",)
    assert result.detector.effect_egress_completeness_gate_passed is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "effect_egress_completeness_gate_passed=True" in result.detector.refusal_reason


def test_detected_sequence_gap_refuses_orderly_v2_stream() -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        victim_fault="sequence_gap",
    )

    assert result.victim is not None
    assert result.victim_returncode == 0
    assert result.detector.scored is False
    assert result.detector.effect_egress_completeness_signals == ("first_sequence_error",)
    assert result.detector.effect_egress_completeness_gate_passed is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "identity approval scorer" in result.detector.refusal_reason


def test_detected_record_count_mismatch_refuses_empty_false_negative() -> None:
    collected = run_collected_scenario(
        "vulnerable_attack",
        victim_fault="drop_record_count_mismatch",
    )
    result = run_detected_scenario(
        "vulnerable_attack",
        victim_fault="drop_record_count_mismatch",
    )

    assert collected.collector.records == ()
    assert collected.collector.declared_record_count == 1
    assert result.victim is not None
    assert result.victim_returncode == 0
    assert result.detector.scored is False
    assert result.detector.effect_egress_completeness_signals == ("record_count_mismatch",)
    assert result.detector.effect_egress_completeness_gate_passed is False
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "identity approval scorer" in result.detector.refusal_reason

    same_effects_without_signal = _scoreable_input(effects=collected.collector.records)
    would_be_clean_report = score_detector_input(same_effects_without_signal)
    assert would_be_clean_report.scored is True
    assert would_be_clean_report.findings == ()


def test_detected_scenario_fails_closed_when_authority_exits_before_receipt_document() -> None:
    with pytest.raises(RuntimeError, match="authority subprocess failed"):
        run_detected_scenario("hardened_authorized", authority_fault="exit_before_receipt")


def test_detected_scenario_rejects_nonzero_detector_returncode() -> None:
    with pytest.raises(ValidationError, match="successful detector subprocess"):
        DetectedScenario(
            victim_profile="identity_approval",
            detector=DetectorReport(**_report_fields(), scored=True),
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
            victim_profile="identity_approval",
            detector=DetectorReport(**_report_fields(), scored=True),
            victim_returncode=3,
            authority_returncode=1,
            detector_returncode=0,
        )


def test_detected_scenario_rejects_authority_state_for_receipt_free_profile() -> None:
    with pytest.raises(ValidationError, match="receipt-free profile cannot carry authority"):
        DetectedScenario(
            victim_profile="data_export",
            detector=DetectorReport(
                victim_profile="data_export",
                scorer_name="data-export-scorer",
                detector_input_id="detector-input-export",
                scored=True,
            ),
            victim_returncode=3,
            authority=AuthoritySummary(
                request_count=0,
                issued_token_count=0,
                receipt_count=0,
            ),
            authority_returncode=0,
            detector_returncode=0,
        )


def test_default_receipt_budget_is_large_enough_for_authority_document() -> None:
    payload = (
        ReceiptBundle(
            receipt_source="approval-authority",
            receipt_coverage="asserted_complete",
        ).model_dump_json()
        + "\n"
    )

    assert len(payload.encode("utf-8")) < DEFAULT_DETECTOR_RECEIPT_MAX_BYTES
