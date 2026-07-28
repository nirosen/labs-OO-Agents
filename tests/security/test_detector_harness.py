# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the out-of-process detector harness example."""

from __future__ import annotations

import os
from io import BytesIO
from tempfile import TemporaryFile
from typing import BinaryIO, get_args

import pytest
from pydantic import ValidationError

import examples.security_hardening.detector_harness as detector_harness
from examples.security_hardening.approval_authority import (
    AuthoritySummary,
)
from examples.security_hardening.data_export import EXPORT_EFFECT_TYPE
from examples.security_hardening.detector_harness import (
    _FINDING_ADMISSION_REFUSALS,
    _IDENTITY_PROFILE,
    DEFAULT_AUTHORITY_SUMMARY_MAX_BYTES,
    DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    DEFAULT_DETECTOR_REPORT_MAX_BYTES,
    DEFAULT_VICTIM_SUMMARY_MAX_BYTES,
    DetectedScenario,
    DetectorReport,
    FindingAdmissionRefusal,
    SupervisorAdmissionError,
    _admit_authority_summary,
    _admit_detector_report,
    _admit_finding_bundle,
    _admit_victim_summary,
    _validate_detector_fault,
    _validate_max_authority_summary_bytes,
    _validate_max_detector_report_bytes,
    _validate_max_finding_bundle_bytes,
    _validate_max_victim_summary_bytes,
    _validate_subprocess_output_fault,
    evidence_ref_membership_gated_scorer,
    receipt_scope_gated_scorer,
    run_detected_scenario,
    score_detector_input,
    score_fd,
)
from examples.security_hardening.effect_collector import VictimSummary, run_collected_scenario
from examples.security_hardening.identity_approval import (
    EFFECT_TYPE,
    detect_grants_without_approval,
)
from nooa.security import (
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
    DetectorInput,
    EffectRecord,
    FdEffectSink,
    FindingBundle,
    ReceiptBundle,
    SecurityFinding,
    SecurityReceipt,
    read_finding_bundle,
    require_complete_finding_bundle,
    write_finding_bundle,
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
        "declared_finding_count": 0,
    }
    fields.update(updates)
    return fields


def _finding_bundle_bytes(bundle: FindingBundle, *, terminated: bool = True) -> bytes:
    suffix = "\n" if terminated else ""
    return (bundle.model_dump_json() + suffix).encode("utf-8")


def test_detector_report_is_strict_and_self_consistent() -> None:
    report = DetectorReport(
        **_report_fields(),
        run_id="run-1",
        scored=True,
    )

    assert report.schema_version == "nooa-detector-harness-example-v4"
    assert report.victim_profile == "identity_approval"
    assert report.scorer_name == "identity-approval-scorer"
    assert report.declared_finding_count == 0
    assert report.finding_admission_refusal is None
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
    with pytest.raises(ValidationError, match="finding_bundle_completeness_signals"):
        DetectorReport(
            **_report_fields(),
            finding_bundle_completeness_signals=("truncated", "truncated"),
            scored=True,
        )
    with pytest.raises(ValidationError, match="finding_bundle_completeness_gate_passed"):
        DetectorReport(
            **_report_fields(),
            finding_bundle_completeness_signals=("truncated",),
            finding_bundle_completeness_gate_passed=True,
            scored=True,
        )
    with pytest.raises(ValidationError, match="requires declared_finding_count"):
        DetectorReport(
            **_report_fields(declared_finding_count=None),
            scored=True,
        )
    with pytest.raises(ValidationError, match="cannot carry finding_admission_refusal"):
        DetectorReport(
            **_report_fields(),
            finding_bundle_completeness_gate_passed=True,
            finding_admission_refusal="scope_drift",
            scored=True,
        )
    with pytest.raises(
        ValidationError,
        match="requires finding_bundle_completeness_gate_passed=True",
    ):
        DetectorReport(
            **_report_fields(),
            finding_admission_refusal="scope_drift",
            scored=False,
            refusal_reason="scope drift",
        )
    with pytest.raises(ValidationError, match="requires refusal_reason"):
        DetectorReport(**_report_fields(), scored=False)
    with pytest.raises(ValidationError, match="scorer_name must match victim_profile"):
        DetectorReport(
            **_report_fields(scorer_name="data-export-scorer"),
            scored=True,
        )


def test_finding_admission_refusal_vocabulary_matches_literal() -> None:
    assert set(get_args(FindingAdmissionRefusal)) == set(_FINDING_ADMISSION_REFUSALS)
    assert len(_FINDING_ADMISSION_REFUSALS) == len(set(_FINDING_ADMISSION_REFUSALS))


def test_score_detector_input_emits_identity_finding() -> None:
    detector_input = _scoreable_input()

    report, finding_bundle = score_detector_input(detector_input)

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
    assert report.declared_finding_count == 1
    assert finding_bundle.producer == "identity-approval-scorer"
    assert finding_bundle.findings[0].evidence_refs == (
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

    direct_report, direct_bundle = score_detector_input(detector_input)
    gated_report, gated_bundle = score_detector_input(
        detector_input,
        scorer=receipt_scope_gated_scorer(
            detect_grants_without_approval,
            expected_run_id=detector_input.run_id,
        ),
    )

    assert direct_report.scored is True
    assert direct_report.declared_finding_count == 1
    assert len(direct_bundle.findings) == 1
    assert gated_report.scored is False
    assert gated_report.declared_finding_count == 0
    assert gated_bundle.findings == ()
    assert gated_report.refusal_reason is not None
    assert "detector receipt scope gate refused input" in gated_report.refusal_reason
    assert "mismatched_run_id_receipt_ids=('authority-receipt-req-attack',)" in (
        gated_report.refusal_reason
    )


def test_evidence_ref_membership_gated_scorer_accepts_current_input_ids() -> None:
    receipt = SecurityReceipt(
        receipt_id="authority-receipt-req-attack",
        receipt_type="identity.approval",
        source="approval-authority",
        run_id="identity-approval-demo/vulnerable_attack",
        target="contractor@prod-db",
        effect_type=EFFECT_TYPE,
        attributes={"request_id": "req-attack"},
    )
    detector_input = _scoreable_input(receipts=(receipt,))

    def scorer(input_: DetectorInput) -> tuple[SecurityFinding, ...]:
        return (
            SecurityFinding(
                finding_id="finding-allowed-refs",
                finding_type="authorization.missing_receipt",
                producer="identity-approval-scorer",
                run_id=input_.run_id,
                target="contractor@prod-db",
                evidence_refs=(
                    input_.input_id,
                    input_.effects[0].id,
                    input_.receipts[0].receipt_id,
                ),
            ),
        )

    report, finding_bundle = score_detector_input(
        detector_input,
        scorer=evidence_ref_membership_gated_scorer(scorer),
    )

    assert report.scored is True
    assert report.declared_finding_count == 1
    assert finding_bundle.findings[0].evidence_refs == (
        detector_input.input_id,
        detector_input.effects[0].id,
        receipt.receipt_id,
    )


def test_evidence_ref_membership_gated_scorer_refuses_invented_refs() -> None:
    detector_input = _scoreable_input()

    def scorer(input_: DetectorInput) -> tuple[SecurityFinding, ...]:
        return (
            SecurityFinding(
                finding_id="finding-invented-ref",
                finding_type="authorization.missing_receipt",
                producer="identity-approval-scorer",
                run_id=input_.run_id,
                target="contractor@prod-db",
                evidence_refs=(input_.input_id, "invented-evidence-id"),
            ),
        )

    report, finding_bundle = score_detector_input(
        detector_input,
        scorer=evidence_ref_membership_gated_scorer(scorer),
    )

    assert report.scored is False
    assert report.declared_finding_count == 0
    assert finding_bundle.findings == ()
    assert report.refusal_reason is not None
    assert "detector evidence ref membership gate refused scorer output" in report.refusal_reason
    assert "unknown_evidence_refs=('invented-evidence-id',)" in report.refusal_reason
    assert "unknown_evidence_ref_finding_ids=('finding-invented-ref',)" in report.refusal_reason
    assert "allowed_evidence_id_count=2" in report.refusal_reason
    assert detector_input.effects[0].id not in report.refusal_reason


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
    with (
        TemporaryFile() as effect_fh,
        TemporaryFile() as receipt_fh,
        TemporaryFile() as finding_fh,
    ):
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
            os.dup(finding_fh.fileno()),
            profile_name="data_export",
            run_id="data-export-demo/export_vulnerable_attack",
            input_id="detector-input-export_vulnerable_attack",
        )
        finding_fh.seek(0)
        finding_bundle = require_complete_finding_bundle(read_finding_bundle(finding_fh))

    assert report.scored is True
    assert report.refusal_reason is None
    assert report.declared_finding_count == 1
    assert len(finding_bundle.findings) == 1


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
    report, finding_bundle = score_detector_input(detector_input)

    assert report.scored is False
    assert report.declared_finding_count == 0
    assert finding_bundle.findings == ()
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
    assert result.detector.declared_finding_count == 1
    assert len(result.findings) == 1


def test_detected_scenario_closes_setup_resources_when_pipe_allocation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_pipe = os.pipe
    real_temporary_file = TemporaryFile
    finding_files: list[BinaryIO] = []
    opened_fds: list[int] = []
    pipe_calls = 0

    def tracked_temporary_file() -> BinaryIO:
        finding_file = real_temporary_file()
        finding_files.append(finding_file)
        return finding_file

    def failing_pipe() -> tuple[int, int]:
        nonlocal pipe_calls
        pipe_calls += 1
        if pipe_calls == 3:
            raise OSError("simulated pipe allocation failure")
        read_fd, write_fd = real_pipe()
        opened_fds.extend([read_fd, write_fd])
        return read_fd, write_fd

    monkeypatch.setattr(detector_harness, "TemporaryFile", tracked_temporary_file)
    monkeypatch.setattr(detector_harness.os, "pipe", failing_pipe)

    with pytest.raises(OSError, match="simulated pipe allocation failure"):
        detector_harness.run_detected_scenario("vulnerable_attack")

    assert len(finding_files) == 1
    assert finding_files[0].closed is True
    assert len(opened_fds) == 4
    for fd in opened_fds:
        with pytest.raises(OSError):
            os.fstat(fd)


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
    assert result.detector.declared_finding_count == 0
    assert result.findings == ()


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
    assert result.detector.declared_finding_count == 0
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "detector receipt scope gate refused input" in result.detector.refusal_reason
    assert "mismatched_run_id_receipt_ids=('authority-receipt-req-approved',)" in (
        result.detector.refusal_reason
    )


@pytest.mark.parametrize(
    ("detector_fault", "expected_reason"),
    [
        (
            "blank_finding_run_id",
            "missing_run_id_finding_ids=('finding-req-attack',)",
        ),
        (
            "stale_finding_run_id",
            "mismatched_run_id_finding_ids=('finding-req-attack',)",
        ),
    ],
)
def test_detected_invalid_finding_scope_refuses_at_supervisor_boundary(
    detector_fault: str,
    expected_reason: str,
) -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        detector_fault=detector_fault,  # type: ignore[arg-type]
    )

    assert result.victim is not None
    assert result.authority is not None
    assert result.detector.run_id == "identity-approval-demo/vulnerable_attack"
    assert result.detector.scored is False
    assert result.detector.declared_finding_count == 1
    assert result.detector.finding_admission_refusal == "scope_drift"
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "supervisor finding scope gate refused output" in result.detector.refusal_reason
    assert expected_reason in result.detector.refusal_reason


def test_detected_duplicate_finding_id_refuses_at_supervisor_boundary() -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        detector_fault="duplicate_finding_id",
    )

    assert result.victim is not None
    assert result.authority is not None
    assert result.detector.run_id == "identity-approval-demo/vulnerable_attack"
    assert result.detector.scored is False
    assert result.detector.finding_bundle_completeness_signals == ()
    assert result.detector.finding_bundle_completeness_gate_passed is True
    assert result.detector.declared_finding_count == 2
    assert result.detector.finding_admission_refusal == "duplicate_finding_id"
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "supervisor finding ID uniqueness gate refused output" in result.detector.refusal_reason
    assert "duplicate_finding_ids=('finding-req-attack',)" in result.detector.refusal_reason
    assert "supervisor finding scope gate refused output" not in result.detector.refusal_reason


@pytest.mark.parametrize(
    (
        "detector_fault",
        "expected_signals",
        "expected_gate",
        "expected_admission_refusal",
        "expected_reason",
    ),
    [
        (
            "truncate_finding_document",
            ("truncated",),
            False,
            None,
            "supervisor finding bundle completeness gate refused output",
        ),
        (
            "drop_finding_count_mismatch",
            (),
            True,
            "count_mismatch",
            "supervisor finding bundle count gate refused output",
        ),
    ],
)
def test_detected_finding_bundle_faults_refuse_before_scope(
    detector_fault: str,
    expected_signals: tuple[str, ...],
    expected_gate: bool,
    expected_admission_refusal: str | None,
    expected_reason: str,
) -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        detector_fault=detector_fault,  # type: ignore[arg-type]
    )

    assert result.detector.scored is False
    assert result.detector.finding_bundle_completeness_signals == expected_signals
    assert result.detector.finding_bundle_completeness_gate_passed is expected_gate
    assert result.detector.declared_finding_count == 1
    assert result.detector.finding_admission_refusal == expected_admission_refusal
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert expected_reason in result.detector.refusal_reason
    assert "supervisor finding scope gate refused output" not in result.detector.refusal_reason


@pytest.mark.parametrize(
    "detector_fault",
    [
        "blank_finding_run_id",
        "stale_finding_run_id",
        "duplicate_finding_id",
        "truncate_finding_document",
        "drop_finding_count_mismatch",
    ],
)
def test_detector_finding_faults_reject_zero_finding_scenarios(detector_fault: str) -> None:
    with pytest.raises(RuntimeError, match="requires at least one detector finding"):
        run_detected_scenario(
            "hardened_authorized",
            detector_fault=detector_fault,  # type: ignore[arg-type]
        )


def test_supervisor_refuses_detector_report_scope_before_finding_scope() -> None:
    report = DetectorReport(
        **_report_fields(),
        run_id="run-stale",
        scored=True,
    )

    admitted = _admit_detector_report(
        report.model_dump_json(),
        profile=_IDENTITY_PROFILE,
        input_id="detector-input-1",
        expected_run_id="run-current",
        max_report_bytes=DEFAULT_DETECTOR_REPORT_MAX_BYTES,
    )

    assert admitted.run_id == "run-stale"
    assert admitted.scored is False
    assert admitted.declared_finding_count == 0
    assert admitted.finding_admission_refusal is None
    assert admitted.refusal_reason is not None
    assert "supervisor detector report scope gate refused output" in admitted.refusal_reason
    assert "reported_run_id='run-stale'" in admitted.refusal_reason


def test_supervisor_refuses_malformed_detector_report_payload() -> None:
    admitted = _admit_detector_report(
        "{",
        profile=_IDENTITY_PROFILE,
        input_id="detector-input-1",
        expected_run_id="run-current",
        max_report_bytes=DEFAULT_DETECTOR_REPORT_MAX_BYTES,
    )

    assert admitted.run_id == "run-current"
    assert admitted.scored is False
    assert admitted.declared_finding_count is None
    assert admitted.finding_admission_refusal is None
    assert admitted.refusal_reason is not None
    assert "supervisor detector report parse admission refused output" in (
        admitted.refusal_reason
    )
    assert "invalid DetectorReport payload" in admitted.refusal_reason


def test_supervisor_clears_child_supplied_finding_admission_refusal() -> None:
    report = DetectorReport(
        **_report_fields(),
        run_id="run-current",
        finding_bundle_completeness_gate_passed=True,
        finding_admission_refusal="scope_drift",
        scored=False,
        refusal_reason="child-supplied refusal",
    )

    admitted = _admit_detector_report(
        report.model_dump_json(),
        profile=_IDENTITY_PROFILE,
        input_id="detector-input-1",
        expected_run_id="run-current",
        max_report_bytes=DEFAULT_DETECTOR_REPORT_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.finding_admission_refusal is None
    assert admitted.refusal_reason == "child-supplied refusal"


def test_supervisor_admits_complete_finding_bundle_after_report_count_check() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())
    payload = BytesIO()
    write_finding_bundle(payload, finding_bundle)
    payload.seek(0)

    admitted, findings = _admit_finding_bundle(
        payload,
        report=report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is True
    assert admitted.finding_bundle_completeness_signals == ()
    assert admitted.finding_bundle_completeness_gate_passed is True
    assert admitted.declared_finding_count == 1
    assert admitted.finding_admission_refusal is None
    assert findings == finding_bundle.findings


def test_supervisor_refuses_truncated_finding_document_before_scope() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())

    admitted, findings = _admit_finding_bundle(
        BytesIO(_finding_bundle_bytes(finding_bundle, terminated=False)),
        report=report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.finding_bundle_completeness_signals == ("truncated",)
    assert admitted.finding_bundle_completeness_gate_passed is False
    assert admitted.declared_finding_count == 1
    assert admitted.finding_admission_refusal is None
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding bundle completeness gate refused output" in admitted.refusal_reason
    assert "truncated=True" in admitted.refusal_reason
    assert "supervisor finding scope gate refused output" not in admitted.refusal_reason


def test_supervisor_refuses_finding_count_mismatch_before_scope() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())

    admitted, findings = _admit_finding_bundle(
        BytesIO(_finding_bundle_bytes(FindingBundle(producer=finding_bundle.producer))),
        report=report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.finding_bundle_completeness_signals == ()
    assert admitted.finding_bundle_completeness_gate_passed is True
    assert admitted.declared_finding_count == 1
    assert admitted.finding_admission_refusal == "count_mismatch"
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding bundle count gate refused output" in admitted.refusal_reason
    assert "declared_finding_count=1" in admitted.refusal_reason
    assert "finding_count=0" in admitted.refusal_reason
    assert "supervisor finding scope gate refused output" not in admitted.refusal_reason


def test_supervisor_refuses_duplicate_finding_ids_after_scope_and_coherence() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())
    duplicate_bundle = FindingBundle(
        producer=finding_bundle.producer,
        findings=(finding_bundle.findings[0], finding_bundle.findings[0]),
    )
    duplicate_report = DetectorReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "declared_finding_count": 2,
        }
    )

    admitted, findings = _admit_finding_bundle(
        BytesIO(_finding_bundle_bytes(duplicate_bundle)),
        report=duplicate_report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.finding_bundle_completeness_signals == ()
    assert admitted.finding_bundle_completeness_gate_passed is True
    assert admitted.declared_finding_count == 2
    assert admitted.finding_admission_refusal == "duplicate_finding_id"
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding ID uniqueness gate refused output" in admitted.refusal_reason
    assert "duplicate_finding_ids=('finding-req-attack',)" in admitted.refusal_reason
    assert "supervisor finding scope gate refused output" not in admitted.refusal_reason


def test_supervisor_refuses_scope_before_finding_id_uniqueness() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())
    stale_finding = SecurityFinding.model_validate(
        {
            **finding_bundle.findings[0].model_dump(mode="python"),
            "run_id": "identity-approval-demo/stale",
        }
    )
    duplicate_stale_bundle = FindingBundle(
        producer=finding_bundle.producer,
        findings=(stale_finding, stale_finding),
    )
    duplicate_report = DetectorReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "declared_finding_count": 2,
        }
    )

    admitted, findings = _admit_finding_bundle(
        BytesIO(_finding_bundle_bytes(duplicate_stale_bundle)),
        report=duplicate_report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.declared_finding_count == 2
    assert admitted.finding_admission_refusal == "scope_drift"
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding scope gate refused output" in admitted.refusal_reason
    assert "mismatched_run_id_finding_ids=('finding-req-attack', 'finding-req-attack')" in (
        admitted.refusal_reason
    )
    assert "supervisor finding ID uniqueness gate refused output" not in admitted.refusal_reason


def test_supervisor_refuses_refused_report_with_finding_rows_after_scope() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())
    refused_report = DetectorReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "scored": False,
            "refusal_reason": "policy refused",
        }
    )

    admitted, findings = _admit_finding_bundle(
        BytesIO(_finding_bundle_bytes(finding_bundle)),
        report=refused_report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.finding_bundle_completeness_gate_passed is True
    assert admitted.declared_finding_count == 1
    assert admitted.finding_admission_refusal == "refused_report_rows"
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding bundle coherence gate refused output" in admitted.refusal_reason


def test_supervisor_refuses_malformed_finding_bundle_payload() -> None:
    report, _finding_bundle = score_detector_input(_scoreable_input())

    admitted, findings = _admit_finding_bundle(
        BytesIO(b"{\n"),
        report=report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.finding_bundle_completeness_signals == ()
    assert admitted.finding_bundle_completeness_gate_passed is False
    assert admitted.declared_finding_count == 1
    assert admitted.finding_admission_refusal is None
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding bundle parse admission refused output" in admitted.refusal_reason
    assert "invalid FindingBundle payload" in admitted.refusal_reason


def test_supervisor_preserves_unsupported_finding_bundle_version_refusal() -> None:
    report, finding_bundle = score_detector_input(_scoreable_input())
    payload = _finding_bundle_bytes(finding_bundle).replace(
        b"nooa-finding-bundle-v1",
        b"nooa-finding-bundle-v2",
        1,
    )

    admitted, findings = _admit_finding_bundle(
        BytesIO(payload),
        report=report,
        expected_run_id=report.run_id,
        max_bundle_bytes=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )

    assert admitted.scored is False
    assert admitted.declared_finding_count == 1
    assert admitted.finding_admission_refusal is None
    assert findings == ()
    assert admitted.refusal_reason is not None
    assert "supervisor finding bundle parse admission refused output" in admitted.refusal_reason
    assert "unsupported finding bundle schema_version: 'nooa-finding-bundle-v2'" in (
        admitted.refusal_reason
    )
    assert "invalid FindingBundle payload" not in admitted.refusal_reason


def test_supervisor_admits_victim_summary_and_refuses_visible_scenario_drift() -> None:
    payload = (
        VictimSummary(
            scenario="vulnerable_attack",
            decision="allowed",
            decision_source="backend",
            backend_event_count=1,
        ).model_dump_json()
    )

    assert (
        _admit_victim_summary(
            payload,
            expected_scenario="vulnerable_attack",
            max_summary_bytes=DEFAULT_VICTIM_SUMMARY_MAX_BYTES,
        ).scenario
        == "vulnerable_attack"
    )

    with pytest.raises(SupervisorAdmissionError) as exc_info:
        _admit_victim_summary(
            payload,
            expected_scenario="hardened_authorized",
            max_summary_bytes=DEFAULT_VICTIM_SUMMARY_MAX_BYTES,
        )

    assert exc_info.value.role == "victim"
    assert exc_info.value.reason == "scenario_mismatch"
    assert exc_info.value.expected_scenario == "hardened_authorized"
    assert exc_info.value.reported_scenario == "vulnerable_attack"
    assert "supervisor victim summary scope gate refused output" in str(exc_info.value)


@pytest.mark.parametrize(
    ("admit", "payload", "kwargs", "role", "limit_name"),
    [
        (
            _admit_victim_summary,
            "{",
            {
                "expected_scenario": "vulnerable_attack",
                "max_summary_bytes": DEFAULT_VICTIM_SUMMARY_MAX_BYTES,
            },
            "victim",
            "max_victim_summary_bytes",
        ),
        (
            _admit_authority_summary,
            "{",
            {"max_summary_bytes": DEFAULT_AUTHORITY_SUMMARY_MAX_BYTES},
            "authority",
            "max_authority_summary_bytes",
        ),
    ],
)
def test_supervisor_summary_admission_refuses_malformed_payloads(
    admit: object,
    payload: str,
    kwargs: dict[str, object],
    role: str,
    limit_name: str,
) -> None:
    with pytest.raises(SupervisorAdmissionError) as exc_info:
        admit(payload, **kwargs)  # type: ignore[operator]

    assert exc_info.value.role == role
    assert exc_info.value.reason == "invalid_payload"
    assert exc_info.value.limit_name is None
    assert limit_name not in str(exc_info.value)


@pytest.mark.parametrize(
    ("admit", "payload", "kwargs", "role", "limit_name"),
    [
        (
            _admit_victim_summary,
            VictimSummary(
                scenario="vulnerable_attack",
                decision="allowed",
                decision_source="backend",
                backend_event_count=1,
            ).model_dump_json(),
            {"expected_scenario": "vulnerable_attack", "max_summary_bytes": 1},
            "victim",
            "max_victim_summary_bytes",
        ),
        (
            _admit_authority_summary,
            AuthoritySummary(
                request_count=1,
                issued_token_count=1,
                receipt_count=1,
                receipt_ids=("receipt-1",),
            ).model_dump_json(),
            {"max_summary_bytes": 1},
            "authority",
            "max_authority_summary_bytes",
        ),
    ],
)
def test_supervisor_summary_admission_refuses_over_bound_payloads(
    admit: object,
    payload: str,
    kwargs: dict[str, object],
    role: str,
    limit_name: str,
) -> None:
    with pytest.raises(SupervisorAdmissionError) as exc_info:
        admit(payload, **kwargs)  # type: ignore[operator]

    assert exc_info.value.role == role
    assert exc_info.value.reason == "payload_too_large"
    assert exc_info.value.limit_name == limit_name
    assert exc_info.value.limit_value == 1
    assert f"{limit_name}=1" in str(exc_info.value)


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
    assert result.findings == ()
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
    assert result.findings == ()
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
    assert result.findings == ()
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


def test_detected_scenario_refuses_detector_report_over_parse_admission_budget() -> None:
    result = run_detected_scenario("vulnerable_attack", max_detector_report_bytes=1)

    assert result.detector_returncode == 0
    assert result.detector.scored is False
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "supervisor detector report parse admission refused output" in (
        result.detector.refusal_reason
    )
    assert "max_detector_report_bytes=1" in result.detector.refusal_reason


def test_detected_scenario_refuses_malformed_detector_report_payload() -> None:
    result = run_detected_scenario(
        "vulnerable_attack",
        subprocess_output_fault="malformed_detector_report",
    )

    assert result.detector_returncode == 0
    assert result.detector.scored is False
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "invalid DetectorReport payload" in result.detector.refusal_reason


def test_detected_scenario_refuses_finding_bundle_over_parse_admission_budget() -> None:
    result = run_detected_scenario("vulnerable_attack", max_finding_bundle_bytes=1)

    assert result.detector_returncode == 0
    assert result.detector.scored is False
    assert result.detector.finding_bundle_completeness_signals == ()
    assert result.detector.finding_bundle_completeness_gate_passed is False
    assert result.detector.declared_finding_count == 1
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "supervisor finding bundle parse admission refused output" in (
        result.detector.refusal_reason
    )
    assert "max_bundle_bytes=1" in result.detector.refusal_reason


@pytest.mark.parametrize(
    ("subprocess_output_fault", "role", "reason"),
    [
        ("malformed_victim_summary", "victim", "invalid_payload"),
        ("stale_victim_scenario", "victim", "scenario_mismatch"),
        ("malformed_authority_summary", "authority", "invalid_payload"),
    ],
)
def test_detected_scenario_refuses_invalid_child_summaries(
    subprocess_output_fault: str,
    role: str,
    reason: str,
) -> None:
    with pytest.raises(SupervisorAdmissionError) as exc_info:
        run_detected_scenario(
            "vulnerable_attack",
            subprocess_output_fault=subprocess_output_fault,  # type: ignore[arg-type]
        )

    assert exc_info.value.role == role
    assert exc_info.value.reason == reason


def test_stale_victim_scenario_fault_requires_a_successful_victim_summary() -> None:
    with pytest.raises(
        ValueError,
        match="stale_victim_scenario requires a successful victim summary",
    ):
        run_detected_scenario(
            "vulnerable_attack",
            victim_fault="partial_tail_crash",
            subprocess_output_fault="stale_victim_scenario",
        )


def test_victim_scenario_admission_is_profile_independent() -> None:
    with pytest.raises(SupervisorAdmissionError) as exc_info:
        run_detected_scenario(
            "export_vulnerable_attack",
            subprocess_output_fault="stale_victim_scenario",
        )

    assert exc_info.value.role == "victim"
    assert exc_info.value.reason == "scenario_mismatch"
    assert exc_info.value.expected_scenario == "export_vulnerable_attack"
    assert exc_info.value.reported_scenario == "export_vulnerable_attack-stale"


@pytest.mark.parametrize(
    ("kwargs", "role", "limit_name"),
    [
        ({"max_victim_summary_bytes": 1}, "victim", "max_victim_summary_bytes"),
        ({"max_authority_summary_bytes": 1}, "authority", "max_authority_summary_bytes"),
    ],
)
def test_detected_scenario_refuses_over_bound_child_summaries(
    kwargs: dict[str, object],
    role: str,
    limit_name: str,
) -> None:
    with pytest.raises(SupervisorAdmissionError) as exc_info:
        run_detected_scenario("vulnerable_attack", **kwargs)  # type: ignore[arg-type]

    assert exc_info.value.role == role
    assert exc_info.value.reason == "payload_too_large"
    assert exc_info.value.limit_name == limit_name


@pytest.mark.parametrize(
    ("value", "error_type"),
    [
        (0, ValueError),
        (-1, ValueError),
        (True, TypeError),
        (1.5, TypeError),
        ("1024", TypeError),
    ],
)
def test_validate_max_detector_report_bytes_rejects_invalid_values(
    value: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        _validate_max_detector_report_bytes(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("validator", "value", "error_type"),
    [
        (_validate_max_finding_bundle_bytes, 0, ValueError),
        (_validate_max_finding_bundle_bytes, True, TypeError),
        (_validate_max_victim_summary_bytes, 0, ValueError),
        (_validate_max_victim_summary_bytes, True, TypeError),
        (_validate_max_authority_summary_bytes, -1, ValueError),
        (_validate_max_authority_summary_bytes, "1024", TypeError),
    ],
)
def test_validate_summary_parse_budgets_reject_invalid_values(
    validator: object,
    value: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        validator(value)  # type: ignore[operator]


def test_validate_detector_fault_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="unsupported detector fault"):
        _validate_detector_fault("not-a-fault")


def test_validate_subprocess_output_fault_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="unsupported subprocess output fault"):
        _validate_subprocess_output_fault("not-a-fault")


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
    assert result.findings == ()
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
    assert result.findings == ()
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
    assert result.findings == ()
    assert result.detector.refusal_reason is not None
    assert "identity approval scorer" in result.detector.refusal_reason

    same_effects_without_signal = _scoreable_input(effects=collected.collector.records)
    would_be_clean_report, would_be_clean_bundle = score_detector_input(
        same_effects_without_signal
    )
    assert would_be_clean_report.scored is True
    assert would_be_clean_bundle.findings == ()


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
                declared_finding_count=0,
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


def test_default_detector_report_parse_budget_is_large_enough_for_clean_report() -> None:
    report = run_detected_scenario("vulnerable_attack").detector

    assert len(report.model_dump_json().encode("utf-8")) < DEFAULT_DETECTOR_REPORT_MAX_BYTES


def test_default_finding_bundle_parse_budget_is_large_enough_for_clean_bundle() -> None:
    _report, finding_bundle = score_detector_input(_scoreable_input())

    assert (
        len(_finding_bundle_bytes(finding_bundle))
        < DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES
    )


def test_default_summary_parse_budgets_are_large_enough_for_clean_outputs() -> None:
    result = run_detected_scenario("vulnerable_attack")

    assert result.victim is not None
    assert result.authority is not None
    assert len(result.victim.model_dump_json().encode("utf-8")) < DEFAULT_VICTIM_SUMMARY_MAX_BYTES
    assert (
        len(result.authority.model_dump_json().encode("utf-8"))
        < DEFAULT_AUTHORITY_SUMMARY_MAX_BYTES
    )
