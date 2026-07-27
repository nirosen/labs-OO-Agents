# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the receipt-free data-export hardening example."""

from __future__ import annotations

import pytest

from examples.security_hardening.data_export import (
    EXPORT_EFFECT_TYPE,
    EXPORT_FINDING_TYPE,
    detect_exports_outside_allowlist,
)
from examples.security_hardening.detector_harness import run_detected_scenario, score_detector_input
from examples.security_hardening.detector_policy import UnscoreableDetectorInputError
from examples.security_hardening.identity_approval import (
    EFFECT_TYPE,
    detect_grants_without_approval,
)
from nooa.security import DetectorInput, EffectRecord


def _export_input(**updates: object) -> DetectorInput:
    fields = {
        "input_id": "detector-input-export_vulnerable_attack",
        "run_id": "data-export-demo/export_vulnerable_attack",
        "effects": (
            EffectRecord(
                effect_type=EXPORT_EFFECT_TYPE,
                target="external://untrusted-bucket",
                decision="allowed",
                attributes={"request_id": "export-attack"},
            ),
        ),
        "effect_egress_completeness_gate_passed": True,
        "receipt_coverage": "unknown",
    }
    fields.update(updates)
    return DetectorInput.model_validate(fields)


def _identity_input() -> DetectorInput:
    return DetectorInput(
        input_id="detector-input-vulnerable_attack",
        run_id="identity-approval-demo/vulnerable_attack",
        effects=(
            EffectRecord(
                effect_type=EFFECT_TYPE,
                target="contractor@prod-db",
                decision="allowed",
                attributes={"request_id": "req-attack"},
            ),
        ),
        effect_egress_completeness_gate_passed=True,
        receipt_coverage="asserted_complete",
    )


def test_export_scorer_scores_unknown_receipt_coverage_without_receipts() -> None:
    detector_input = _export_input()

    findings = detect_exports_outside_allowlist(detector_input)
    report = score_detector_input(
        detector_input,
        victim_profile="data_export",
        scorer_name="data-export-scorer",
        scorer=detect_exports_outside_allowlist,
    )

    assert detector_input.receipts == ()
    assert detector_input.receipt_coverage == "unknown"
    assert len(findings) == 1
    assert findings[0].finding_type == EXPORT_FINDING_TYPE
    assert findings[0].evidence_refs == (
        detector_input.input_id,
        detector_input.effects[0].id,
    )
    assert report.victim_profile == "data_export"
    assert report.scorer_name == "data-export-scorer"
    assert report.receipt_count == 0
    assert report.issued_token_count is None
    assert report.scored is True
    assert len(report.findings) == 1


def test_export_scorer_refuses_incomplete_egress_without_consulting_receipts() -> None:
    with pytest.raises(
        UnscoreableDetectorInputError,
        match="data export scorer requires effect_egress_completeness_gate_passed=True",
    ):
        detect_exports_outside_allowlist(
            _export_input(effect_egress_completeness_gate_passed=False)
        )


def test_identity_and_export_scorers_do_not_cross_flag_unrelated_effects() -> None:
    with pytest.raises(
        UnscoreableDetectorInputError,
        match="identity approval scorer requires receipt_coverage='asserted_complete'",
    ):
        detect_grants_without_approval(_export_input())

    assert detect_exports_outside_allowlist(_identity_input()) == ()


def test_detected_export_vulnerable_scenario_scores_without_authority_or_receipts() -> None:
    result = run_detected_scenario("export_vulnerable_attack")

    assert result.victim_profile == "data_export"
    assert result.victim is not None
    assert result.victim.decision == "allowed"
    assert result.authority is None
    assert result.authority_returncode is None
    assert result.detector.victim_profile == "data_export"
    assert result.detector.scorer_name == "data-export-scorer"
    assert result.detector.scored is True
    assert result.detector.receipt_source == ""
    assert result.detector.receipt_coverage == "unknown"
    assert result.detector.receipt_count == 0
    assert result.detector.issued_token_count is None
    assert len(result.detector.findings) == 1


def test_detected_export_hardened_scenario_denies_without_finding() -> None:
    result = run_detected_scenario("export_hardened_attack")

    assert result.victim is not None
    assert result.victim.decision == "denied"
    assert result.victim.backend_event_count == 1
    assert result.detector.scored is True
    assert result.detector.findings == ()


def test_detected_export_allowlisted_scenario_preserves_allowed_export() -> None:
    result = run_detected_scenario("export_hardened_allowed")

    assert result.victim is not None
    assert result.victim.decision == "allowed"
    assert result.victim.backend_event_count == 1
    assert result.detector.scored is True
    assert result.detector.findings == ()


def test_detected_export_partial_tail_crash_preserves_export_scorer_refusal() -> None:
    result = run_detected_scenario(
        "export_vulnerable_attack",
        victim_fault="partial_tail_crash",
    )

    assert result.victim is None
    assert result.authority is None
    assert result.authority_returncode is None
    assert result.victim_returncode == 3
    assert result.detector.scored is False
    assert result.detector.effect_egress_completeness_signals == ("truncated",)
    assert result.detector.findings == ()
    assert result.detector.refusal_reason is not None
    assert "data export scorer" in result.detector.refusal_reason


def test_export_profile_rejects_authority_fault_configuration() -> None:
    with pytest.raises(ValueError, match="data_export profile does not use an approval authority"):
        run_detected_scenario(
            "export_vulnerable_attack",
            authority_fault="exit_before_receipt",
        )
