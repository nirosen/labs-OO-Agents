# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for security finding transport."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nooa.security import (
    FINDING_SCOPE_SIGNALS,
    FindingScopeError,
    FindingScopeValidation,
    SecurityFinding,
    finding_scope_signals,
    require_valid_finding_scope,
    validate_finding_scope,
)


def _finding(**updates: object) -> SecurityFinding:
    fields: dict[str, object] = {
        "finding_id": "finding-1",
        "finding_type": "authorization.missing_receipt",
        "producer": "identity_policy.v1",
        "run_id": "run-20260727-identity-1",
        "target": "invoice-42",
        "evidence_refs": ("effect-event-1", "receipt-audit-1"),
        "attributes": {"rule": "require_approval_token", "matched": True},
    }
    fields.update(updates)
    return SecurityFinding.model_validate(fields)


def test_security_finding_is_strict_json_transport() -> None:
    finding = _finding()

    assert set(finding.model_dump(mode="json")) == {
        "schema_version",
        "finding_id",
        "finding_type",
        "producer",
        "run_id",
        "target",
        "evidence_refs",
        "attributes",
    }
    assert finding.schema_version == "nooa-finding-v1"
    assert finding.finding_id == "finding-1"
    assert finding.finding_type == "authorization.missing_receipt"
    assert finding.producer == "identity_policy.v1"
    assert finding.run_id == "run-20260727-identity-1"
    assert finding.target == "invoice-42"
    assert finding.evidence_refs == ("effect-event-1", "receipt-audit-1")
    assert finding.attributes == {"rule": "require_approval_token", "matched": True}

    with pytest.raises(ValidationError):
        _finding(typo="not-allowed")
    with pytest.raises(ValidationError):
        _finding(schema_version="nooa-finding-v2")
    with pytest.raises(ValidationError):
        _finding(attributes={"unsafe": object()})
    with pytest.raises(ValidationError):
        _finding(evidence_refs=("effect-event-1", ""))


def test_security_finding_defaults_round_trip_and_freeze_field_bindings() -> None:
    finding = SecurityFinding(
        finding_id="finding-2",
        finding_type="prompt_injection.suspected",
        producer="prompt_detector.v1",
    )

    assert finding.target == ""
    assert finding.run_id == ""
    assert finding.evidence_refs == ()
    assert finding.attributes == {}
    assert SecurityFinding.model_validate_json(finding.model_dump_json()) == finding

    with pytest.raises(ValidationError):
        finding.finding_id = "finding-3"


def test_security_finding_evidence_refs_are_opaque_ids() -> None:
    finding = _finding(
        evidence_refs=("effect-event-1", "receipt-audit-1", "siem-event-9"),
    )

    assert finding.evidence_refs == ("effect-event-1", "receipt-audit-1", "siem-event-9")


def test_validate_finding_scope_materializes_once_and_preserves_order() -> None:
    source = iter(
        (
            _finding(finding_id="finding-1"),
            _finding(finding_id="finding-2"),
        )
    )

    validation = validate_finding_scope(
        source,
        expected_run_id="run-20260727-identity-1",
    )

    assert tuple(source) == ()
    assert [finding.finding_id for finding in validation.findings] == ["finding-1", "finding-2"]
    assert validation.expected_run_id == "run-20260727-identity-1"
    assert validation.missing_run_id_finding_ids == ()
    assert validation.mismatched_run_id_finding_ids == ()
    assert finding_scope_signals(validation) == ()
    assert require_valid_finding_scope(validation) is validation.findings


def test_validate_finding_scope_reports_canonical_run_scope_diagnostics() -> None:
    validation = validate_finding_scope(
        (
            _finding(finding_id="finding-current"),
            _finding(finding_id="finding-missing", run_id=""),
            _finding(finding_id="finding-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    assert validation.missing_run_id_finding_ids == ("finding-missing",)
    assert validation.mismatched_run_id_finding_ids == ("finding-stale",)
    assert finding_scope_signals(validation) == ("missing_run_id", "run_id_mismatch")
    assert FINDING_SCOPE_SIGNALS == ("missing_run_id", "run_id_mismatch")


@pytest.mark.parametrize(
    ("findings", "expected_signals", "expected_missing_ids", "expected_mismatched_ids"),
    [
        pytest.param(
            (
                _finding(finding_id="finding-missing-1", run_id=""),
                _finding(finding_id="finding-missing-2", run_id=""),
            ),
            ("missing_run_id",),
            ("finding-missing-1", "finding-missing-2"),
            (),
            id="missing-only",
        ),
        pytest.param(
            (
                _finding(finding_id="finding-stale-1", run_id="run-prior"),
                _finding(finding_id="finding-stale-2", run_id="run-other"),
            ),
            ("run_id_mismatch",),
            (),
            ("finding-stale-1", "finding-stale-2"),
            id="mismatch-only",
        ),
    ],
)
def test_validate_finding_scope_preserves_each_single_signal_category(
    findings: tuple[SecurityFinding, ...],
    expected_signals: tuple[str, ...],
    expected_missing_ids: tuple[str, ...],
    expected_mismatched_ids: tuple[str, ...],
) -> None:
    validation = validate_finding_scope(
        findings,
        expected_run_id="run-20260727-identity-1",
    )

    assert finding_scope_signals(validation) == expected_signals
    assert validation.missing_run_id_finding_ids == expected_missing_ids
    assert validation.mismatched_run_id_finding_ids == expected_mismatched_ids


def test_require_valid_finding_scope_raises_structured_error() -> None:
    validation = validate_finding_scope(
        (
            _finding(finding_id="finding-missing", run_id=""),
            _finding(finding_id="finding-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    with pytest.raises(FindingScopeError) as exc_info:
        require_valid_finding_scope(validation)

    error = exc_info.value
    assert error.reasons == ("missing_run_id", "run_id_mismatch")
    assert error.expected_run_id == "run-20260727-identity-1"
    assert error.missing_run_id_finding_ids == ("finding-missing",)
    assert error.mismatched_run_id_finding_ids == ("finding-stale",)
    assert not isinstance(error, ValueError)


def test_empty_finding_scope_passes_without_claiming_coverage() -> None:
    validation = validate_finding_scope((), expected_run_id="run-20260727-identity-1")

    assert validation.findings == ()
    assert finding_scope_signals(validation) == ()
    assert require_valid_finding_scope(validation) == ()


@pytest.mark.parametrize("expected_run_id", ["", None, 0])
def test_validate_finding_scope_rejects_invalid_expected_run_id(expected_run_id: object) -> None:
    error_type = ValueError if expected_run_id == "" else TypeError
    with pytest.raises(error_type):
        validate_finding_scope(
            (),
            expected_run_id=expected_run_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("findings", ["not-findings", b"not-findings", [object()]])
def test_validate_finding_scope_rejects_non_finding_inputs(findings: object) -> None:
    with pytest.raises(TypeError, match="SecurityFinding"):
        validate_finding_scope(
            findings,  # type: ignore[arg-type]
            expected_run_id="run-20260727-identity-1",
        )


def test_finding_scope_helpers_reject_non_validation_inputs_and_clean_error() -> None:
    with pytest.raises(TypeError, match="expected FindingScopeValidation"):
        finding_scope_signals("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingScopeValidation"):
        require_valid_finding_scope("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingScopeValidation"):
        FindingScopeError("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one scope signal"):
        FindingScopeError(FindingScopeValidation(findings=(), expected_run_id="run-1"))
