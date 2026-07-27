# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for security finding transport."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nooa.security import SecurityFinding


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
