# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security finding transport and opt-in run-scope helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

EvidenceRef = Annotated[str, Field(min_length=1)]
FindingScopeSignal = Literal["missing_run_id", "run_id_mismatch"]
# Tuple order is public because FindingScopeError.reasons preserves it.
FINDING_SCOPE_SIGNALS: tuple[FindingScopeSignal, ...] = (
    "missing_run_id",
    "run_id_mismatch",
)


class SecurityFinding(BaseModel):
    """Transport schema for detector or scorer findings.

    A ``SecurityFinding`` is a portable record shape, not a detector, policy
    engine, or trust boundary. It does not authenticate ``producer``, verify
    that ``evidence_refs`` exist, or make data constructed inside a victim
    process trustworthy. A finding is only as trustworthy as the execution and
    collection boundary that produced it.

    ``run_id`` is application-assigned scope for grouping findings from one
    run or assessment; NOOA does not mint it, verify it, or infer that equal
    values establish trusted provenance. ``evidence_refs`` are opaque
    identifiers so applications can point at ``EffectRecord.id``,
    ``SecurityReceipt.receipt_id``, SIEM records, or other evidence without
    making NOOA own the join semantics. The schema
    intentionally does not standardize severity, verdict, or enforcement
    action; those remain application policy. Field bindings are frozen for
    transport stability, but nested ``attributes`` values remain ordinary
    Python containers and are not a tamper-resistance boundary.

    ``attributes`` must contain sanitized JSON values only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-finding-v1"] = Field(
        default="nooa-finding-v1",
        description="Finding wire-format discriminator.",
    )
    finding_id: str = Field(
        min_length=1,
        description="Stable finding identifier assigned by the producer.",
    )
    finding_type: str = Field(
        min_length=1,
        description="Application-defined finding category, e.g. 'prompt_injection.suspected'.",
    )
    producer: str = Field(
        min_length=1,
        description="Sanitized identifier for the detector, scorer, or policy producer.",
    )
    run_id: str = Field(
        default="",
        description="Application-assigned run or assessment scope for grouping related findings.",
    )
    target: str = Field(
        default="",
        description="Sanitized target identifier for the finding, if any.",
    )
    evidence_refs: tuple[EvidenceRef, ...] = Field(
        default_factory=tuple,
        description="Opaque identifiers for evidence that supports this finding.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined finding details.",
    )


@dataclass(frozen=True)
class FindingScopeValidation:
    """Run-scope diagnostics for one materialized finding bundle.

    This result preserves the input order in ``findings`` and reports only
    caller-visible ``run_id`` inconsistencies against one caller-selected
    ``expected_run_id``. It does not authenticate finding producers, verify
    evidence references, enforce finding-id uniqueness, determine verdicts or
    severity, or prove that a detector found everything it should have.

    A clean empty result means only that none of the supplied findings
    contradicted the requested run scope. It does not prove that no findings
    exist or that detector coverage was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_finding_scope` performs.
    """

    findings: tuple[SecurityFinding, ...]
    expected_run_id: str
    missing_run_id_finding_ids: tuple[str, ...] = ()
    mismatched_run_id_finding_ids: tuple[str, ...] = ()


class FindingScopeError(RuntimeError):
    """Raised when supplied findings do not fit one expected run scope.

    This error reports only diagnostics visible in a
    :class:`FindingScopeValidation`. It does not establish finding
    authenticity, detector coverage, or semantic correctness.
    """

    def __init__(self, validation: FindingScopeValidation) -> None:
        if not isinstance(validation, FindingScopeValidation):
            raise TypeError(
                "FindingScopeError expected FindingScopeValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = finding_scope_signals(validation)
        if not reasons:
            raise ValueError("FindingScopeError requires at least one scope signal")
        self.expected_run_id = validation.expected_run_id
        self.missing_run_id_finding_ids = validation.missing_run_id_finding_ids
        self.mismatched_run_id_finding_ids = validation.mismatched_run_id_finding_ids
        self.reasons = reasons
        super().__init__(
            "finding bundle does not match expected run scope: "
            f"expected_run_id={validation.expected_run_id!r}, "
            f"missing_run_id_finding_ids={validation.missing_run_id_finding_ids!r}, "
            f"mismatched_run_id_finding_ids={validation.mismatched_run_id_finding_ids!r}"
        )


def finding_scope_signals(validation: FindingScopeValidation) -> tuple[FindingScopeSignal, ...]:
    """Return canonical run-scope diagnostics for one finding bundle."""
    if not isinstance(validation, FindingScopeValidation):
        raise TypeError(
            "finding_scope_signals expected FindingScopeValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[FindingScopeSignal] = []
    if validation.missing_run_id_finding_ids:
        signals.append("missing_run_id")
    if validation.mismatched_run_id_finding_ids:
        signals.append("run_id_mismatch")
    return tuple(signals)


def validate_finding_scope(
    findings: Iterable[SecurityFinding],
    *,
    expected_run_id: str,
) -> FindingScopeValidation:
    """Materialize findings and report run-scope inconsistencies.

    ``findings`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_finding_scope` when no scope signal
    is present. ``expected_run_id`` must be a non-empty caller-selected scope;
    this helper does not mint or authenticate it.

    The helper checks only that each supplied finding carries a non-empty
    ``run_id`` equal to ``expected_run_id``. It does not verify producer
    identity, detector coverage, finding-id uniqueness, evidence references,
    or application-specific finding semantics.
    """
    if not isinstance(expected_run_id, str):
        raise TypeError(
            "validate_finding_scope expected str expected_run_id, "
            f"got {type(expected_run_id).__name__}"
        )
    if not expected_run_id:
        raise ValueError("validate_finding_scope requires non-empty expected_run_id")
    if isinstance(findings, (str, bytes, bytearray)) or not isinstance(findings, Iterable):
        raise TypeError(
            "validate_finding_scope expected iterable of SecurityFinding, "
            f"got {type(findings).__name__}"
        )

    materialized = tuple(findings)
    for index, finding in enumerate(materialized):
        if not isinstance(finding, SecurityFinding):
            raise TypeError(
                "validate_finding_scope expected SecurityFinding at "
                f"index {index}, got {type(finding).__name__}"
            )

    return FindingScopeValidation(
        findings=materialized,
        expected_run_id=expected_run_id,
        missing_run_id_finding_ids=tuple(
            finding.finding_id for finding in materialized if not finding.run_id
        ),
        mismatched_run_id_finding_ids=tuple(
            finding.finding_id
            for finding in materialized
            if finding.run_id and finding.run_id != expected_run_id
        ),
    )


def require_valid_finding_scope(
    validation: FindingScopeValidation,
) -> tuple[SecurityFinding, ...]:
    """Return supplied findings or fail closed on visible run-scope drift."""
    if not isinstance(validation, FindingScopeValidation):
        raise TypeError(
            "require_valid_finding_scope expected FindingScopeValidation, "
            f"got {type(validation).__name__}"
        )
    if finding_scope_signals(validation):
        raise FindingScopeError(validation)
    return validation.findings
