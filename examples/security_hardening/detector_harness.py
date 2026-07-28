# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Out-of-process detector harness for two security-hardening victim profiles.

This example keeps process lifecycle outside ``src/nooa``. Every profile gives
the victim only an effect write end and gives the detector only the effect read
end. The identity-approval profile also wires a separate approval authority and
receipt pipe; the data-export profile leaves those unwired and scores a
receipt-free destination policy. Both profiles construct one
:class:`~nooa.security.DetectorInput` inside the same detector code path before
running their application-local scorer, then emit report metadata on stdout and
finding rows through a separate :class:`~nooa.security.FindingBundle`.

The split shows where a separately controlled detector and optional approval
issuer can run. This branch expects V2 effect egress so EOF before
writer-declared completion becomes a detector refusal. When an authority
receipt pipe is present, the example also wraps the profile scorer with one
receipt-ID uniqueness gate, one receipt source-alignment gate, and one receipt
run-scope gate keyed by the supervisor-selected ``run_id`` so a repeated receipt
ID, visibly mismatched row source, or stale receipt copy becomes a refusal
before policy runs. Every profile also wraps its scorer with one detector-side
evidence-reference membership gate built from the current ``DetectorInput``
IDs, so a scorer that invents a reference outside that input becomes a refusal
before the finding bundle is emitted. This does not authenticate channel
contents, receipt sources, scorer output, allowed evidence IDs, or refusal text;
make same-user subprocesses a trust boundary; provide sandboxing or attestation;
prove that an issued token was honored; or turn detector findings into
enforcement. The receipt path now uses the public LF-terminated bundle reader so
EOF before the bundle terminator becomes an explicit detector refusal before
receipt-ID uniqueness, source alignment, run-scope, or profile policy runs.
After the detector subprocess emits its report and finding bundle, the
supervisor admits only a bounded report payload to parsing, reads one bounded
LF-terminated finding document from a supervisor-owned temporary file,
cross-checks ``declared_finding_count``, checks both report and finding row
scopes against the supervisor-selected ``run_id``, and refuses repeated
``finding_id`` values before requiring each admitted row to cite the
supervisor-selected ``input_id``. The report admission path also rejects a
visible ``detector_input_id`` echo that does not match that supervisor-selected
value. Existing scope and report-coherence refusals retain precedence; the
ID-uniqueness gate runs only after those checks pass, and the required-ref gate
runs last. For current finding-admission failures, the supervisor clears any
child-supplied value and sets one example-local ``finding_admission_refusal``
field so consumers need not parse refusal text to identify the failed stage.
The supervisor also admits victim and authority summary payloads through their own
bounded parse checks and rejects visible victim scenario drift before
assembling ``DetectedScenario``. The stdout bounds are parse-admission checks
after ``communicate()`` has already collected stdout; the finding-bundle bound
applies when the supervisor later reads the temporary file. Neither makes
well-formed child lies impossible.

    uv run python -m examples.security_hardening.detector_harness demo
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import TemporaryFile
from typing import BinaryIO, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from examples.security_hardening.approval_authority import (
    _AUTHORITY_FAULTS,
    DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
    ApprovalRequestDocument,
    ApprovalResponseDocument,
    AuthorityFault,
    AuthoritySummary,
    approval_tokens_by_request_id,
    read_approval_response_document,
)
from examples.security_hardening.data_export import (
    EXPORT_SCENARIOS,
    DataExportAgent,
    DataExportBackend,
    detect_exports_outside_allowlist,
    observe_data_export,
)
from examples.security_hardening.data_export import (
    scenario_config as data_export_scenario_config,
)
from examples.security_hardening.detector_policy import UnscoreableDetectorInputError
from examples.security_hardening.effect_collector import (
    _VICTIM_FAULTS,
    VictimFault,
    VictimSummary,
    _approval_request_read_identity_from_args,
    _approval_response_write_identity_from_args,
    _collector_read_identity_from_args,
    _FaultInjectingV2Sink,
    _fd_identity,
    _finish_victim_effect_stream,
    _has_fd_identity,
    _receipt_read_identity_from_args,
    _receipt_write_identity_from_args,
    _scenario_config,
    _terminate_process,
    _validate_victim_fault,
)
from examples.security_hardening.identity_approval import (
    IdentityApprovalAgent,
    IdentityBackend,
    detect_grants_without_approval,
    install_identity_grant_defender,
    observe_identity_grant,
)
from nooa.security import (
    DEFAULT_FINDING_BUNDLE_MAX_BYTES,
    DEFAULT_RECEIPT_BUNDLE_MAX_BYTES,
    EFFECT_EGRESS_COMPLETENESS_SIGNALS,
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
    FINDING_BUNDLE_COMPLETENESS_SIGNALS,
    RECEIPT_BUNDLE_COMPLETENESS_SIGNALS,
    DetectorInput,
    EffectEgressCompletenessSignal,
    EffectEgressReadResult,
    FindingBundle,
    FindingBundleCompletenessSignal,
    FindingBundleIncompleteError,
    FindingBundleInputTooLargeError,
    FindingBundleReadResult,
    FindingEvidenceRefError,
    FindingIdUniquenessError,
    FindingRequiredEvidenceRefError,
    FindingScopeError,
    ReceiptBundleCompletenessSignal,
    ReceiptBundleIncompleteError,
    ReceiptBundleReadResult,
    ReceiptCoverage,
    ReceiptIdUniquenessError,
    ReceiptScopeError,
    ReceiptSourceAlignmentError,
    SecurityFinding,
    UnsupportedFindingBundleVersionError,
    detector_input_from_egress,
    finding_bundle_completeness_signals,
    framework_guard_observer,
    install_agent_call_effect_recorder,
    install_effect_recorder,
    install_effect_sink,
    read_effect_egress,
    read_finding_bundle,
    read_receipt_bundle,
    receipt_bundle_completeness_signals,
    require_complete_finding_bundle,
    require_complete_receipt_bundle,
    require_valid_finding_evidence_ref_membership,
    require_valid_finding_id_uniqueness,
    require_valid_finding_required_evidence_ref,
    require_valid_finding_scope,
    require_valid_receipt_id_uniqueness,
    require_valid_receipt_scope,
    require_valid_receipt_source_alignment,
    validate_finding_evidence_ref_membership,
    validate_finding_id_uniqueness,
    validate_finding_required_evidence_ref,
    validate_finding_scope,
    validate_receipt_id_uniqueness,
    validate_receipt_scope,
    validate_receipt_source_alignment,
    write_finding_bundle,
)

_DETECTOR_REPORT_SCHEMA_VERSION: Literal["nooa-detector-harness-example-v4"] = (
    "nooa-detector-harness-example-v4"
)
_DETECTED_SCENARIO_SCHEMA_VERSION: Literal["nooa-detector-scenario-example-v4"] = (
    "nooa-detector-scenario-example-v4"
)
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DETECTOR_RECEIPT_MAX_BYTES = DEFAULT_RECEIPT_BUNDLE_MAX_BYTES
DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES = DEFAULT_FINDING_BUNDLE_MAX_BYTES
DEFAULT_DETECTOR_REPORT_MAX_BYTES = 1024 * 1024
DEFAULT_VICTIM_SUMMARY_MAX_BYTES = 1024 * 1024
DEFAULT_AUTHORITY_SUMMARY_MAX_BYTES = 1024 * 1024
_DETECTOR_FAULTS = (
    "none",
    "blank_finding_run_id",
    "stale_finding_run_id",
    "duplicate_finding_id",
    "drop_required_evidence_ref",
    "truncate_finding_document",
    "drop_finding_count_mismatch",
)
DetectorFault = Literal[
    "none",
    "blank_finding_run_id",
    "stale_finding_run_id",
    "duplicate_finding_id",
    "drop_required_evidence_ref",
    "truncate_finding_document",
    "drop_finding_count_mismatch",
]
_SUBPROCESS_OUTPUT_FAULTS = (
    "none",
    "malformed_detector_report",
    "malformed_victim_summary",
    "stale_victim_scenario",
    "malformed_authority_summary",
)
SubprocessOutputFault = Literal[
    "none",
    "malformed_detector_report",
    "malformed_victim_summary",
    "stale_victim_scenario",
    "malformed_authority_summary",
]
SupervisorAdmissionRole = Literal["victim", "authority"]
SupervisorAdmissionReason = Literal["payload_too_large", "invalid_payload", "scenario_mismatch"]
FindingAdmissionRefusal = Literal[
    "count_mismatch",
    "scope_drift",
    "refused_report_rows",
    "duplicate_finding_id",
    "missing_required_evidence_ref",
]
_FINDING_ADMISSION_REFUSALS: tuple[FindingAdmissionRefusal, ...] = (
    "count_mismatch",
    "scope_drift",
    "refused_report_rows",
    "duplicate_finding_id",
    "missing_required_evidence_ref",
)
DetectorScorer = Callable[[DetectorInput], tuple[SecurityFinding, ...]]


@dataclass(frozen=True)
class DetectorProfile:
    """Example-local detector profile for one victim family."""

    name: str
    scorer_name: str
    scenario_names: frozenset[str]
    scorer: DetectorScorer
    run_id_prefix: str
    uses_approval_authority: bool


_IDENTITY_PROFILE = DetectorProfile(
    name="identity_approval",
    scorer_name="identity-approval-scorer",
    scenario_names=frozenset(
        {
            "vulnerable_attack",
            "defender_only_attack",
            "hardened_attack",
            "hardened_authorized",
        }
    ),
    scorer=detect_grants_without_approval,
    run_id_prefix="identity-approval-demo",
    uses_approval_authority=True,
)
_DATA_EXPORT_PROFILE = DetectorProfile(
    name="data_export",
    scorer_name="data-export-scorer",
    scenario_names=EXPORT_SCENARIOS,
    scorer=detect_exports_outside_allowlist,
    run_id_prefix="data-export-demo",
    uses_approval_authority=False,
)
_DETECTOR_PROFILES = {
    profile.name: profile for profile in (_IDENTITY_PROFILE, _DATA_EXPORT_PROFILE)
}


class DetectorReport(BaseModel):
    """Example-local result emitted by the detector subprocess.

    ``scored=False`` means this example's policy declined to score the
    assembled bundle. It is not a vulnerability verdict and does not imply the
    input was malicious.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-harness-example-v4"] = (
        _DETECTOR_REPORT_SCHEMA_VERSION
    )
    victim_profile: str = Field(min_length=1)
    scorer_name: str = Field(min_length=1)
    detector_input_id: str = Field(min_length=1)
    run_id: str = ""
    effect_egress_completeness_signals: tuple[EffectEgressCompletenessSignal, ...] = ()
    effect_egress_completeness_gate_passed: bool = False
    receipt_bundle_completeness_signals: tuple[ReceiptBundleCompletenessSignal, ...] = ()
    receipt_bundle_completeness_gate_passed: bool = False
    finding_bundle_completeness_signals: tuple[FindingBundleCompletenessSignal, ...] = ()
    finding_bundle_completeness_gate_passed: bool = False
    receipt_source: str = ""
    receipt_coverage: ReceiptCoverage = "unknown"
    receipt_count: int = Field(default=0, ge=0)
    declared_receipt_count: int | None = Field(default=None, ge=0)
    declared_finding_count: int | None = Field(default=None, ge=0)
    finding_admission_refusal: FindingAdmissionRefusal | None = None
    scored: bool
    refusal_reason: str | None = None

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
        profile = _profile_from_name(self.victim_profile)
        if self.scorer_name != profile.scorer_name:
            raise ValueError("scorer_name must match victim_profile")
        canonical = tuple(
            signal
            for signal in EFFECT_EGRESS_COMPLETENESS_SIGNALS
            if signal in self.effect_egress_completeness_signals
        )
        if self.effect_egress_completeness_signals != canonical:
            raise ValueError(
                "effect_egress_completeness_signals must use canonical unique order"
            )
        if self.effect_egress_completeness_gate_passed and self.effect_egress_completeness_signals:
            raise ValueError(
                "effect_egress_completeness_gate_passed cannot be true when "
                "effect_egress_completeness_signals is non-empty"
            )
        canonical_receipt_bundle_signals = tuple(
            signal
            for signal in RECEIPT_BUNDLE_COMPLETENESS_SIGNALS
            if signal in self.receipt_bundle_completeness_signals
        )
        if self.receipt_bundle_completeness_signals != canonical_receipt_bundle_signals:
            raise ValueError(
                "receipt_bundle_completeness_signals must use canonical unique order"
            )
        if (
            self.receipt_bundle_completeness_gate_passed
            and self.receipt_bundle_completeness_signals
        ):
            raise ValueError(
                "receipt_bundle_completeness_gate_passed cannot be true when "
                "receipt_bundle_completeness_signals is non-empty"
            )
        canonical_finding_bundle_signals = tuple(
            signal
            for signal in FINDING_BUNDLE_COMPLETENESS_SIGNALS
            if signal in self.finding_bundle_completeness_signals
        )
        if self.finding_bundle_completeness_signals != canonical_finding_bundle_signals:
            raise ValueError(
                "finding_bundle_completeness_signals must use canonical unique order"
            )
        if (
            self.finding_bundle_completeness_gate_passed
            and self.finding_bundle_completeness_signals
        ):
            raise ValueError(
                "finding_bundle_completeness_gate_passed cannot be true when "
                "finding_bundle_completeness_signals is non-empty"
            )
        if self.finding_admission_refusal is not None:
            if self.finding_admission_refusal not in _FINDING_ADMISSION_REFUSALS:
                raise ValueError("finding_admission_refusal must be a known refusal")
            if not self.finding_bundle_completeness_gate_passed:
                raise ValueError(
                    "finding_admission_refusal requires "
                    "finding_bundle_completeness_gate_passed=True"
                )
            if self.scored:
                raise ValueError("scored detector report cannot carry finding_admission_refusal")
        if self.scored and self.refusal_reason is not None:
            raise ValueError("scored detector report cannot carry refusal_reason")
        if self.scored and self.declared_finding_count is None:
            raise ValueError("scored detector report requires declared_finding_count")
        if not self.scored:
            if self.refusal_reason is None:
                raise ValueError("refused detector report requires refusal_reason")
        return self


class SupervisorAdmissionError(RuntimeError):
    """Raised when one child summary cannot be admitted by the supervisor.

    The error carries only supervisor-visible parse-admission facts. It does
    not authenticate the child process, prove summary truth, or turn an echoed
    field into trusted provenance. Detector report admission does not raise
    this error because ``DetectorReport`` already has its own ``scored=False``
    refusal channel.
    """

    def __init__(
        self,
        *,
        role: SupervisorAdmissionRole,
        reason: SupervisorAdmissionReason,
        payload_bytes: int | None = None,
        limit_name: str | None = None,
        limit_value: int | None = None,
        expected_scenario: str | None = None,
        reported_scenario: str | None = None,
    ) -> None:
        self.role = role
        self.reason = reason
        self.payload_bytes = payload_bytes
        self.limit_name = limit_name
        self.limit_value = limit_value
        self.expected_scenario = expected_scenario
        self.reported_scenario = reported_scenario
        if reason == "payload_too_large":
            if payload_bytes is None or limit_name is None or limit_value is None:
                raise ValueError("payload_too_large requires payload and limit facts")
            detail = f"payload_bytes={payload_bytes} exceeds {limit_name}={limit_value}"
            prefix = f"supervisor {role} summary parse admission refused output"
        elif reason == "invalid_payload":
            detail = "invalid summary payload"
            prefix = f"supervisor {role} summary parse admission refused output"
        else:
            if expected_scenario is None or reported_scenario is None:
                raise ValueError("scenario_mismatch requires expected and reported scenarios")
            detail = (
                f"expected_scenario={expected_scenario!r}, "
                f"reported_scenario={reported_scenario!r}"
            )
            prefix = "supervisor victim summary scope gate refused output"
        super().__init__(f"{prefix}: {detail}")


class DetectedScenario(BaseModel):
    """Supervisor-side join of victim, authority, and detector outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-scenario-example-v4"] = (
        _DETECTED_SCENARIO_SCHEMA_VERSION
    )
    victim_profile: str = Field(min_length=1)
    victim: VictimSummary | None = None
    authority: AuthoritySummary | None = None
    detector: DetectorReport
    findings: tuple[SecurityFinding, ...] = ()
    victim_returncode: int
    authority_returncode: int | None = None
    detector_returncode: int

    @model_validator(mode="after")
    def _validate_process_results(self) -> Self:
        profile = _profile_from_name(self.victim_profile)
        if self.detector.victim_profile != self.victim_profile:
            raise ValueError("detector victim_profile must match detected scenario")
        if self.victim_returncode == 0 and self.victim is None:
            raise ValueError("successful victim subprocess must emit a victim summary")
        if profile.uses_approval_authority and self.authority_returncode is None:
            raise ValueError("approval authority profile requires authority_returncode")
        if not profile.uses_approval_authority and (
            self.authority is not None or self.authority_returncode is not None
        ):
            raise ValueError("receipt-free profile cannot carry authority process results")
        if self.authority_returncode is None:
            if self.authority is not None:
                raise ValueError("authority summary requires authority_returncode")
        else:
            if self.authority_returncode == 0 and self.authority is None:
                raise ValueError("successful authority subprocess must emit an authority summary")
            if self.authority_returncode != 0:
                raise ValueError("detected scenario requires a successful authority subprocess")
        if self.detector_returncode != 0:
            raise ValueError("detected scenario requires a successful detector subprocess")
        if not self.detector.scored and self.findings:
            raise ValueError("refused detector scenario cannot carry findings")
        if self.detector.scored and self.detector.declared_finding_count != len(self.findings):
            raise ValueError("declared_finding_count must match admitted findings")
        return self


def score_detector_input(
    detector_input: DetectorInput,
    *,
    victim_profile: str = _IDENTITY_PROFILE.name,
    scorer_name: str = _IDENTITY_PROFILE.scorer_name,
    scorer: DetectorScorer = detect_grants_without_approval,
    receipt_count: int | None = None,
    declared_receipt_count: int | None = None,
    receipt_bundle_completeness_signals: tuple[ReceiptBundleCompletenessSignal, ...] = (),
    receipt_bundle_completeness_gate_passed: bool = False,
) -> tuple[DetectorReport, FindingBundle]:
    """Run one scorer and return report metadata plus out-of-band finding rows."""
    if not isinstance(detector_input, DetectorInput):
        raise TypeError(
            "score_detector_input expected DetectorInput, "
            f"got {type(detector_input).__name__}"
        )
    if receipt_count is None:
        receipt_count = len(detector_input.receipts)
    report_fields = {
        "victim_profile": victim_profile,
        "scorer_name": scorer_name,
        "detector_input_id": detector_input.input_id,
        "run_id": detector_input.run_id,
        "effect_egress_completeness_signals": detector_input.effect_egress_completeness_signals,
        "effect_egress_completeness_gate_passed": detector_input.effect_egress_completeness_gate_passed,
        "receipt_bundle_completeness_signals": receipt_bundle_completeness_signals,
        "receipt_bundle_completeness_gate_passed": receipt_bundle_completeness_gate_passed,
        "receipt_source": detector_input.receipt_source,
        "receipt_coverage": detector_input.receipt_coverage,
        "receipt_count": receipt_count,
        "declared_receipt_count": declared_receipt_count,
    }
    try:
        findings = scorer(detector_input)
    except UnscoreableDetectorInputError as exc:
        return (
            DetectorReport(
                **report_fields,
                declared_finding_count=0,
                scored=False,
                refusal_reason=str(exc),
            ),
            FindingBundle(producer=scorer_name),
        )
    return (
        DetectorReport(
            **report_fields,
            declared_finding_count=len(findings),
            scored=True,
        ),
        FindingBundle(
            producer=scorer_name,
            findings=findings,
        ),
    )


def receipt_scope_gated_scorer(
    scorer: DetectorScorer,
    *,
    expected_run_id: str,
) -> DetectorScorer:
    """Wrap one scorer with an example-local receipt run-scope gate.

    The expected scope comes from the supervisor-selected run identifier, not
    from the detector input itself. The wrapper converts visible receipt scope
    drift into the same example-local refusal path used for policy refusals.
    It does not authenticate the scope, receipt source, or refusal text.
    """
    if not callable(scorer):
        raise TypeError(
            "receipt_scope_gated_scorer expected callable scorer, "
            f"got {type(scorer).__name__}"
        )

    def _score(detector_input: DetectorInput) -> tuple[SecurityFinding, ...]:
        try:
            require_valid_receipt_scope(
                validate_receipt_scope(
                    detector_input.receipts,
                    expected_run_id=expected_run_id,
                )
            )
        except ReceiptScopeError as exc:
            raise UnscoreableDetectorInputError(
                f"detector receipt scope gate refused input: {exc}"
            ) from exc
        # Keep scorer-owned refusals distinct from receipt-scope refusals.
        return scorer(detector_input)

    return _score


def receipt_id_uniqueness_gated_scorer(scorer: DetectorScorer) -> DetectorScorer:
    """Wrap one scorer with an example-local receipt-ID uniqueness gate.

    This checks only whether one supplied receipt iterable reuses a
    ``receipt_id`` before receipt scope or policy runs. It does not authenticate
    receipts, sources, or identifiers; prove that distinct identifiers denote
    distinct receipts; establish uniqueness across bundles, runs, or sources;
    or survive a hostile detector process.
    """
    if not callable(scorer):
        raise TypeError(
            "receipt_id_uniqueness_gated_scorer expected callable scorer, "
            f"got {type(scorer).__name__}"
        )

    def _score(detector_input: DetectorInput) -> tuple[SecurityFinding, ...]:
        try:
            require_valid_receipt_id_uniqueness(
                validate_receipt_id_uniqueness(detector_input.receipts)
            )
        except ReceiptIdUniquenessError as exc:
            raise UnscoreableDetectorInputError(
                f"detector receipt ID uniqueness gate refused input: {exc}"
            ) from exc
        return scorer(detector_input)

    return _score


def receipt_source_alignment_gated_scorer(
    scorer: DetectorScorer,
    *,
    expected_source: str,
) -> DetectorScorer:
    """Wrap one scorer with an example-local receipt source-alignment gate.

    This checks only whether one supplied receipt iterable carries row
    ``source`` values exactly equal to one caller-supplied ``expected_source``.
    In this example the expected value comes from the same receipt bundle, so
    the check is intra-document coherence rather than provenance. It does not
    authenticate receipts, sources, or the expected value; prove that receipts
    originated from the named source; or survive a hostile detector process.
    """
    if not callable(scorer):
        raise TypeError(
            "receipt_source_alignment_gated_scorer expected callable scorer, "
            f"got {type(scorer).__name__}"
        )

    def _score(detector_input: DetectorInput) -> tuple[SecurityFinding, ...]:
        try:
            require_valid_receipt_source_alignment(
                validate_receipt_source_alignment(
                    detector_input.receipts,
                    expected_source=expected_source,
                )
            )
        except ReceiptSourceAlignmentError as exc:
            raise UnscoreableDetectorInputError(
                f"detector receipt source alignment gate refused input: {exc}"
            ) from exc
        return scorer(detector_input)

    return _score


def evidence_ref_membership_gated_scorer(scorer: DetectorScorer) -> DetectorScorer:
    """Wrap one scorer with an example-local evidence-reference membership gate.

    The allowed ID set is built from the same ``DetectorInput`` the scorer sees:
    its ``input_id``, effect IDs, and receipt IDs. This checks only whether one
    scorer output references IDs outside that supplied input. It does not
    authenticate the input, scorer, findings, or referenced evidence; require a
    finding to cite any evidence; or survive a hostile detector process.
    """
    if not callable(scorer):
        raise TypeError(
            "evidence_ref_membership_gated_scorer expected callable scorer, "
            f"got {type(scorer).__name__}"
        )

    def _score(detector_input: DetectorInput) -> tuple[SecurityFinding, ...]:
        findings = scorer(detector_input)
        allowed_evidence_ids = (
            detector_input.input_id,
            *(effect.id for effect in detector_input.effects),
            *(receipt.receipt_id for receipt in detector_input.receipts),
        )
        try:
            return require_valid_finding_evidence_ref_membership(
                validate_finding_evidence_ref_membership(
                    findings,
                    allowed_evidence_ids=allowed_evidence_ids,
                )
            )
        except FindingEvidenceRefError as exc:
            raise UnscoreableDetectorInputError(
                f"detector evidence ref membership gate refused scorer output: {exc}"
            ) from exc

    return _score


def score_fd(
    effect_fd: int,
    receipt_fd: int | None,
    finding_fd: int,
    *,
    profile_name: str = _IDENTITY_PROFILE.name,
    run_id: str,
    input_id: str,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    fault: DetectorFault = "none",
) -> DetectorReport:
    """Assemble one detector input, emit one finding bundle, then return report metadata."""
    profile = _profile_from_name(profile_name)
    fault = _validate_detector_fault(fault)
    with os.fdopen(effect_fd, "rb", closefd=True) as effect_fh:
        egress = read_effect_egress(
            effect_fh,
            expected_schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2,
        )
    scorer = evidence_ref_membership_gated_scorer(profile.scorer)
    receipts = ()
    receipt_source = ""
    receipt_coverage: ReceiptCoverage = "unknown"
    declared_receipt_count: int | None = None
    receipt_bundle_signals: tuple[ReceiptBundleCompletenessSignal, ...] = ()
    receipt_bundle_gate_passed = False
    if receipt_fd is not None:
        with os.fdopen(receipt_fd, "rb", closefd=True) as receipt_fh:
            receipt_bundle_result = read_receipt_bundle(
                receipt_fh,
                max_bundle_bytes=max_receipt_bytes,
            )
        receipt_bundle_signals = receipt_bundle_completeness_signals(receipt_bundle_result)
        try:
            receipt_bundle = require_complete_receipt_bundle(receipt_bundle_result)
        except ReceiptBundleIncompleteError as exc:
            report = _receipt_bundle_refusal_report(
                profile=profile,
                input_id=input_id,
                run_id=run_id,
                egress=egress,
                receipt_bundle_result=receipt_bundle_result,
                refusal_reason=f"detector receipt bundle completeness gate refused input: {exc}",
            )
            _write_detector_finding_bundle(
                finding_fd,
                FindingBundle(producer=profile.scorer_name),
                fault=fault,
            )
            return report
        receipts = receipt_bundle.receipts
        receipt_source = receipt_bundle.receipt_source
        receipt_coverage = cast(ReceiptCoverage, receipt_bundle.receipt_coverage)
        declared_receipt_count = receipt_bundle.declared_receipt_count
        receipt_bundle_gate_passed = True
        if profile.uses_approval_authority:
            scorer = receipt_scope_gated_scorer(
                scorer,
                expected_run_id=run_id,
            )
            scorer = receipt_source_alignment_gated_scorer(
                scorer,
                expected_source=receipt_bundle.receipt_source,
            )
            scorer = receipt_id_uniqueness_gated_scorer(scorer)
    detector_input = detector_input_from_egress(
        egress,
        input_id=input_id,
        run_id=run_id,
        receipts=receipts,
        receipt_source=receipt_source,
        receipt_coverage=receipt_coverage,
        require_complete=False,
    )
    report, finding_bundle = score_detector_input(
        detector_input,
        victim_profile=profile.name,
        scorer_name=profile.scorer_name,
        scorer=scorer,
        receipt_count=len(receipts),
        declared_receipt_count=declared_receipt_count,
        receipt_bundle_completeness_signals=receipt_bundle_signals,
        receipt_bundle_completeness_gate_passed=receipt_bundle_gate_passed,
    )
    report, finding_bundle = _inject_detector_fault(
        report,
        finding_bundle,
        fault=fault,
        run_id=run_id,
        input_id=input_id,
    )
    _write_detector_finding_bundle(finding_fd, finding_bundle, fault=fault)
    return report


def _receipt_bundle_refusal_report(
    *,
    profile: DetectorProfile,
    input_id: str,
    run_id: str,
    egress: EffectEgressReadResult,
    receipt_bundle_result: ReceiptBundleReadResult,
    refusal_reason: str,
) -> DetectorReport:
    """Render one example-local refusal before receipt scope or profile policy."""
    bundle = receipt_bundle_result.bundle
    detector_input = detector_input_from_egress(
        egress,
        input_id=input_id,
        run_id=run_id,
        require_complete=False,
    )
    return DetectorReport(
        victim_profile=profile.name,
        scorer_name=profile.scorer_name,
        detector_input_id=detector_input.input_id,
        run_id=detector_input.run_id,
        effect_egress_completeness_signals=detector_input.effect_egress_completeness_signals,
        effect_egress_completeness_gate_passed=(
            detector_input.effect_egress_completeness_gate_passed
        ),
        receipt_bundle_completeness_signals=receipt_bundle_completeness_signals(
            receipt_bundle_result
        ),
        receipt_bundle_completeness_gate_passed=False,
        receipt_source=bundle.receipt_source if bundle is not None else "",
        receipt_coverage=(
            cast(ReceiptCoverage, bundle.receipt_coverage) if bundle is not None else "unknown"
        ),
        receipt_count=len(bundle.receipts) if bundle is not None else 0,
        declared_receipt_count=(
            bundle.declared_receipt_count if bundle is not None else None
        ),
        declared_finding_count=0,
        scored=False,
        refusal_reason=refusal_reason,
    )


def _inject_detector_fault(
    report: DetectorReport,
    finding_bundle: FindingBundle,
    *,
    fault: DetectorFault,
    run_id: str,
    input_id: str,
) -> tuple[DetectorReport, FindingBundle]:
    """Apply one example-only detector output fault after scoring."""
    if fault == "none":
        return report, finding_bundle
    if not report.scored:
        raise ValueError(f"{fault} requires a scored detector report")
    if not finding_bundle.findings:
        raise ValueError(f"{fault} requires at least one detector finding")
    if fault in {"blank_finding_run_id", "stale_finding_run_id"}:
        first, *remaining = finding_bundle.findings
        faulted_finding = SecurityFinding.model_validate(
            {
                **first.model_dump(mode="python"),
                "run_id": "" if fault == "blank_finding_run_id" else f"{run_id}/stale",
            }
        )
        return report, FindingBundle.model_validate(
            {
                **finding_bundle.model_dump(mode="python"),
                "findings": (faulted_finding, *remaining),
            }
        )
    if fault == "duplicate_finding_id":
        first, *remaining = finding_bundle.findings
        duplicate = SecurityFinding.model_validate(first.model_dump(mode="python"))
        faulted_findings = (first, duplicate, *remaining)
        faulted_report = DetectorReport.model_validate(
            {
                **report.model_dump(mode="python"),
                "declared_finding_count": len(faulted_findings),
            }
        )
        return faulted_report, FindingBundle.model_validate(
            {
                **finding_bundle.model_dump(mode="python"),
                "findings": faulted_findings,
            }
        )
    if fault == "drop_required_evidence_ref":
        first, *remaining = finding_bundle.findings
        faulted_evidence_refs = tuple(
            evidence_ref for evidence_ref in first.evidence_refs if evidence_ref != input_id
        )
        if faulted_evidence_refs == first.evidence_refs:
            raise ValueError(f"{fault} requires a finding that cites input_id")
        faulted_finding = SecurityFinding.model_validate(
            {
                **first.model_dump(mode="python"),
                "evidence_refs": faulted_evidence_refs,
            }
        )
        return report, FindingBundle.model_validate(
            {
                **finding_bundle.model_dump(mode="python"),
                "findings": (faulted_finding, *remaining),
            }
        )
    if fault == "drop_finding_count_mismatch":
        return report, FindingBundle.model_validate(
            {
                **finding_bundle.model_dump(mode="python"),
                "findings": tuple(finding_bundle.findings[1:]),
            }
        )
    if fault == "truncate_finding_document":
        return report, finding_bundle
    raise AssertionError(f"unhandled detector fault: {fault}")


def _write_detector_finding_bundle(
    finding_fd: int,
    finding_bundle: FindingBundle,
    *,
    fault: DetectorFault,
) -> None:
    """Write the detector's finding bundle to its dedicated inherited descriptor."""
    with os.fdopen(finding_fd, "wb", closefd=True) as finding_fh:
        if fault == "truncate_finding_document":
            payload = finding_bundle.model_dump_json().encode("utf-8")
            written = finding_fh.write(payload)
            if written != len(payload):
                raise OSError(f"finding bundle writer wrote {written} of {len(payload)} bytes")
            finding_fh.flush()
            return
        write_finding_bundle(finding_fh, finding_bundle)


def _admit_summary_payload[SummaryModelT: BaseModel](
    payload: str,
    *,
    role: SupervisorAdmissionRole,
    model: type[SummaryModelT],
    max_payload_bytes: int,
    limit_name: str,
) -> SummaryModelT:
    """Parse one child summary after a supervisor-side byte admission check."""
    payload_bytes = len(payload.encode("utf-8"))
    if payload_bytes > max_payload_bytes:
        raise SupervisorAdmissionError(
            role=role,
            reason="payload_too_large",
            payload_bytes=payload_bytes,
            limit_name=limit_name,
            limit_value=max_payload_bytes,
        )
    try:
        return model.model_validate_json(payload)
    except ValidationError as exc:
        raise SupervisorAdmissionError(role=role, reason="invalid_payload") from exc


def _admit_victim_summary(
    payload: str,
    *,
    expected_scenario: str,
    max_summary_bytes: int,
) -> VictimSummary:
    """Admit one victim summary and reject visible scenario drift."""
    if not isinstance(expected_scenario, str):
        raise TypeError(
            "_admit_victim_summary expected str expected_scenario, "
            f"got {type(expected_scenario).__name__}"
        )
    if not expected_scenario:
        raise ValueError("_admit_victim_summary requires non-empty expected_scenario")
    max_summary_bytes = _validate_max_victim_summary_bytes(max_summary_bytes)
    summary = _admit_summary_payload(
        payload,
        role="victim",
        model=VictimSummary,
        max_payload_bytes=max_summary_bytes,
        limit_name="max_victim_summary_bytes",
    )
    if summary.scenario != expected_scenario:
        raise SupervisorAdmissionError(
            role="victim",
            reason="scenario_mismatch",
            expected_scenario=expected_scenario,
            reported_scenario=summary.scenario,
        )
    return summary


def _admit_authority_summary(
    payload: str,
    *,
    max_summary_bytes: int,
) -> AuthoritySummary:
    """Admit one authority summary after a supervisor-side byte check."""
    max_summary_bytes = _validate_max_authority_summary_bytes(max_summary_bytes)
    return _admit_summary_payload(
        payload,
        role="authority",
        model=AuthoritySummary,
        max_payload_bytes=max_summary_bytes,
        limit_name="max_authority_summary_bytes",
    )


def _admit_detector_report(
    payload: str,
    *,
    profile: DetectorProfile,
    input_id: str,
    expected_run_id: str,
    max_report_bytes: int,
) -> DetectorReport:
    """Parse one detector report and fail closed on visible output-scope drift.

    ``max_report_bytes`` bounds only the payload admitted to JSON parsing. The
    supervisor already holds ``payload`` because ``subprocess.communicate()``
    collected it before this helper runs.
    """
    max_report_bytes = _validate_max_detector_report_bytes(max_report_bytes)
    payload_bytes = payload.encode("utf-8")
    if len(payload_bytes) > max_report_bytes:
        return _supervisor_refusal_report(
            profile=profile,
            input_id=input_id,
            run_id=expected_run_id,
            refusal_reason=(
                "supervisor detector report parse admission refused output: "
                f"payload_bytes={len(payload_bytes)} exceeds "
                f"max_detector_report_bytes={max_report_bytes}"
            ),
        )

    try:
        report = DetectorReport.model_validate_json(payload)
    except ValidationError:
        return _supervisor_refusal_report(
            profile=profile,
            input_id=input_id,
            run_id=expected_run_id,
            refusal_reason=(
                "supervisor detector report parse admission refused output: "
                "invalid DetectorReport payload"
            ),
        )
    report = _clear_supervisor_finding_admission_refusal(report)
    if report.run_id != expected_run_id:
        return _supervisor_refuse_parsed_report(
            report,
            refusal_reason=(
                "supervisor detector report scope gate refused output: "
                f"expected_run_id={expected_run_id!r}, reported_run_id={report.run_id!r}"
            ),
        )
    if report.detector_input_id != input_id:
        return _supervisor_refuse_parsed_report(
            report,
            refusal_reason=(
                "supervisor detector report input ID gate refused output: "
                f"expected_input_id={input_id!r}, "
                f"reported_input_id={report.detector_input_id!r}"
            ),
        )
    return report


def _admit_finding_bundle(
    fh: BinaryIO,
    *,
    report: DetectorReport,
    expected_run_id: str,
    expected_input_id: str,
    max_bundle_bytes: int,
) -> tuple[DetectorReport, tuple[SecurityFinding, ...]]:
    """Read one finding bundle and fail closed on visible cross-channel drift."""
    max_bundle_bytes = _validate_max_finding_bundle_bytes(max_bundle_bytes)
    try:
        result = read_finding_bundle(fh, max_bundle_bytes=max_bundle_bytes)
    except FindingBundleInputTooLargeError as exc:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=f"supervisor finding bundle parse admission refused output: {exc}",
            ),
            (),
        )
    except UnsupportedFindingBundleVersionError as exc:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=f"supervisor finding bundle parse admission refused output: {exc}",
            ),
            (),
        )
    except ValueError:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=(
                    "supervisor finding bundle parse admission refused output: "
                    "invalid FindingBundle payload"
                ),
            ),
            (),
        )
    report = _with_finding_bundle_diagnostics(report, result, gate_passed=False)
    try:
        bundle = require_complete_finding_bundle(result)
    except FindingBundleIncompleteError as exc:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=f"supervisor finding bundle completeness gate refused output: {exc}",
            ),
            (),
        )
    report = _with_finding_bundle_diagnostics(report, result, gate_passed=True)
    if report.declared_finding_count != len(bundle.findings):
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=(
                    "supervisor finding bundle count gate refused output: "
                    f"declared_finding_count={report.declared_finding_count!r}, "
                    f"finding_count={len(bundle.findings)!r}"
                ),
                finding_admission_refusal="count_mismatch",
            ),
            (),
        )
    try:
        require_valid_finding_scope(
            validate_finding_scope(
                bundle.findings,
                expected_run_id=expected_run_id,
            )
        )
    except FindingScopeError as exc:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=f"supervisor finding scope gate refused output: {exc}",
                finding_admission_refusal="scope_drift",
            ),
            (),
        )
    if not report.scored and bundle.findings:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=(
                    "supervisor finding bundle coherence gate refused output: "
                    "refused detector report cannot carry findings"
                ),
                finding_admission_refusal="refused_report_rows",
            ),
            (),
        )
    try:
        require_valid_finding_id_uniqueness(
            validate_finding_id_uniqueness(bundle.findings)
        )
    except FindingIdUniquenessError as exc:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=f"supervisor finding ID uniqueness gate refused output: {exc}",
                finding_admission_refusal="duplicate_finding_id",
            ),
            (),
        )
    try:
        # Use the supervisor-selected ID, not the detector report's echoed value.
        require_valid_finding_required_evidence_ref(
            validate_finding_required_evidence_ref(
                bundle.findings,
                required_evidence_ref=expected_input_id,
            )
        )
    except FindingRequiredEvidenceRefError as exc:
        return (
            _supervisor_refuse_parsed_report(
                report,
                refusal_reason=(
                    "supervisor finding required evidence-ref gate refused output: "
                    f"{exc}"
                ),
                finding_admission_refusal="missing_required_evidence_ref",
            ),
            (),
        )
    return report, bundle.findings


def _with_finding_bundle_diagnostics(
    report: DetectorReport,
    result: FindingBundleReadResult,
    *,
    gate_passed: bool,
) -> DetectorReport:
    """Attach supervisor-visible finding bundle diagnostics to one parsed report."""
    return DetectorReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "finding_bundle_completeness_signals": finding_bundle_completeness_signals(result),
            "finding_bundle_completeness_gate_passed": gate_passed,
            "finding_admission_refusal": None,
        }
    )


def _clear_supervisor_finding_admission_refusal(report: DetectorReport) -> DetectorReport:
    """Clear child-supplied values for one supervisor-owned diagnostic field."""
    return DetectorReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "finding_admission_refusal": None,
        }
    )


def _supervisor_refuse_parsed_report(
    report: DetectorReport,
    *,
    refusal_reason: str,
    finding_admission_refusal: FindingAdmissionRefusal | None = None,
) -> DetectorReport:
    """Preserve parsed report diagnostics while marking its finding rows unaccepted."""
    return DetectorReport.model_validate(
        {
            **report.model_dump(mode="python"),
            "finding_admission_refusal": finding_admission_refusal,
            "scored": False,
            "refusal_reason": refusal_reason,
        }
    )


def _supervisor_refusal_report(
    *,
    profile: DetectorProfile,
    input_id: str,
    run_id: str,
    refusal_reason: str,
) -> DetectorReport:
    """Create one minimal refusal when detector stdout is not admitted to parsing."""
    return DetectorReport(
        victim_profile=profile.name,
        scorer_name=profile.scorer_name,
        detector_input_id=input_id,
        run_id=run_id,
        scored=False,
        refusal_reason=refusal_reason,
    )


def _inject_subprocess_output_fault(
    victim_stdout: str,
    authority_stdout: str,
    detector_stdout: str,
    *,
    fault: SubprocessOutputFault,
    scenario: str,
    profile: DetectorProfile,
    victim_returncode: int,
) -> tuple[str, str, str]:
    """Corrupt one child stdout payload for supervisor admission tests."""
    if fault == "none":
        return victim_stdout, authority_stdout, detector_stdout
    if fault == "malformed_detector_report":
        return victim_stdout, authority_stdout, "{"
    if fault in {"malformed_victim_summary", "stale_victim_scenario"}:
        if victim_returncode != 0:
            raise ValueError(f"{fault} requires a successful victim summary")
        if fault == "malformed_victim_summary":
            return "{", authority_stdout, detector_stdout
        scenario_field = f'"scenario":"{scenario}"'
        stale_scenario_field = f'"scenario":"{scenario}-stale"'
        if scenario_field not in victim_stdout:
            raise ValueError("stale_victim_scenario requires the expected serialized scenario")
        return (
            victim_stdout.replace(scenario_field, stale_scenario_field, 1),
            authority_stdout,
            detector_stdout,
        )
    if fault == "malformed_authority_summary":
        if not profile.uses_approval_authority:
            raise ValueError(f"{profile.name} profile does not emit an authority summary")
        return victim_stdout, "{", detector_stdout
    raise AssertionError(f"unhandled subprocess output fault: {fault}")


async def run_victim_with_authority_to_fd(
    scenario: str,
    effect_fd: int,
    approval_request_fd: int,
    approval_response_fd: int,
    *,
    run_id: str,
    collector_read_identity: tuple[int, int, int] | None = None,
    receipt_read_identity: tuple[int, int, int] | None = None,
    receipt_write_identity: tuple[int, int, int] | None = None,
    approval_request_read_identity: tuple[int, int, int] | None = None,
    approval_response_write_identity: tuple[int, int, int] | None = None,
    fault: VictimFault = "none",
    emit_guard_effect: bool = False,
) -> VictimSummary:
    """Run one victim that obtains any approval token through the authority pipe."""
    request, enforce_approval, defender_enabled = _scenario_config(scenario)
    request = replace(request, approval_token=None)
    fault = _validate_victim_fault(fault)
    response = _request_approval_token(
        approval_request_fd,
        approval_response_fd,
        request_id=request.request_id,
        principal=request.principal,
        resource=request.resource,
    )
    request = replace(request, approval_token=response.approval_token)
    backend = IdentityBackend(
        enforce_approval=enforce_approval,
        approved_tokens=approval_tokens_by_request_id(run_id=run_id),
    )
    agent = IdentityApprovalAgent(backend)
    self_reported_collector_read_endpoint_open = (
        _has_fd_identity(collector_read_identity) if collector_read_identity is not None else None
    )
    self_reported_receipt_read_endpoint_open = (
        _has_fd_identity(receipt_read_identity) if receipt_read_identity is not None else None
    )
    self_reported_receipt_write_endpoint_open = (
        _has_fd_identity(receipt_write_identity) if receipt_write_identity is not None else None
    )
    self_reported_approval_request_read_endpoint_open = (
        _has_fd_identity(approval_request_read_identity)
        if approval_request_read_identity is not None
        else None
    )
    self_reported_approval_response_write_endpoint_open = (
        _has_fd_identity(approval_response_write_identity)
        if approval_response_write_identity is not None
        else None
    )

    with ExitStack() as cleanup:
        cleanup.callback(os.close, effect_fd)
        sink = _FaultInjectingV2Sink(effect_fd, fault)
        cleanup.callback(install_effect_sink(agent.event_manager, sink))
        cleanup.callback(
            install_agent_call_effect_recorder(
                agent.event_manager,
                observe_identity_grant,
            )
        )
        if defender_enabled:
            cleanup.callback(install_identity_grant_defender(agent.event_manager))
        if emit_guard_effect:
            cleanup.callback(install_effect_recorder(agent.event_manager, framework_guard_observer))
        decision = await agent.handle_request(request)
        if emit_guard_effect:
            await agent.runtime.execute_code("eval('1 + 1')")
        _finish_victim_effect_stream(sink, effect_fd, fault)

    return VictimSummary(
        scenario=scenario,
        decision="allowed" if decision.granted else "denied",
        decision_source=decision.source,
        backend_event_count=len(backend.audit_log()),
        self_reported_collector_read_endpoint_open=self_reported_collector_read_endpoint_open,
        self_reported_receipt_read_endpoint_open=self_reported_receipt_read_endpoint_open,
        self_reported_receipt_write_endpoint_open=self_reported_receipt_write_endpoint_open,
        self_reported_approval_request_read_endpoint_open=(
            self_reported_approval_request_read_endpoint_open
        ),
        self_reported_approval_response_write_endpoint_open=(
            self_reported_approval_response_write_endpoint_open
        ),
    )


async def run_data_export_victim_to_fd(
    scenario: str,
    effect_fd: int,
    *,
    collector_read_identity: tuple[int, int, int] | None = None,
    receipt_read_identity: tuple[int, int, int] | None = None,
    receipt_write_identity: tuple[int, int, int] | None = None,
    approval_request_read_identity: tuple[int, int, int] | None = None,
    approval_response_write_identity: tuple[int, int, int] | None = None,
    fault: VictimFault = "none",
    emit_guard_effect: bool = False,
) -> VictimSummary:
    """Run one data-export victim with only an effect write descriptor."""
    request, enforce_allowlist = data_export_scenario_config(scenario)
    fault = _validate_victim_fault(fault)
    backend = DataExportBackend(enforce_allowlist=enforce_allowlist)
    agent = DataExportAgent(backend)
    self_reported_collector_read_endpoint_open = (
        _has_fd_identity(collector_read_identity) if collector_read_identity is not None else None
    )
    self_reported_receipt_read_endpoint_open = (
        _has_fd_identity(receipt_read_identity) if receipt_read_identity is not None else None
    )
    self_reported_receipt_write_endpoint_open = (
        _has_fd_identity(receipt_write_identity) if receipt_write_identity is not None else None
    )
    self_reported_approval_request_read_endpoint_open = (
        _has_fd_identity(approval_request_read_identity)
        if approval_request_read_identity is not None
        else None
    )
    self_reported_approval_response_write_endpoint_open = (
        _has_fd_identity(approval_response_write_identity)
        if approval_response_write_identity is not None
        else None
    )

    with ExitStack() as cleanup:
        cleanup.callback(os.close, effect_fd)
        sink = _FaultInjectingV2Sink(effect_fd, fault)
        cleanup.callback(install_effect_sink(agent.event_manager, sink))
        cleanup.callback(
            install_agent_call_effect_recorder(
                agent.event_manager,
                observe_data_export,
            )
        )
        if emit_guard_effect:
            cleanup.callback(install_effect_recorder(agent.event_manager, framework_guard_observer))
        decision = await agent.handle_request(request)
        if emit_guard_effect:
            await agent.runtime.execute_code("eval('1 + 1')")
        _finish_victim_effect_stream(sink, effect_fd, fault)

    return VictimSummary(
        scenario=scenario,
        decision="allowed" if decision.exported else "denied",
        decision_source=decision.source,
        backend_event_count=len(backend.audit_log()),
        self_reported_collector_read_endpoint_open=self_reported_collector_read_endpoint_open,
        self_reported_receipt_read_endpoint_open=self_reported_receipt_read_endpoint_open,
        self_reported_receipt_write_endpoint_open=self_reported_receipt_write_endpoint_open,
        self_reported_approval_request_read_endpoint_open=(
            self_reported_approval_request_read_endpoint_open
        ),
        self_reported_approval_response_write_endpoint_open=(
            self_reported_approval_response_write_endpoint_open
        ),
    )


def run_detected_scenario(
    scenario: str = "vulnerable_attack",
    *,
    victim_fault: VictimFault = "none",
    authority_fault: AuthorityFault = "none",
    detector_fault: DetectorFault = "none",
    subprocess_output_fault: SubprocessOutputFault = "none",
    emit_guard_effect: bool = False,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    max_finding_bundle_bytes: int = DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    max_authority_document_bytes: int = DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
    max_detector_report_bytes: int = DEFAULT_DETECTOR_REPORT_MAX_BYTES,
    max_victim_summary_bytes: int = DEFAULT_VICTIM_SUMMARY_MAX_BYTES,
    max_authority_summary_bytes: int = DEFAULT_AUTHORITY_SUMMARY_MAX_BYTES,
    timeout: float = 10.0,
) -> DetectedScenario:
    """Run one configured victim profile and detector over supervisor-owned channels."""
    profile = _profile_for_scenario(scenario)
    victim_fault = _validate_victim_fault(victim_fault)
    authority_fault = _validate_authority_fault(authority_fault)
    detector_fault = _validate_detector_fault(detector_fault)
    subprocess_output_fault = _validate_subprocess_output_fault(subprocess_output_fault)
    max_receipt_bytes = _validate_max_receipt_bytes(max_receipt_bytes)
    max_finding_bundle_bytes = _validate_max_finding_bundle_bytes(max_finding_bundle_bytes)
    max_authority_document_bytes = _validate_max_authority_document_bytes(
        max_authority_document_bytes
    )
    max_detector_report_bytes = _validate_max_detector_report_bytes(
        max_detector_report_bytes
    )
    max_victim_summary_bytes = _validate_max_victim_summary_bytes(max_victim_summary_bytes)
    max_authority_summary_bytes = _validate_max_authority_summary_bytes(
        max_authority_summary_bytes
    )
    if not profile.uses_approval_authority and authority_fault != "none":
        raise ValueError(f"{profile.name} profile does not use an approval authority")
    if (
        not profile.uses_approval_authority
        and subprocess_output_fault == "malformed_authority_summary"
    ):
        raise ValueError(f"{profile.name} profile does not emit an authority summary")

    run_id = f"{profile.run_id_prefix}/{scenario}"
    input_id = f"detector-input-{scenario}"
    finding_file: BinaryIO | None = None
    open_fds: list[int] = []
    receipt_read_fd: int | None = None
    receipt_write_fd: int | None = None
    approval_request_read_fd: int | None = None
    approval_request_write_fd: int | None = None
    approval_response_read_fd: int | None = None
    approval_response_write_fd: int | None = None
    receipt_read_identity: tuple[int, int, int] | None = None
    receipt_write_identity: tuple[int, int, int] | None = None
    approval_request_read_identity: tuple[int, int, int] | None = None
    approval_response_write_identity: tuple[int, int, int] | None = None
    try:
        finding_file = TemporaryFile()
        effect_read_fd, effect_write_fd = os.pipe()
        open_fds.extend([effect_read_fd, effect_write_fd])
        effect_read_identity = _fd_identity(effect_read_fd)
        if profile.uses_approval_authority:
            receipt_read_fd, receipt_write_fd = os.pipe()
            open_fds.extend([receipt_read_fd, receipt_write_fd])
            approval_request_read_fd, approval_request_write_fd = os.pipe()
            open_fds.extend([approval_request_read_fd, approval_request_write_fd])
            approval_response_read_fd, approval_response_write_fd = os.pipe()
            open_fds.extend([approval_response_read_fd, approval_response_write_fd])
            receipt_read_identity = _fd_identity(receipt_read_fd)
            receipt_write_identity = _fd_identity(receipt_write_fd)
            approval_request_read_identity = _fd_identity(approval_request_read_fd)
            approval_response_write_identity = _fd_identity(approval_response_write_fd)
    except BaseException:
        for fd in open_fds:
            os.close(fd)
        if finding_file is not None:
            finding_file.close()
        raise
    assert finding_file is not None
    detector: subprocess.Popen[str] | None = None
    authority: subprocess.Popen[str] | None = None
    victim: subprocess.Popen[str] | None = None
    try:
        detector = _spawn_detector_subprocess(
            effect_fd=effect_read_fd,
            receipt_fd=receipt_read_fd,
            finding_fd=finding_file.fileno(),
            profile_name=profile.name,
            run_id=run_id,
            input_id=input_id,
            max_receipt_bytes=max_receipt_bytes,
            fault=detector_fault,
        )
        victim_args = [
            "victim",
            "--profile",
            profile.name,
            "--effect-fd",
            str(effect_write_fd),
            "--scenario",
            scenario,
            "--run-id",
            run_id,
            "--collector-read-device",
            str(effect_read_identity[0]),
            "--collector-read-inode",
            str(effect_read_identity[1]),
            "--collector-read-access-mode",
            str(effect_read_identity[2]),
            "--fault",
            victim_fault,
        ]
        victim_pass_fds = [effect_write_fd]
        if profile.uses_approval_authority:
            if (
                receipt_read_fd is None
                or receipt_write_fd is None
                or approval_request_read_fd is None
                or approval_request_write_fd is None
                or approval_response_read_fd is None
                or approval_response_write_fd is None
                or receipt_read_identity is None
                or receipt_write_identity is None
                or approval_request_read_identity is None
                or approval_response_write_identity is None
            ):
                raise RuntimeError("approval authority profile is missing pipe state")
            authority = _spawn_authority_subprocess(
                request_fd=approval_request_read_fd,
                response_fd=approval_response_write_fd,
                receipt_fd=receipt_write_fd,
                run_id=run_id,
                fault=authority_fault,
                max_document_bytes=max_authority_document_bytes,
            )
            victim_args.extend(
                [
                    "--approval-request-fd",
                    str(approval_request_write_fd),
                    "--approval-response-fd",
                    str(approval_response_read_fd),
                    "--receipt-read-device",
                    str(receipt_read_identity[0]),
                    "--receipt-read-inode",
                    str(receipt_read_identity[1]),
                    "--receipt-read-access-mode",
                    str(receipt_read_identity[2]),
                    "--receipt-write-device",
                    str(receipt_write_identity[0]),
                    "--receipt-write-inode",
                    str(receipt_write_identity[1]),
                    "--receipt-write-access-mode",
                    str(receipt_write_identity[2]),
                    "--approval-request-read-device",
                    str(approval_request_read_identity[0]),
                    "--approval-request-read-inode",
                    str(approval_request_read_identity[1]),
                    "--approval-request-read-access-mode",
                    str(approval_request_read_identity[2]),
                    "--approval-response-write-device",
                    str(approval_response_write_identity[0]),
                    "--approval-response-write-inode",
                    str(approval_response_write_identity[1]),
                    "--approval-response-write-access-mode",
                    str(approval_response_write_identity[2]),
                ]
            )
            victim_pass_fds.extend([approval_request_write_fd, approval_response_read_fd])
        if emit_guard_effect:
            victim_args.append("--emit-guard-effect")
        victim = _spawn_harness_subprocess(
            *victim_args,
            pass_fds=tuple(victim_pass_fds),
        )
    except BaseException:
        _terminate_process(victim)
        _terminate_process(authority)
        _terminate_process(detector)
        finding_file.close()
        raise
    finally:
        for fd in open_fds:
            os.close(fd)

    try:
        victim_stdout, victim_stderr = victim.communicate(timeout=timeout)
        if authority is not None:
            authority_stdout, authority_stderr = authority.communicate(timeout=timeout)
        else:
            authority_stdout = ""
            authority_stderr = ""
        detector_stdout, detector_stderr = detector.communicate(timeout=timeout)
    except BaseException:
        _terminate_process(victim)
        _terminate_process(authority)
        _terminate_process(detector)
        finding_file.close()
        raise

    try:
        if authority is not None and authority.returncode != 0:
            raise RuntimeError(
                _subprocess_failure_message("authority", authority.returncode, authority_stderr)
            )
        if detector.returncode != 0:
            raise RuntimeError(
                _subprocess_failure_message("detector", detector.returncode, detector_stderr)
            )

        victim_stdout, authority_stdout, detector_stdout = _inject_subprocess_output_fault(
            victim_stdout,
            authority_stdout,
            detector_stdout,
            fault=subprocess_output_fault,
            scenario=scenario,
            profile=profile,
            victim_returncode=victim.returncode,
        )
        victim_summary = (
            _admit_victim_summary(
                victim_stdout,
                expected_scenario=scenario,
                max_summary_bytes=max_victim_summary_bytes,
            )
            if victim.returncode == 0
            else None
        )
        authority_summary = (
            _admit_authority_summary(
                authority_stdout,
                max_summary_bytes=max_authority_summary_bytes,
            )
            if authority is not None
            else None
        )
        detector_report = _admit_detector_report(
            detector_stdout,
            profile=profile,
            input_id=input_id,
            expected_run_id=run_id,
            max_report_bytes=max_detector_report_bytes,
        )
        findings: tuple[SecurityFinding, ...] = ()
        if detector_report.declared_finding_count is not None:
            finding_file.seek(0)
            detector_report, findings = _admit_finding_bundle(
                finding_file,
                report=detector_report,
                expected_run_id=run_id,
                expected_input_id=input_id,
                max_bundle_bytes=max_finding_bundle_bytes,
            )
        return DetectedScenario(
            victim_profile=profile.name,
            victim=victim_summary,
            authority=authority_summary,
            detector=detector_report,
            findings=findings,
            victim_returncode=victim.returncode,
            authority_returncode=authority.returncode if authority is not None else None,
            detector_returncode=detector.returncode,
        )
    finally:
        finding_file.close()


def format_result(result: DetectedScenario) -> str:
    """Render one compact detector scenario table for the terminal."""
    rows = [
        (
            "profile",
            "scorer",
            "victim_returncode",
            "authority_returncode",
            "detector_returncode",
            "authority_issued_tokens",
            "declared_receipts",
            "scored",
            "findings",
            "refusal",
        ),
        (
            result.victim_profile,
            result.detector.scorer_name,
            str(result.victim_returncode),
            str(result.authority_returncode) if result.authority_returncode is not None else "n/a",
            str(result.detector_returncode),
            (
                str(result.authority.issued_token_count)
                if result.authority is not None
                else "n/a"
            ),
            (
                str(result.detector.declared_receipt_count)
                if result.detector.declared_receipt_count is not None
                else "n/a"
            ),
            str(result.detector.scored),
            str(len(result.findings)),
            result.detector.refusal_reason or "",
        ),
    ]
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    return "\n".join(
        " | ".join(cell.ljust(widths[column]) for column, cell in enumerate(row))
        for row in rows
    )


def _request_approval_token(
    request_fd: int,
    response_fd: int,
    *,
    request_id: str,
    principal: str,
    resource: str,
) -> ApprovalResponseDocument:
    """Write one request document and read one bounded authority response."""
    request = ApprovalRequestDocument(
        request_id=request_id,
        principal=principal,
        resource=resource,
    )
    with ExitStack() as cleanup:
        request_fh = cleanup.enter_context(os.fdopen(request_fd, "wb", closefd=True))
        response_fh = cleanup.enter_context(os.fdopen(response_fd, "rb", closefd=True))
        payload = request.model_dump_json().encode("utf-8")
        written = request_fh.write(payload)
        if written != len(payload):
            raise OSError(f"victim wrote {written} of {len(payload)} approval request bytes")
        request_fh.flush()
        request_fh.close()
        response = read_approval_response_document(response_fh)
    if response.request_id != request_id:
        raise ValueError("authority response request_id does not match request")
    return response


def _spawn_detector_subprocess(
    *,
    effect_fd: int,
    receipt_fd: int | None,
    finding_fd: int,
    profile_name: str,
    run_id: str,
    input_id: str,
    max_receipt_bytes: int,
    fault: DetectorFault,
) -> subprocess.Popen[str]:
    """Launch this module in detector mode with explicit inherited descriptors."""
    args = [
        "detector",
        "--effect-fd",
        str(effect_fd),
        "--finding-fd",
        str(finding_fd),
        "--profile",
        profile_name,
        "--run-id",
        run_id,
        "--input-id",
        input_id,
        "--max-receipt-bytes",
        str(max_receipt_bytes),
        "--fault",
        fault,
    ]
    pass_fds = [effect_fd, finding_fd]
    if receipt_fd is not None:
        args.extend(["--receipt-fd", str(receipt_fd)])
        pass_fds.append(receipt_fd)
    return _spawn_harness_subprocess(
        *args,
        pass_fds=tuple(pass_fds),
    )


def _spawn_authority_subprocess(
    *,
    request_fd: int,
    response_fd: int,
    receipt_fd: int,
    run_id: str,
    fault: AuthorityFault,
    max_document_bytes: int,
) -> subprocess.Popen[str]:
    """Launch the approval authority with only its request, response, and receipt ends."""
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "examples.security_hardening.approval_authority",
            "--request-fd",
            str(request_fd),
            "--response-fd",
            str(response_fd),
            "--receipt-fd",
            str(receipt_fd),
            "--run-id",
            run_id,
            "--fault",
            fault,
            "--max-document-bytes",
            str(max_document_bytes),
        ],
        cwd=_REPO_ROOT,
        pass_fds=(request_fd, response_fd, receipt_fd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _spawn_harness_subprocess(
    *args: str,
    pass_fds: tuple[int, ...],
) -> subprocess.Popen[str]:
    """Launch this module with explicit inherited descriptors."""
    return subprocess.Popen(
        [sys.executable, "-m", "examples.security_hardening.detector_harness", *args],
        cwd=_REPO_ROOT,
        pass_fds=pass_fds,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _validate_authority_fault(fault: str) -> AuthorityFault:
    if fault in _AUTHORITY_FAULTS:
        return cast(AuthorityFault, fault)
    raise ValueError(f"unsupported authority fault: {fault}")


def _validate_detector_fault(fault: str) -> DetectorFault:
    if fault in _DETECTOR_FAULTS:
        return cast(DetectorFault, fault)
    raise ValueError(f"unsupported detector fault: {fault}")


def _validate_subprocess_output_fault(fault: str) -> SubprocessOutputFault:
    if fault in _SUBPROCESS_OUTPUT_FAULTS:
        return cast(SubprocessOutputFault, fault)
    raise ValueError(f"unsupported subprocess output fault: {fault}")


def _profile_from_name(profile_name: str) -> DetectorProfile:
    """Return one configured detector profile by stable example-local name."""
    try:
        return _DETECTOR_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unsupported detector profile: {profile_name}") from exc


def _profile_for_scenario(scenario: str) -> DetectorProfile:
    """Return the profile that owns one configured scenario name."""
    for profile in _DETECTOR_PROFILES.values():
        if scenario in profile.scenario_names:
            return profile
    raise ValueError(f"unknown detector harness scenario: {scenario}")


def _subprocess_failure_message(role: str, returncode: int, stderr: str) -> str:
    """Render one concise child-process failure line without an empty separator."""
    detail = stderr.strip()
    suffix = f": {detail}" if detail else ""
    return f"{role} subprocess failed with returncode={returncode}{suffix}"


def _validate_max_receipt_bytes(max_receipt_bytes: int) -> int:
    """Validate one positive strict integer receipt budget."""
    if not isinstance(max_receipt_bytes, int) or isinstance(max_receipt_bytes, bool):
        raise TypeError(
            "detector harness expected int max_receipt_bytes, "
            f"got {type(max_receipt_bytes).__name__}"
        )
    if max_receipt_bytes <= 0:
        raise ValueError("detector harness requires max_receipt_bytes > 0")
    return max_receipt_bytes


def _validate_max_finding_bundle_bytes(max_bundle_bytes: int) -> int:
    """Validate one positive strict integer finding-bundle budget."""
    if not isinstance(max_bundle_bytes, int) or isinstance(max_bundle_bytes, bool):
        raise TypeError(
            "detector harness expected int max_finding_bundle_bytes, "
            f"got {type(max_bundle_bytes).__name__}"
        )
    if max_bundle_bytes <= 0:
        raise ValueError("detector harness requires max_finding_bundle_bytes > 0")
    return max_bundle_bytes


def _validate_max_authority_document_bytes(max_document_bytes: int) -> int:
    """Validate one positive strict integer authority document budget."""
    if not isinstance(max_document_bytes, int) or isinstance(max_document_bytes, bool):
        raise TypeError(
            "detector harness expected int max_authority_document_bytes, "
            f"got {type(max_document_bytes).__name__}"
        )
    if max_document_bytes <= 0:
        raise ValueError("detector harness requires max_authority_document_bytes > 0")
    return max_document_bytes


def _validate_max_detector_report_bytes(max_report_bytes: int) -> int:
    """Validate one positive strict integer detector report parse budget."""
    if not isinstance(max_report_bytes, int) or isinstance(max_report_bytes, bool):
        raise TypeError(
            "detector harness expected int max_detector_report_bytes, "
            f"got {type(max_report_bytes).__name__}"
        )
    if max_report_bytes <= 0:
        raise ValueError("detector harness requires max_detector_report_bytes > 0")
    return max_report_bytes


def _validate_max_victim_summary_bytes(max_summary_bytes: int) -> int:
    """Validate one positive strict integer victim summary parse budget."""
    if not isinstance(max_summary_bytes, int) or isinstance(max_summary_bytes, bool):
        raise TypeError(
            "detector harness expected int max_victim_summary_bytes, "
            f"got {type(max_summary_bytes).__name__}"
        )
    if max_summary_bytes <= 0:
        raise ValueError("detector harness requires max_victim_summary_bytes > 0")
    return max_summary_bytes


def _validate_max_authority_summary_bytes(max_summary_bytes: int) -> int:
    """Validate one positive strict integer authority summary parse budget."""
    if not isinstance(max_summary_bytes, int) or isinstance(max_summary_bytes, bool):
        raise TypeError(
            "detector harness expected int max_authority_summary_bytes, "
            f"got {type(max_summary_bytes).__name__}"
        )
    if max_summary_bytes <= 0:
        raise ValueError("detector harness requires max_authority_summary_bytes > 0")
    return max_summary_bytes


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    detector_parser = subparsers.add_parser(
        "detector",
        help="Assemble and score one detector input from inherited descriptors.",
    )
    detector_parser.add_argument("--effect-fd", type=int, required=True)
    detector_parser.add_argument("--receipt-fd", type=int)
    detector_parser.add_argument("--finding-fd", type=int, required=True)
    detector_parser.add_argument(
        "--profile",
        choices=tuple(_DETECTOR_PROFILES),
        default=_IDENTITY_PROFILE.name,
    )
    detector_parser.add_argument("--run-id", required=True)
    detector_parser.add_argument("--input-id", required=True)
    detector_parser.add_argument(
        "--max-receipt-bytes",
        type=int,
        default=DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    )
    detector_parser.add_argument(
        "--fault",
        choices=_DETECTOR_FAULTS,
        default="none",
    )

    victim_parser = subparsers.add_parser(
        "victim",
        help="Run one configured victim profile with inherited descriptors.",
    )
    victim_parser.add_argument("--effect-fd", type=int, required=True)
    victim_parser.add_argument(
        "--profile",
        choices=tuple(_DETECTOR_PROFILES),
        default=_IDENTITY_PROFILE.name,
    )
    victim_parser.add_argument("--approval-request-fd", type=int)
    victim_parser.add_argument("--approval-response-fd", type=int)
    victim_parser.add_argument("--scenario", required=True)
    victim_parser.add_argument("--run-id", required=True)
    victim_parser.add_argument("--collector-read-device", type=int)
    victim_parser.add_argument("--collector-read-inode", type=int)
    victim_parser.add_argument("--collector-read-access-mode", type=int)
    victim_parser.add_argument("--receipt-read-device", type=int)
    victim_parser.add_argument("--receipt-read-inode", type=int)
    victim_parser.add_argument("--receipt-read-access-mode", type=int)
    victim_parser.add_argument("--receipt-write-device", type=int)
    victim_parser.add_argument("--receipt-write-inode", type=int)
    victim_parser.add_argument("--receipt-write-access-mode", type=int)
    victim_parser.add_argument("--approval-request-read-device", type=int)
    victim_parser.add_argument("--approval-request-read-inode", type=int)
    victim_parser.add_argument("--approval-request-read-access-mode", type=int)
    victim_parser.add_argument("--approval-response-write-device", type=int)
    victim_parser.add_argument("--approval-response-write-inode", type=int)
    victim_parser.add_argument("--approval-response-write-access-mode", type=int)
    victim_parser.add_argument(
        "--fault",
        choices=_VICTIM_FAULTS,
        default="none",
    )
    victim_parser.add_argument("--emit-guard-effect", action="store_true")

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run the supervisor/victim/authority/detector demo.",
    )
    demo_parser.add_argument("--scenario", default="vulnerable_attack")
    demo_parser.add_argument(
        "--victim-fault",
        choices=_VICTIM_FAULTS,
        default="none",
    )
    demo_parser.add_argument(
        "--authority-fault",
        choices=_AUTHORITY_FAULTS,
        default="none",
    )
    demo_parser.add_argument(
        "--detector-fault",
        choices=_DETECTOR_FAULTS,
        default="none",
    )
    demo_parser.add_argument(
        "--subprocess-output-fault",
        choices=_SUBPROCESS_OUTPUT_FAULTS,
        default="none",
    )
    demo_parser.add_argument("--emit-guard-effect", action="store_true")
    demo_parser.add_argument(
        "--max-receipt-bytes",
        type=int,
        default=DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    )
    demo_parser.add_argument(
        "--max-finding-bundle-bytes",
        type=int,
        default=DEFAULT_DETECTOR_FINDING_BUNDLE_MAX_BYTES,
    )
    demo_parser.add_argument(
        "--max-authority-document-bytes",
        type=int,
        default=DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
    )
    demo_parser.add_argument(
        "--max-detector-report-bytes",
        type=int,
        default=DEFAULT_DETECTOR_REPORT_MAX_BYTES,
    )
    demo_parser.add_argument(
        "--max-victim-summary-bytes",
        type=int,
        default=DEFAULT_VICTIM_SUMMARY_MAX_BYTES,
    )
    demo_parser.add_argument(
        "--max-authority-summary-bytes",
        type=int,
        default=DEFAULT_AUTHORITY_SUMMARY_MAX_BYTES,
    )
    demo_parser.add_argument("--timeout", type=float, default=10.0)

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one detector or victim role, or the combined detector demo."""
    args = _parse_args(argv)
    if args.command == "detector":
        print(
            score_fd(
                args.effect_fd,
                args.receipt_fd,
                args.finding_fd,
                profile_name=args.profile,
                run_id=args.run_id,
                input_id=args.input_id,
                max_receipt_bytes=args.max_receipt_bytes,
                fault=cast(DetectorFault, args.fault),
            ).model_dump_json()
        )
        return 0
    if args.command == "victim":
        profile = _profile_from_name(args.profile)
        if profile.uses_approval_authority:
            if args.approval_request_fd is None or args.approval_response_fd is None:
                raise ValueError(
                    "identity_approval victim requires approval request and response descriptors"
                )
            summary = asyncio.run(
                run_victim_with_authority_to_fd(
                    args.scenario,
                    args.effect_fd,
                    args.approval_request_fd,
                    args.approval_response_fd,
                    run_id=args.run_id,
                    collector_read_identity=_collector_read_identity_from_args(args),
                    receipt_read_identity=_receipt_read_identity_from_args(args),
                    receipt_write_identity=_receipt_write_identity_from_args(args),
                    approval_request_read_identity=_approval_request_read_identity_from_args(args),
                    approval_response_write_identity=_approval_response_write_identity_from_args(
                        args
                    ),
                    fault=cast(VictimFault, args.fault),
                    emit_guard_effect=args.emit_guard_effect,
                )
            )
        else:
            summary = asyncio.run(
                run_data_export_victim_to_fd(
                    args.scenario,
                    args.effect_fd,
                    collector_read_identity=_collector_read_identity_from_args(args),
                    receipt_read_identity=_receipt_read_identity_from_args(args),
                    receipt_write_identity=_receipt_write_identity_from_args(args),
                    approval_request_read_identity=_approval_request_read_identity_from_args(args),
                    approval_response_write_identity=_approval_response_write_identity_from_args(
                        args
                    ),
                    fault=cast(VictimFault, args.fault),
                    emit_guard_effect=args.emit_guard_effect,
                )
            )
        print(
            summary.model_dump_json()
        )
        return 0

    try:
        result = run_detected_scenario(
            args.scenario,
            victim_fault=cast(VictimFault, args.victim_fault),
            authority_fault=cast(AuthorityFault, args.authority_fault),
            detector_fault=cast(DetectorFault, args.detector_fault),
            subprocess_output_fault=cast(SubprocessOutputFault, args.subprocess_output_fault),
            emit_guard_effect=args.emit_guard_effect,
            max_receipt_bytes=args.max_receipt_bytes,
            max_finding_bundle_bytes=args.max_finding_bundle_bytes,
            max_authority_document_bytes=args.max_authority_document_bytes,
            max_detector_report_bytes=args.max_detector_report_bytes,
            max_victim_summary_bytes=args.max_victim_summary_bytes,
            max_authority_summary_bytes=args.max_authority_summary_bytes,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(format_result(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
