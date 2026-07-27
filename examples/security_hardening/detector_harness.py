# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Out-of-process detector harness for two security-hardening victim profiles.

This example keeps process lifecycle outside ``src/nooa``. Every profile gives
the victim only an effect write end and gives the detector only the effect read
end. The identity-approval profile also wires a separate approval authority and
receipt pipe; the data-export profile leaves those unwired and scores a
receipt-free destination policy. Both profiles construct one
:class:`~nooa.security.DetectorInput` inside the same detector code path before
running their application-local scorer.

The split shows where a separately controlled detector and optional approval
issuer can run. It does not authenticate pipe contents, make same-user
subprocesses a trust boundary, provide sandboxing or attestation, prove that an
issued token was honored, or turn detector findings into enforcement.

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
from typing import BinaryIO, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from examples.security_hardening.approval_authority import (
    DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
    ApprovalRequestDocument,
    ApprovalResponseDocument,
    AuthorityFault,
    AuthorityReceiptDocument,
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
    VictimFault,
    VictimSummary,
    _approval_request_read_identity_from_args,
    _approval_response_write_identity_from_args,
    _collector_read_identity_from_args,
    _fd_identity,
    _has_fd_identity,
    _receipt_read_identity_from_args,
    _receipt_write_identity_from_args,
    _scenario_config,
    _terminate_process,
    _validate_victim_fault,
    _write_all,
)
from examples.security_hardening.identity_approval import (
    IdentityApprovalAgent,
    IdentityBackend,
    detect_grants_without_approval,
    install_identity_grant_defender,
    observe_identity_grant,
)
from nooa.security import (
    EFFECT_EGRESS_COMPLETENESS_SIGNALS,
    DetectorInput,
    EffectEgressCompletenessSignal,
    FdEffectSink,
    ReceiptCoverage,
    SecurityFinding,
    detector_input_from_egress,
    framework_guard_observer,
    install_agent_call_effect_recorder,
    install_effect_recorder,
    install_effect_sink,
    read_effect_egress,
)

_DETECTOR_REPORT_SCHEMA_VERSION: Literal["nooa-detector-harness-example-v3"] = (
    "nooa-detector-harness-example-v3"
)
_DETECTED_SCENARIO_SCHEMA_VERSION: Literal["nooa-detector-scenario-example-v3"] = (
    "nooa-detector-scenario-example-v3"
)
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DETECTOR_RECEIPT_MAX_BYTES = 1024 * 1024
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


class DetectorReceiptInputTooLargeError(ValueError):
    """Raised when the detector refuses an over-bound receipt document."""

    def __init__(self, max_receipt_bytes: int) -> None:
        self.max_receipt_bytes = max_receipt_bytes
        super().__init__(f"detector receipt input exceeds max_receipt_bytes={max_receipt_bytes}")


class DetectorReport(BaseModel):
    """Example-local result emitted by the detector subprocess.

    ``scored=False`` means this example's policy declined to score the
    assembled bundle. It is not a vulnerability verdict and does not imply the
    input was malicious.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-harness-example-v3"] = (
        _DETECTOR_REPORT_SCHEMA_VERSION
    )
    victim_profile: str = Field(min_length=1)
    scorer_name: str = Field(min_length=1)
    detector_input_id: str = Field(min_length=1)
    run_id: str = ""
    effect_egress_completeness_signals: tuple[EffectEgressCompletenessSignal, ...] = ()
    effect_egress_completeness_gate_passed: bool = False
    receipt_source: str = ""
    receipt_coverage: ReceiptCoverage = "unknown"
    receipt_count: int = Field(default=0, ge=0)
    issued_token_count: int | None = Field(default=None, ge=0)
    scored: bool
    refusal_reason: str | None = None
    findings: tuple[SecurityFinding, ...] = ()

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
        if self.issued_token_count is not None and self.issued_token_count != self.receipt_count:
            raise ValueError("issued_token_count must match receipt_count")
        if self.scored and self.refusal_reason is not None:
            raise ValueError("scored detector report cannot carry refusal_reason")
        if not self.scored:
            if self.findings:
                raise ValueError("refused detector report cannot carry findings")
            if self.refusal_reason is None:
                raise ValueError("refused detector report requires refusal_reason")
        return self


class DetectedScenario(BaseModel):
    """Supervisor-side join of victim, authority, and detector outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-scenario-example-v3"] = (
        _DETECTED_SCENARIO_SCHEMA_VERSION
    )
    victim_profile: str = Field(min_length=1)
    victim: VictimSummary | None = None
    authority: AuthoritySummary | None = None
    detector: DetectorReport
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
        return self


def read_receipt_document(
    fh: BinaryIO,
    *,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
) -> AuthorityReceiptDocument:
    """Read exactly one bounded authority receipt document from a binary stream."""
    max_receipt_bytes = _validate_max_receipt_bytes(max_receipt_bytes)
    payload = fh.read(max_receipt_bytes + 1)
    if not isinstance(payload, bytes):
        raise TypeError(f"read_receipt_document expected bytes, got {type(payload).__name__}")
    if len(payload) > max_receipt_bytes:
        raise DetectorReceiptInputTooLargeError(max_receipt_bytes)
    return AuthorityReceiptDocument.model_validate_json(payload)


def score_detector_input(
    detector_input: DetectorInput,
    *,
    victim_profile: str = _IDENTITY_PROFILE.name,
    scorer_name: str = _IDENTITY_PROFILE.scorer_name,
    scorer: DetectorScorer = detect_grants_without_approval,
    receipt_count: int | None = None,
    issued_token_count: int | None = None,
) -> DetectorReport:
    """Run the example-local deterministic scorer over one detector input."""
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
        "receipt_source": detector_input.receipt_source,
        "receipt_coverage": detector_input.receipt_coverage,
        "receipt_count": receipt_count,
        "issued_token_count": issued_token_count,
    }
    try:
        findings = scorer(detector_input)
    except UnscoreableDetectorInputError as exc:
        return DetectorReport(
            **report_fields,
            scored=False,
            refusal_reason=str(exc),
        )
    return DetectorReport(
        **report_fields,
        scored=True,
        findings=findings,
    )


def score_fd(
    effect_fd: int,
    receipt_fd: int | None,
    *,
    profile_name: str = _IDENTITY_PROFILE.name,
    run_id: str,
    input_id: str,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
) -> DetectorReport:
    """Assemble one detector input from effect and receipt descriptors, then score it."""
    profile = _profile_from_name(profile_name)
    receipts = ()
    receipt_source = ""
    receipt_coverage: ReceiptCoverage = "unknown"
    issued_token_count: int | None = None
    if receipt_fd is not None:
        with os.fdopen(receipt_fd, "rb", closefd=True) as receipt_fh:
            receipt_document = read_receipt_document(
                receipt_fh,
                max_receipt_bytes=max_receipt_bytes,
            )
        receipts = receipt_document.receipts
        receipt_source = receipt_document.receipt_source
        receipt_coverage = receipt_document.receipt_coverage
        issued_token_count = receipt_document.issued_token_count
    with os.fdopen(effect_fd, "rb", closefd=True) as effect_fh:
        egress = read_effect_egress(effect_fh)
    detector_input = detector_input_from_egress(
        egress,
        input_id=input_id,
        run_id=run_id,
        receipts=receipts,
        receipt_source=receipt_source,
        receipt_coverage=receipt_coverage,
        require_complete=False,
    )
    return score_detector_input(
        detector_input,
        victim_profile=profile.name,
        scorer_name=profile.scorer_name,
        scorer=profile.scorer,
        receipt_count=len(receipts),
        issued_token_count=issued_token_count,
    )


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
        cleanup.callback(install_effect_sink(agent.event_manager, FdEffectSink(effect_fd)))
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
        if fault == "partial_tail_crash":
            _write_all(effect_fd, b'{"schema_version":"nooa-effect-egress-v1"')
            raise SystemExit(3)

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
        cleanup.callback(install_effect_sink(agent.event_manager, FdEffectSink(effect_fd)))
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
        if fault == "partial_tail_crash":
            _write_all(effect_fd, b'{"schema_version":"nooa-effect-egress-v1"')
            raise SystemExit(3)

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
    emit_guard_effect: bool = False,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    max_authority_document_bytes: int = DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
    timeout: float = 10.0,
) -> DetectedScenario:
    """Run one configured victim profile and detector over supervisor-owned pipes."""
    profile = _profile_for_scenario(scenario)
    victim_fault = _validate_victim_fault(victim_fault)
    authority_fault = _validate_authority_fault(authority_fault)
    max_receipt_bytes = _validate_max_receipt_bytes(max_receipt_bytes)
    max_authority_document_bytes = _validate_max_authority_document_bytes(
        max_authority_document_bytes
    )
    if not profile.uses_approval_authority and authority_fault != "none":
        raise ValueError(f"{profile.name} profile does not use an approval authority")

    run_id = f"{profile.run_id_prefix}/{scenario}"
    input_id = f"detector-input-{scenario}"
    effect_read_fd, effect_write_fd = os.pipe()
    open_fds = [effect_read_fd, effect_write_fd]
    effect_read_identity = _fd_identity(effect_read_fd)
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
    if profile.uses_approval_authority:
        receipt_read_fd, receipt_write_fd = os.pipe()
        approval_request_read_fd, approval_request_write_fd = os.pipe()
        approval_response_read_fd, approval_response_write_fd = os.pipe()
        open_fds.extend(
            [
                receipt_read_fd,
                receipt_write_fd,
                approval_request_read_fd,
                approval_request_write_fd,
                approval_response_read_fd,
                approval_response_write_fd,
            ]
        )
        receipt_read_identity = _fd_identity(receipt_read_fd)
        receipt_write_identity = _fd_identity(receipt_write_fd)
        approval_request_read_identity = _fd_identity(approval_request_read_fd)
        approval_response_write_identity = _fd_identity(approval_response_write_fd)
    detector: subprocess.Popen[str] | None = None
    authority: subprocess.Popen[str] | None = None
    victim: subprocess.Popen[str] | None = None
    try:
        detector = _spawn_detector_subprocess(
            effect_fd=effect_read_fd,
            receipt_fd=receipt_read_fd,
            profile_name=profile.name,
            run_id=run_id,
            input_id=input_id,
            max_receipt_bytes=max_receipt_bytes,
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
        raise

    if authority is not None and authority.returncode != 0:
        raise RuntimeError(
            _subprocess_failure_message("authority", authority.returncode, authority_stderr)
        )
    if detector.returncode != 0:
        raise RuntimeError(
            _subprocess_failure_message("detector", detector.returncode, detector_stderr)
        )

    victim_summary = (
        VictimSummary.model_validate_json(victim_stdout) if victim.returncode == 0 else None
    )
    authority_summary = (
        AuthoritySummary.model_validate_json(authority_stdout) if authority is not None else None
    )
    return DetectedScenario(
        victim_profile=profile.name,
        victim=victim_summary,
        authority=authority_summary,
        detector=DetectorReport.model_validate_json(detector_stdout),
        victim_returncode=victim.returncode,
        authority_returncode=authority.returncode if authority is not None else None,
        detector_returncode=detector.returncode,
    )


def format_result(result: DetectedScenario) -> str:
    """Render one compact detector scenario table for the terminal."""
    rows = [
        (
            "profile",
            "scorer",
            "victim_returncode",
            "authority_returncode",
            "detector_returncode",
            "issued_tokens",
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
                str(result.detector.issued_token_count)
                if result.detector.issued_token_count is not None
                else "n/a"
            ),
            str(result.detector.scored),
            str(len(result.detector.findings)),
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
    profile_name: str,
    run_id: str,
    input_id: str,
    max_receipt_bytes: int,
) -> subprocess.Popen[str]:
    """Launch this module in detector mode with explicit inherited descriptors."""
    args = [
        "detector",
        "--effect-fd",
        str(effect_fd),
        "--profile",
        profile_name,
        "--run-id",
        run_id,
        "--input-id",
        input_id,
        "--max-receipt-bytes",
        str(max_receipt_bytes),
    ]
    pass_fds = [effect_fd]
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
    if fault == "none" or fault == "exit_before_receipt":
        return fault
    raise ValueError(f"unsupported authority fault: {fault}")


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


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    detector_parser = subparsers.add_parser(
        "detector",
        help="Assemble and score one detector input from inherited descriptors.",
    )
    detector_parser.add_argument("--effect-fd", type=int, required=True)
    detector_parser.add_argument("--receipt-fd", type=int)
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
    victim_parser.add_argument("--fault", choices=("none", "partial_tail_crash"), default="none")
    victim_parser.add_argument("--emit-guard-effect", action="store_true")

    demo_parser = subparsers.add_parser(
        "demo",
        help="Run the supervisor/victim/authority/detector demo.",
    )
    demo_parser.add_argument("--scenario", default="vulnerable_attack")
    demo_parser.add_argument("--victim-fault", choices=("none", "partial_tail_crash"), default="none")
    demo_parser.add_argument("--authority-fault", choices=("none", "exit_before_receipt"), default="none")
    demo_parser.add_argument("--emit-guard-effect", action="store_true")
    demo_parser.add_argument(
        "--max-receipt-bytes",
        type=int,
        default=DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    )
    demo_parser.add_argument(
        "--max-authority-document-bytes",
        type=int,
        default=DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
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
                profile_name=args.profile,
                run_id=args.run_id,
                input_id=args.input_id,
                max_receipt_bytes=args.max_receipt_bytes,
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
            emit_guard_effect=args.emit_guard_effect,
            max_receipt_bytes=args.max_receipt_bytes,
            max_authority_document_bytes=args.max_authority_document_bytes,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(format_result(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
