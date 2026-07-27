# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Out-of-process detector harness for the identity hardening example.

This example keeps detector process lifecycle outside ``src/nooa``. A
supervisor creates one effect pipe and one receipt pipe, gives the victim only
the effect write end, gives the detector only the effect read end plus the
receipt read end, and lets the detector construct one
:class:`~nooa.security.DetectorInput` before running the example-local scorer.

The split shows where a separately controlled detector can run. It does not
authenticate effect frames, turn a supervisor-issued demo receipt into backend
truth, make same-user subprocesses a trust boundary, provide sandboxing or
attestation, or turn detector findings into enforcement.

    uv run python -m examples.security_hardening.detector_harness demo
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from examples.security_hardening.effect_collector import (
    VictimFault,
    VictimSummary,
    _fd_identity,
    _scenario_config,
    _terminate_process,
    _validate_victim_fault,
    _write_all,
)
from examples.security_hardening.effect_collector import (
    _spawn_subprocess as _spawn_effect_collector_subprocess,
)
from examples.security_hardening.identity_approval import (
    EFFECT_TYPE,
    RECEIPT_TYPE,
    UnscoreableDetectorInputError,
    detect_grants_without_approval,
)
from nooa.security import (
    EFFECT_EGRESS_COMPLETENESS_SIGNALS,
    DetectorInput,
    EffectEgressCompletenessSignal,
    ReceiptCoverage,
    SecurityFinding,
    SecurityReceipt,
    detector_input_from_egress,
    read_effect_egress,
)

_RECEIPT_DOCUMENT_SCHEMA_VERSION: Literal["nooa-detector-receipts-example-v1"] = (
    "nooa-detector-receipts-example-v1"
)
_DETECTOR_REPORT_SCHEMA_VERSION: Literal["nooa-detector-harness-example-v1"] = (
    "nooa-detector-harness-example-v1"
)
_DETECTED_SCENARIO_SCHEMA_VERSION: Literal["nooa-detector-scenario-example-v1"] = (
    "nooa-detector-scenario-example-v1"
)
_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DETECTOR_RECEIPT_MAX_BYTES = 1024 * 1024


class DetectorReceiptInputTooLargeError(ValueError):
    """Raised when the detector refuses an over-bound receipt document."""

    def __init__(self, max_receipt_bytes: int) -> None:
        self.max_receipt_bytes = max_receipt_bytes
        super().__init__(f"detector receipt input exceeds max_receipt_bytes={max_receipt_bytes}")


class DetectorReceiptDocument(BaseModel):
    """Example-local receipt bundle written by the supervisor.

    The document is a deterministic demo input, not a backend audit export.
    ``receipt_source`` and ``receipt_coverage`` remain supervisor assertions.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-receipts-example-v1"] = (
        _RECEIPT_DOCUMENT_SCHEMA_VERSION
    )
    receipt_source: str = Field(min_length=1)
    receipt_coverage: ReceiptCoverage
    receipts: tuple[SecurityReceipt, ...] = ()


class DetectorReport(BaseModel):
    """Example-local result emitted by the detector subprocess.

    ``scored=False`` means this example's policy declined to score the
    assembled bundle. It is not a vulnerability verdict and does not imply the
    input was malicious.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-harness-example-v1"] = (
        _DETECTOR_REPORT_SCHEMA_VERSION
    )
    detector_input_id: str = Field(min_length=1)
    run_id: str = ""
    effect_egress_completeness_signals: tuple[EffectEgressCompletenessSignal, ...] = ()
    effect_egress_completeness_gate_passed: bool = False
    receipt_source: str = ""
    receipt_coverage: ReceiptCoverage = "unknown"
    scored: bool
    refusal_reason: str | None = None
    findings: tuple[SecurityFinding, ...] = ()

    @model_validator(mode="after")
    def _validate_report(self) -> Self:
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
        if self.scored and self.refusal_reason is not None:
            raise ValueError("scored detector report cannot carry refusal_reason")
        if not self.scored:
            if self.findings:
                raise ValueError("refused detector report cannot carry findings")
            if self.refusal_reason is None:
                raise ValueError("refused detector report requires refusal_reason")
        return self


class DetectedScenario(BaseModel):
    """Supervisor-side join of victim status and detector output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-scenario-example-v1"] = (
        _DETECTED_SCENARIO_SCHEMA_VERSION
    )
    victim: VictimSummary | None = None
    detector: DetectorReport
    victim_returncode: int
    detector_returncode: int

    @model_validator(mode="after")
    def _validate_process_results(self) -> Self:
        if self.victim_returncode == 0 and self.victim is None:
            raise ValueError("successful victim subprocess must emit a victim summary")
        if self.detector_returncode != 0:
            raise ValueError("detected scenario requires a successful detector subprocess")
        return self


def read_receipt_document(
    fh: BinaryIO,
    *,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
) -> DetectorReceiptDocument:
    """Read exactly one bounded serialized receipt document from a binary stream."""
    max_receipt_bytes = _validate_max_receipt_bytes(max_receipt_bytes)
    payload = fh.read(max_receipt_bytes + 1)
    if not isinstance(payload, bytes):
        raise TypeError(f"read_receipt_document expected bytes, got {type(payload).__name__}")
    if len(payload) > max_receipt_bytes:
        raise DetectorReceiptInputTooLargeError(max_receipt_bytes)
    return DetectorReceiptDocument.model_validate_json(payload)


def score_detector_input(detector_input: DetectorInput) -> DetectorReport:
    """Run the example-local deterministic scorer over one detector input."""
    if not isinstance(detector_input, DetectorInput):
        raise TypeError(
            "score_detector_input expected DetectorInput, "
            f"got {type(detector_input).__name__}"
        )
    report_fields = {
        "detector_input_id": detector_input.input_id,
        "run_id": detector_input.run_id,
        "effect_egress_completeness_signals": detector_input.effect_egress_completeness_signals,
        "effect_egress_completeness_gate_passed": detector_input.effect_egress_completeness_gate_passed,
        "receipt_source": detector_input.receipt_source,
        "receipt_coverage": detector_input.receipt_coverage,
    }
    try:
        findings = detect_grants_without_approval(detector_input)
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
    receipt_fd: int,
    *,
    run_id: str,
    input_id: str,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
) -> DetectorReport:
    """Assemble one detector input from effect and receipt descriptors, then score it."""
    with os.fdopen(receipt_fd, "rb", closefd=True) as receipt_fh:
        receipt_document = read_receipt_document(
            receipt_fh,
            max_receipt_bytes=max_receipt_bytes,
        )
    with os.fdopen(effect_fd, "rb", closefd=True) as effect_fh:
        egress = read_effect_egress(effect_fh)
    detector_input = detector_input_from_egress(
        egress,
        input_id=input_id,
        run_id=run_id,
        receipts=receipt_document.receipts,
        receipt_source=receipt_document.receipt_source,
        receipt_coverage=receipt_document.receipt_coverage,
        require_complete=False,
    )
    return score_detector_input(detector_input)


def run_detected_scenario(
    scenario: str = "vulnerable_attack",
    *,
    victim_fault: VictimFault = "none",
    emit_guard_effect: bool = False,
    max_receipt_bytes: int = DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    timeout: float = 10.0,
) -> DetectedScenario:
    """Run one victim and one detector subprocess over supervisor-owned pipes."""
    _scenario_config(scenario)
    victim_fault = _validate_victim_fault(victim_fault)
    max_receipt_bytes = _validate_max_receipt_bytes(max_receipt_bytes)
    run_id = f"identity-approval-demo/{scenario}"
    input_id = f"detector-input-{scenario}"
    effect_read_fd, effect_write_fd = os.pipe()
    receipt_read_fd, receipt_write_fd = os.pipe()
    effect_read_identity = _fd_identity(effect_read_fd)
    receipt_read_identity = _fd_identity(receipt_read_fd)
    receipt_write_identity = _fd_identity(receipt_write_fd)
    detector: subprocess.Popen[str] | None = None
    victim: subprocess.Popen[str] | None = None
    try:
        detector = _spawn_detector_subprocess(
            effect_fd=effect_read_fd,
            receipt_fd=receipt_read_fd,
            run_id=run_id,
            input_id=input_id,
            max_receipt_bytes=max_receipt_bytes,
        )
        _write_all(
            receipt_write_fd,
            _supervisor_receipt_document(scenario, run_id).model_dump_json().encode("utf-8"),
        )
        os.close(receipt_write_fd)
        receipt_write_fd = -1
        victim_args = [
            "victim",
            "--fd",
            str(effect_write_fd),
            "--scenario",
            scenario,
            "--collector-read-device",
            str(effect_read_identity[0]),
            "--collector-read-inode",
            str(effect_read_identity[1]),
            "--collector-read-access-mode",
            str(effect_read_identity[2]),
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
            "--fault",
            victim_fault,
        ]
        if emit_guard_effect:
            victim_args.append("--emit-guard-effect")
        victim = _spawn_effect_collector_subprocess(*victim_args, pass_fds=(effect_write_fd,))
    except BaseException:
        _terminate_process(victim)
        _terminate_process(detector)
        raise
    finally:
        os.close(effect_read_fd)
        os.close(effect_write_fd)
        os.close(receipt_read_fd)
        if receipt_write_fd >= 0:
            os.close(receipt_write_fd)

    try:
        victim_stdout, victim_stderr = victim.communicate(timeout=timeout)
        detector_stdout, detector_stderr = detector.communicate(timeout=timeout)
    except BaseException:
        _terminate_process(victim)
        _terminate_process(detector)
        raise

    if detector.returncode != 0:
        raise RuntimeError(
            "detector subprocess failed with "
            f"returncode={detector.returncode}: {detector_stderr.strip()}"
        )

    victim_summary = (
        VictimSummary.model_validate_json(victim_stdout) if victim.returncode == 0 else None
    )
    return DetectedScenario(
        victim=victim_summary,
        detector=DetectorReport.model_validate_json(detector_stdout),
        victim_returncode=victim.returncode,
        detector_returncode=detector.returncode,
    )


def format_result(result: DetectedScenario) -> str:
    """Render one compact detector scenario table for the terminal."""
    rows = [
        ("victim_returncode", "detector_returncode", "scored", "findings", "refusal"),
        (
            str(result.victim_returncode),
            str(result.detector_returncode),
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


def _supervisor_receipt_document(scenario: str, run_id: str) -> DetectorReceiptDocument:
    """Issue deterministic supervisor-side demo receipts for one known scenario."""
    request, enforce_approval, _ = _scenario_config(scenario)
    receipts: tuple[SecurityReceipt, ...] = ()
    if scenario == "hardened_authorized" and enforce_approval:
        receipts = (
            SecurityReceipt(
                receipt_id=f"supervisor-receipt-{request.request_id}",
                receipt_type=RECEIPT_TYPE,
                source="supervisor-demo-receipts",
                run_id=run_id,
                target=f"{request.principal}@{request.resource}",
                effect_type=EFFECT_TYPE,
                attributes={
                    "request_id": request.request_id,
                    "principal": request.principal,
                    "resource": request.resource,
                },
            ),
        )
    return DetectorReceiptDocument(
        receipt_source="supervisor-demo-receipts",
        receipt_coverage="asserted_complete",
        receipts=receipts,
    )


def _spawn_detector_subprocess(
    *,
    effect_fd: int,
    receipt_fd: int,
    run_id: str,
    input_id: str,
    max_receipt_bytes: int,
) -> subprocess.Popen[str]:
    """Launch this module in detector mode with explicit inherited descriptors."""
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "examples.security_hardening.detector_harness",
            "detector",
            "--effect-fd",
            str(effect_fd),
            "--receipt-fd",
            str(receipt_fd),
            "--run-id",
            run_id,
            "--input-id",
            input_id,
            "--max-receipt-bytes",
            str(max_receipt_bytes),
        ],
        cwd=_REPO_ROOT,
        pass_fds=(effect_fd, receipt_fd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


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


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    detector_parser = subparsers.add_parser(
        "detector",
        help="Assemble and score one detector input from inherited descriptors.",
    )
    detector_parser.add_argument("--effect-fd", type=int, required=True)
    detector_parser.add_argument("--receipt-fd", type=int, required=True)
    detector_parser.add_argument("--run-id", required=True)
    detector_parser.add_argument("--input-id", required=True)
    detector_parser.add_argument(
        "--max-receipt-bytes",
        type=int,
        default=DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    )

    demo_parser = subparsers.add_parser("demo", help="Run the supervisor/victim/detector demo.")
    demo_parser.add_argument("--scenario", default="vulnerable_attack")
    demo_parser.add_argument("--victim-fault", choices=("none", "partial_tail_crash"), default="none")
    demo_parser.add_argument("--emit-guard-effect", action="store_true")
    demo_parser.add_argument(
        "--max-receipt-bytes",
        type=int,
        default=DEFAULT_DETECTOR_RECEIPT_MAX_BYTES,
    )
    demo_parser.add_argument("--timeout", type=float, default=10.0)

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one detector role or the combined detector demo."""
    args = _parse_args(argv)
    if args.command == "detector":
        print(
            score_fd(
                args.effect_fd,
                args.receipt_fd,
                run_id=args.run_id,
                input_id=args.input_id,
                max_receipt_bytes=args.max_receipt_bytes,
            ).model_dump_json()
        )
        return 0

    result = run_detected_scenario(
        args.scenario,
        victim_fault=cast(VictimFault, args.victim_fault),
        emit_guard_effect=args.emit_guard_effect,
        max_receipt_bytes=args.max_receipt_bytes,
        timeout=args.timeout,
    )
    print(format_result(result))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
