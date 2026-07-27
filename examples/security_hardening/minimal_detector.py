# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Minimal two-process security recipe built from the public ``nooa.security`` surface.

This example is a focused boundary path in the security hardening examples:
one victim process emits a V2 effect stream, one detector process reads it,
builds ``DetectorInput``, and runs a tiny application-owned scorer.

It demonstrates descriptor separation and reader-visible refusal semantics. It
does not authenticate the victim, provide sandboxing or attestation, prove
effect completeness, or turn the example scorer into a NOOA policy API.

    uv run python -m examples.security_hardening.minimal_detector demo
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, cast

from nooa.security import (
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
    DetectorInput,
    EffectRecord,
    FdEffectSink,
    SecurityFinding,
    detector_input_from_egress,
    read_effect_egress,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORT_SCHEMA_VERSION = "nooa-minimal-detector-example-v1"
_VICTIM_FAULTS = ("none", "exit_between_frames")
VictimFault = Literal["none", "exit_between_frames"]


def _demo_effect() -> EffectRecord:
    return EffectRecord(
        id="00000000-0000-0000-0000-000000000021",
        timestamp="2026-07-27T00:00:21",
        effect_type="data.export",
        target="external://untrusted-bucket",
        decision="allowed",
        observer="minimal_detector_example",
        attributes={"request_id": "minimal-export-attack"},
    )


def score_exports(detector_input: DetectorInput) -> tuple[SecurityFinding, ...]:
    """Flag allowed export effects in this example-only detector policy."""
    return tuple(
        SecurityFinding(
            finding_id=f"finding-{effect.id}",
            finding_type="data.export.allowed",
            producer="minimal-export-scorer",
            run_id=detector_input.run_id,
            target=effect.target,
            evidence_refs=(detector_input.input_id, effect.id),
        )
        for effect in detector_input.effects
        if effect.effect_type == "data.export" and effect.decision == "allowed"
    )


def run_victim(effect_fd: int, *, victim_fault: VictimFault = "none") -> None:
    """Write one effect stream from the victim side of the pipe."""
    _validate_victim_fault(victim_fault)
    try:
        sink = FdEffectSink(effect_fd, schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2)
        sink(_demo_effect())
        if victim_fault == "exit_between_frames":
            raise SystemExit(3)
        sink.close()
    finally:
        os.close(effect_fd)


def run_detector(effect_fd: int) -> dict[str, object]:
    """Read one V2 stream and return a detector-side JSON report."""
    with os.fdopen(effect_fd, "rb", closefd=True) as fh:
        egress = read_effect_egress(
            fh,
            expected_schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2,
        )
    detector_input = detector_input_from_egress(
        egress,
        input_id="minimal-detector-input",
        run_id="minimal-detector-demo",
        require_complete=False,
    )
    signals = list(detector_input.effect_egress_completeness_signals)
    if not detector_input.effect_egress_completeness_gate_passed:
        return _report(
            scored=False,
            signals=signals,
            findings=(),
            refusal_reason="effect egress completeness gate did not pass",
        )
    return _report(
        scored=True,
        signals=signals,
        findings=score_exports(detector_input),
        refusal_reason=None,
    )


def run_demo(
    *,
    victim_fault: VictimFault = "none",
    timeout: float = 10.0,
) -> dict[str, object]:
    """Run one victim process and one detector process over a supervisor pipe."""
    _validate_victim_fault(victim_fault)
    read_fd, write_fd = os.pipe()
    detector: subprocess.Popen[str] | None = None
    victim: subprocess.Popen[str] | None = None
    try:
        detector = _spawn_subprocess("detector", "--effect-fd", str(read_fd), pass_fds=(read_fd,))
        victim = _spawn_subprocess(
            "victim",
            "--effect-fd",
            str(write_fd),
            "--victim-fault",
            victim_fault,
            pass_fds=(write_fd,),
        )
    except BaseException:
        _terminate_process(victim)
        _terminate_process(detector)
        raise
    finally:
        os.close(read_fd)
        os.close(write_fd)

    try:
        _victim_stdout, victim_stderr = victim.communicate(timeout=timeout)
        detector_stdout, detector_stderr = detector.communicate(timeout=timeout)
    except BaseException:
        _terminate_process(victim)
        _terminate_process(detector)
        raise

    expected_victim_returncode = 3 if victim_fault == "exit_between_frames" else 0
    if victim.returncode != expected_victim_returncode:
        raise RuntimeError(
            f"victim subprocess failed with returncode={victim.returncode}: {victim_stderr.strip()}"
        )
    if detector.returncode != 0:
        raise RuntimeError(
            "detector subprocess failed with "
            f"returncode={detector.returncode}: {detector_stderr.strip()}"
        )

    report = json.loads(detector_stdout)
    if not isinstance(report, dict):
        raise RuntimeError("detector subprocess did not emit one JSON object")
    report["victim_returncode"] = victim.returncode
    report["detector_returncode"] = detector.returncode
    return report


def _report(
    *,
    scored: bool,
    signals: list[str],
    findings: tuple[SecurityFinding, ...],
    refusal_reason: str | None,
) -> dict[str, object]:
    return {
        "schema_version": _REPORT_SCHEMA_VERSION,
        "scored": scored,
        "effect_egress_completeness_signals": signals,
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "refusal_reason": refusal_reason,
    }


def _spawn_subprocess(*args: str, pass_fds: tuple[int, ...]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", "examples.security_hardening.minimal_detector", *args],
        cwd=_REPO_ROOT,
        pass_fds=pass_fds,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _terminate_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.kill()
    process.wait()


def _validate_victim_fault(victim_fault: str) -> VictimFault:
    if victim_fault not in _VICTIM_FAULTS:
        raise ValueError(f"unknown victim fault: {victim_fault}")
    return cast(VictimFault, victim_fault)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    victim_parser = subparsers.add_parser("victim")
    victim_parser.add_argument("--effect-fd", type=int, required=True)
    victim_parser.add_argument("--victim-fault", choices=_VICTIM_FAULTS, default="none")

    detector_parser = subparsers.add_parser("detector")
    detector_parser.add_argument("--effect-fd", type=int, required=True)

    demo_parser = subparsers.add_parser("demo")
    demo_parser.add_argument("--victim-fault", choices=_VICTIM_FAULTS, default="none")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "victim":
        run_victim(args.effect_fd, victim_fault=args.victim_fault)
        return 0
    if args.command == "detector":
        print(json.dumps(run_detector(args.effect_fd), separators=(",", ":"), ensure_ascii=False))
        return 0
    print(json.dumps(run_demo(victim_fault=args.victim_fault), separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
