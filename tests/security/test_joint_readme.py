# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checked joint-branch scenario matrix."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import NamedTuple, cast

import pytest

from examples.security_hardening.approval_authority import AuthorityFault
from examples.security_hardening.detector_harness import (
    DetectorFault,
    FindingAdmissionRefusal,
    ReceiptAdmissionRefusal,
    SubprocessOutputFault,
    run_detected_scenario,
)
from examples.security_hardening.effect_collector import VictimFault

ROOT_README_PATH = Path(__file__).resolve().parents[2] / "README.md"
EXAMPLES_README_PATH = Path(__file__).resolve().parents[2] / "examples" / "README.md"
HARDENING_README_PATH = EXAMPLES_README_PATH.parent / "security_hardening" / "README.md"
MATRIX_START = "<!-- JOINT_SCENARIO_MATRIX_START -->"
MATRIX_END = "<!-- JOINT_SCENARIO_MATRIX_END -->"
SECURITY_ENTRYPOINTS = (
    "identity_approval.py",
    "effect_collector.py",
    "detector_harness.py",
    "approval_authority.py",
    "data_export.py",
    "minimal_detector.py",
)
SECURITY_SUPPORT_MODULES = (
    "__init__.py",
    "detector_policy.py",
    "identity_contract.py",
)


class _MatrixRow(NamedTuple):
    scenario: str
    victim_fault: VictimFault
    authority_fault: AuthorityFault
    detector_fault: DetectorFault
    subprocess_output_fault: SubprocessOutputFault
    profile: str
    effect_signals: tuple[str, ...]
    receipt_signals: tuple[str, ...]
    finding_signals: tuple[str, ...]
    receipt_admission_refusal: ReceiptAdmissionRefusal | None
    finding_admission_refusal: FindingAdmissionRefusal | None
    scored: bool
    findings: int


def _readme_text(path: Path = ROOT_README_PATH) -> str:
    return path.read_text(encoding="utf-8")


def _strip_code(cell: str) -> str:
    assert cell.startswith("`") and cell.endswith("`"), cell
    return cell[1:-1]


def _matrix_rows() -> tuple[_MatrixRow, ...]:
    text = _readme_text()
    matrix = text.split(MATRIX_START, 1)[1].split(MATRIX_END, 1)[0]
    lines = [line for line in matrix.splitlines() if line.startswith("|")]
    rows: list[_MatrixRow] = []
    for line in lines[2:]:
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        assert len(cells) == 13, line
        effect_signals = ast.literal_eval(_strip_code(cells[6]))
        receipt_signals = ast.literal_eval(_strip_code(cells[7]))
        finding_signals = ast.literal_eval(_strip_code(cells[8]))
        receipt_admission_refusal = ast.literal_eval(_strip_code(cells[9]))
        finding_admission_refusal = ast.literal_eval(_strip_code(cells[10]))
        scored = ast.literal_eval(_strip_code(cells[11]))
        assert isinstance(effect_signals, tuple)
        assert isinstance(receipt_signals, tuple)
        assert isinstance(finding_signals, tuple)
        assert receipt_admission_refusal is None or isinstance(
            receipt_admission_refusal, str
        )
        assert finding_admission_refusal is None or isinstance(
            finding_admission_refusal, str
        )
        assert isinstance(scored, bool)
        rows.append(
            _MatrixRow(
                scenario=_strip_code(cells[0]),
                victim_fault=cast(VictimFault, _strip_code(cells[1])),
                authority_fault=cast(AuthorityFault, _strip_code(cells[2])),
                detector_fault=cast(DetectorFault, _strip_code(cells[3])),
                subprocess_output_fault=cast(SubprocessOutputFault, _strip_code(cells[4])),
                profile=_strip_code(cells[5]),
                effect_signals=effect_signals,
                receipt_signals=receipt_signals,
                finding_signals=finding_signals,
                receipt_admission_refusal=cast(
                    ReceiptAdmissionRefusal | None, receipt_admission_refusal
                ),
                finding_admission_refusal=cast(
                    FindingAdmissionRefusal | None, finding_admission_refusal
                ),
                scored=scored,
                findings=int(_strip_code(cells[12])),
            )
        )
    return tuple(rows)


@pytest.mark.parametrize("readme_path", (ROOT_README_PATH, HARDENING_README_PATH))
def test_joint_readmes_have_one_current_joint_section(readme_path: Path) -> None:
    text = _readme_text(readme_path)

    assert text.count("## Security Review Joint Branch:") == 1
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V16" in text
    assert "## End-to-End Detector Pipeline Joint Branch" not in text
    assert "> Branch: `codex/security-hardening-e2e-detector-pipeline`\n" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V2" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V3" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V4" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V5" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V6" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V7" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V8" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V9" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V10" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V11" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V12" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V13" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V14" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V15" not in text


def test_root_joint_readme_has_scenario_matrix() -> None:
    text = _readme_text()

    assert MATRIX_START in text
    assert MATRIX_END in text


def test_hardening_readme_joint_link_targets_current_root_heading() -> None:
    root_text = _readme_text()
    hardening_text = _readme_text(HARDENING_README_PATH)
    heading = next(
        line.removeprefix("## ")
        for line in root_text.splitlines()
        if line.startswith("## Security Review Joint Branch:")
    )
    expected_anchor = heading.lower().replace(":", "").replace(" ", "-")

    assert f"(../../README.md#{expected_anchor})" in hardening_text


def test_examples_readme_indexes_security_entrypoints() -> None:
    text = _readme_text(EXAMPLES_README_PATH)
    contents_table = text.split("**Contents**", 1)[1].split("\n---", 1)[0]
    entrypoints = set(SECURITY_ENTRYPOINTS)
    support_modules = set(SECURITY_SUPPORT_MODULES)
    security_modules = {path.name for path in HARDENING_README_PATH.parent.glob("*.py")}

    for entrypoint in SECURITY_ENTRYPOINTS:
        assert f"](security_hardening/{entrypoint})" in contents_table
    assert entrypoints.isdisjoint(support_modules)
    assert entrypoints | support_modules == security_modules


def test_hardening_readme_orders_security_onramps() -> None:
    text = _readme_text(HARDENING_README_PATH)
    reading_order = text.split("## Reading Order", 1)[1].split("\n## ", 1)[0]
    links = ("SURFACE.md", "minimal_detector.py", "detector_harness.py")

    positions = [reading_order.index(f"]({link})") for link in links]
    assert positions == sorted(positions)
    for link in links:
        assert (HARDENING_README_PATH.parent / link).exists()


def test_joint_readme_matrix_reproduces_detector_paths() -> None:
    rows = _matrix_rows()

    assert len(rows) == 22
    for row in rows:
        result = run_detected_scenario(
            row.scenario,
            victim_fault=row.victim_fault,
            authority_fault=row.authority_fault,
            detector_fault=row.detector_fault,
            subprocess_output_fault=row.subprocess_output_fault,
        )

        assert result.victim_profile == row.profile
        assert result.detector.effect_egress_completeness_signals == row.effect_signals
        assert result.detector.receipt_bundle_completeness_signals == row.receipt_signals
        assert result.detector.finding_bundle_completeness_signals == row.finding_signals
        assert result.detector.receipt_admission_refusal == row.receipt_admission_refusal
        assert result.detector.finding_admission_refusal == row.finding_admission_refusal
        assert result.detector.scored is row.scored
        assert len(result.findings) == row.findings


def test_joint_readme_exposes_id_uniqueness_refusal_stage() -> None:
    rows = _matrix_rows()
    duplicate_rows = tuple(row for row in rows if row.detector_fault == "duplicate_finding_id")

    assert duplicate_rows == (
        _MatrixRow(
            scenario="vulnerable_attack",
            victim_fault="none",
            authority_fault="none",
            detector_fault="duplicate_finding_id",
            subprocess_output_fault="none",
            profile="identity_approval",
            effect_signals=(),
            receipt_signals=(),
            finding_signals=(),
            receipt_admission_refusal=None,
            finding_admission_refusal="duplicate_finding_id",
            scored=False,
            findings=0,
        ),
    )


def test_joint_readme_exposes_current_finding_admission_refusal_stages() -> None:
    rows = _matrix_rows()
    expected = {
        "blank_finding_run_id": "scope_drift",
        "stale_finding_run_id": "scope_drift",
        "duplicate_finding_id": "duplicate_finding_id",
        "drop_required_evidence_ref": "missing_required_evidence_ref",
        "drop_finding_count_mismatch": "count_mismatch",
    }

    assert {
        row.detector_fault: row.finding_admission_refusal
        for row in rows
        if row.detector_fault in expected
    } == expected


def test_joint_readme_keeps_evidence_membership_detector_side() -> None:
    root_text = _readme_text()
    hardening_text = _readme_text(HARDENING_README_PATH)

    assert "evidence_ref_membership_gated_scorer()" in root_text
    assert "evidence ref membership gate" in hardening_text
    assert "The matrix still has no row for detector-side evidence-ref membership" in root_text
    assert "the current fault axis mutates outputs only after scoring" in root_text
    assert "the supervisor still has no independent evidence-ID set" in root_text


def test_joint_readme_exposes_required_evidence_ref_refusal_stage() -> None:
    rows = _matrix_rows()
    required_ref_rows = tuple(
        row for row in rows if row.detector_fault == "drop_required_evidence_ref"
    )

    assert required_ref_rows == (
        _MatrixRow(
            scenario="vulnerable_attack",
            victim_fault="none",
            authority_fault="none",
            detector_fault="drop_required_evidence_ref",
            subprocess_output_fault="none",
            profile="identity_approval",
            effect_signals=(),
            receipt_signals=(),
            finding_signals=(),
            receipt_admission_refusal=None,
            finding_admission_refusal="missing_required_evidence_ref",
            scored=False,
            findings=0,
        ),
    )


def test_joint_readme_exposes_receipt_id_uniqueness_refusal_stage() -> None:
    rows = _matrix_rows()
    duplicate_receipt_rows = tuple(
        row for row in rows if row.authority_fault == "duplicate_receipt_id"
    )

    assert duplicate_receipt_rows == (
        _MatrixRow(
            scenario="hardened_authorized",
            victim_fault="none",
            authority_fault="duplicate_receipt_id",
            detector_fault="none",
            subprocess_output_fault="none",
            profile="identity_approval",
            effect_signals=(),
            receipt_signals=(),
            finding_signals=(),
            receipt_admission_refusal="duplicate_receipt_id",
            finding_admission_refusal=None,
            scored=False,
            findings=0,
        ),
    )


def test_joint_readme_keeps_receipt_id_uniqueness_detector_side() -> None:
    root_text = _readme_text()
    hardening_text = _readme_text(HARDENING_README_PATH)

    assert "receipt_id_uniqueness_gated_scorer()" in root_text
    assert "receipt ID uniqueness gate" in hardening_text
    assert "V14 adds one detector-side row for `duplicate_receipt_id`" in root_text
    assert "duplicate receipt ID is `duplicate_receipt_id`" in root_text


def test_joint_readme_exposes_receipt_source_alignment_refusal_stage() -> None:
    rows = _matrix_rows()
    mislabeled_receipt_rows = tuple(
        row for row in rows if row.authority_fault == "mislabel_receipt_source"
    )

    assert mislabeled_receipt_rows == (
        _MatrixRow(
            scenario="hardened_authorized",
            victim_fault="none",
            authority_fault="mislabel_receipt_source",
            detector_fault="none",
            subprocess_output_fault="none",
            profile="identity_approval",
            effect_signals=(),
            receipt_signals=(),
            finding_signals=(),
            receipt_admission_refusal="receipt_source_mismatch",
            finding_admission_refusal=None,
            scored=False,
            findings=0,
        ),
    )


def test_joint_readme_keeps_receipt_source_alignment_detector_side() -> None:
    root_text = _readme_text()
    hardening_text = _readme_text(HARDENING_README_PATH)

    assert "receipt_source_alignment_gated_scorer()" in root_text
    assert "receipt source alignment gate" in hardening_text
    assert "V15 adds one detector-side row for `mislabel_receipt_source`" in root_text
    assert "The prior four-row collision splits completely" in root_text


def test_joint_readme_exposes_current_receipt_admission_refusal_stages() -> None:
    rows = _matrix_rows()
    expected = {
        "stale_receipt_run_id": "scope_drift",
        "duplicate_receipt_id": "duplicate_receipt_id",
        "mislabel_receipt_source": "receipt_source_mismatch",
    }

    assert {
        row.authority_fault: row.receipt_admission_refusal
        for row in rows
        if row.authority_fault in expected
    } == expected
