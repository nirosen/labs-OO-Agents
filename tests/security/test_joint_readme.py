# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checked joint-branch scenario matrix."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import NamedTuple, cast

import pytest

from examples.security_hardening.approval_authority import AuthorityFault
from examples.security_hardening.detector_harness import DetectorFault, run_detected_scenario
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
    profile: str
    effect_signals: tuple[str, ...]
    receipt_signals: tuple[str, ...]
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
        assert len(cells) == 9, line
        effect_signals = ast.literal_eval(_strip_code(cells[5]))
        receipt_signals = ast.literal_eval(_strip_code(cells[6]))
        scored = ast.literal_eval(_strip_code(cells[7]))
        assert isinstance(effect_signals, tuple)
        assert isinstance(receipt_signals, tuple)
        assert isinstance(scored, bool)
        rows.append(
            _MatrixRow(
                scenario=_strip_code(cells[0]),
                victim_fault=cast(VictimFault, _strip_code(cells[1])),
                authority_fault=cast(AuthorityFault, _strip_code(cells[2])),
                detector_fault=cast(DetectorFault, _strip_code(cells[3])),
                profile=_strip_code(cells[4]),
                effect_signals=effect_signals,
                receipt_signals=receipt_signals,
                scored=scored,
                findings=int(_strip_code(cells[8])),
            )
        )
    return tuple(rows)


@pytest.mark.parametrize("readme_path", (ROOT_README_PATH, HARDENING_README_PATH))
def test_joint_readmes_have_one_current_joint_section(readme_path: Path) -> None:
    text = _readme_text(readme_path)

    assert text.count("## Security Review Joint Branch:") == 1
    assert "## End-to-End Detector Pipeline Joint Branch" not in text
    assert "> Branch: `codex/security-hardening-e2e-detector-pipeline`\n" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V2" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V3" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V4" not in text
    assert "## Security Review Joint Branch: End-to-End Detector Pipeline V5" not in text


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

    assert len(rows) == 15
    for row in rows:
        result = run_detected_scenario(
            row.scenario,
            victim_fault=row.victim_fault,
            authority_fault=row.authority_fault,
            detector_fault=row.detector_fault,
        )

        assert result.victim_profile == row.profile
        assert result.detector.effect_egress_completeness_signals == row.effect_signals
        assert result.detector.receipt_bundle_completeness_signals == row.receipt_signals
        assert result.detector.scored is row.scored
        assert len(result.detector.findings) == row.findings
