# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checked joint-branch scenario matrix."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import NamedTuple, cast

from examples.security_hardening.detector_harness import run_detected_scenario
from examples.security_hardening.effect_collector import VictimFault

README_PATH = Path(__file__).resolve().parents[2] / "README.md"
MATRIX_START = "<!-- JOINT_SCENARIO_MATRIX_START -->"
MATRIX_END = "<!-- JOINT_SCENARIO_MATRIX_END -->"


class _MatrixRow(NamedTuple):
    scenario: str
    victim_fault: VictimFault
    profile: str
    signals: tuple[str, ...]
    scored: bool
    findings: int


def _readme_text() -> str:
    return README_PATH.read_text(encoding="utf-8")


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
        assert len(cells) == 6, line
        signals = ast.literal_eval(_strip_code(cells[3]))
        scored = ast.literal_eval(_strip_code(cells[4]))
        assert isinstance(signals, tuple)
        assert isinstance(scored, bool)
        rows.append(
            _MatrixRow(
                scenario=_strip_code(cells[0]),
                victim_fault=cast(VictimFault, _strip_code(cells[1])),
                profile=_strip_code(cells[2]),
                signals=signals,
                scored=scored,
                findings=int(_strip_code(cells[5])),
            )
        )
    return tuple(rows)


def test_joint_readme_has_one_current_joint_section() -> None:
    text = _readme_text()

    assert MATRIX_START in text
    assert MATRIX_END in text
    assert text.count("## Security Review Joint Branch:") == 1
    assert "> Branch: `codex/security-hardening-e2e-detector-pipeline`\n" not in text


def test_joint_readme_matrix_reproduces_detector_paths() -> None:
    rows = _matrix_rows()

    assert len(rows) == 9
    for row in rows:
        result = run_detected_scenario(row.scenario, victim_fault=row.victim_fault)

        assert result.victim_profile == row.profile
        assert result.detector.effect_egress_completeness_signals == row.signals
        assert result.detector.scored is row.scored
        assert len(result.detector.findings) == row.findings
