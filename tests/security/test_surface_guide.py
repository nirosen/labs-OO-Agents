# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the checked security surface guide."""

from __future__ import annotations

import re
from pathlib import Path
from textwrap import dedent

import nooa.security as security
from nooa.security import DetectorInput, SecurityFinding

SURFACE_GUIDE_PATH = (
    Path(__file__).resolve().parents[2] / "examples" / "security_hardening" / "SURFACE.md"
)
EXPORT_INDEX_START = "<!-- SECURITY_EXPORT_INDEX_START -->"
EXPORT_INDEX_END = "<!-- SECURITY_EXPORT_INDEX_END -->"
EXPORT_ROW_RE = re.compile(r"^\| `([^`]+)` \|", re.MULTILINE)
MINIMAL_INTEGRATION_SNIPPET = dedent(
    """
    import os

    from nooa.security import (
        EFFECT_EGRESS_SCHEMA_VERSION_V2,
        DetectorInput,
        EffectRecord,
        FdEffectSink,
        SecurityFinding,
        detector_input_from_egress,
        read_effect_egress,
    )

    read_fd, write_fd = os.pipe()
    try:
        sink = FdEffectSink(write_fd, schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2)
        sink(EffectRecord(effect_type="data.export", target="external://bucket", decision="allowed"))
        sink.close()
    finally:
        os.close(write_fd)

    with os.fdopen(read_fd, "rb", closefd=True) as fh:
        egress = read_effect_egress(
            fh,
            expected_schema_version=EFFECT_EGRESS_SCHEMA_VERSION_V2,
        )

    detector_input = detector_input_from_egress(
        egress,
        input_id="assessment-input-1",
        run_id="assessment-1",
    )

    def score_exports(input_: DetectorInput) -> tuple[SecurityFinding, ...]:
        return tuple(
            SecurityFinding(
                finding_id=f"finding-{record.id}",
                finding_type="data.export.allowed",
                producer="example-export-scorer",
                run_id=input_.run_id,
                target=record.target,
                evidence_refs=(input_.input_id, record.id),
            )
            for record in input_.effects
            if record.effect_type == "data.export" and record.decision == "allowed"
        )

    findings = score_exports(detector_input)
    assert detector_input.effect_egress_completeness_gate_passed is True
    assert len(findings) == 1
    """
).strip()


def _guide_text() -> str:
    return SURFACE_GUIDE_PATH.read_text(encoding="utf-8")


def _export_index_text(guide: str) -> str:
    return guide.split(EXPORT_INDEX_START, 1)[1].split(EXPORT_INDEX_END, 1)[0]


def test_surface_guide_export_index_matches_public_security_surface() -> None:
    guide = _guide_text()

    assert EXPORT_INDEX_START in guide
    assert EXPORT_INDEX_END in guide
    documented_names = EXPORT_ROW_RE.findall(_export_index_text(guide))

    assert len(documented_names) == len(set(documented_names))
    assert set(documented_names) == set(security.__all__)


def test_surface_guide_minimal_integration_snippet_is_executable() -> None:
    guide = _guide_text()

    assert f"```python\n{MINIMAL_INTEGRATION_SNIPPET}\n```" in guide

    namespace: dict[str, object] = {}
    exec(MINIMAL_INTEGRATION_SNIPPET, namespace)

    assert isinstance(namespace["detector_input"], DetectorInput)
    findings = namespace["findings"]
    assert isinstance(findings, tuple)
    assert len(findings) == 1
    assert isinstance(findings[0], SecurityFinding)
