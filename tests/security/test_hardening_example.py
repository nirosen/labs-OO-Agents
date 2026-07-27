# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Composition tests for the identity-approval hardening example."""

from __future__ import annotations

from pathlib import Path

import pytest

from examples.security_hardening.identity_approval import (
    AUTHORIZED_REQUEST,
    EFFECT_TYPE,
    FINDING_TYPE,
    PROMPT_INJECTION_REQUEST,
    run_scenario,
)


@pytest.mark.asyncio
async def test_vulnerable_grant_is_recorded_and_flagged_without_receipt(tmp_path: Path) -> None:
    result = await run_scenario(
        "vulnerable_attack",
        PROMPT_INJECTION_REQUEST,
        enforce_approval=False,
        output_dir=tmp_path,
    )

    assert result.decision.granted is True
    assert len(result.effects) == 1
    assert result.effects[0].effect_type == EFFECT_TYPE
    assert result.effects[0].decision == "allowed"
    assert result.receipts == ()
    assert len(result.findings) == 1
    assert result.findings[0].finding_type == FINDING_TYPE
    assert result.findings[0].evidence_refs == (result.effects[0].id,)
    assert result.sink_rows == (result.effects[0].model_dump(mode="json"),)


@pytest.mark.asyncio
async def test_hardened_backend_denies_same_attack_without_finding(tmp_path: Path) -> None:
    result = await run_scenario(
        "hardened_attack",
        PROMPT_INJECTION_REQUEST,
        enforce_approval=True,
        output_dir=tmp_path,
    )

    assert result.decision.granted is False
    assert len(result.effects) == 1
    assert result.effects[0].decision == "denied"
    assert result.receipts == ()
    assert result.findings == ()
    assert result.sink_rows == (result.effects[0].model_dump(mode="json"),)


@pytest.mark.asyncio
async def test_hardened_authorized_grant_correlates_receipt_without_finding(tmp_path: Path) -> None:
    result = await run_scenario(
        "hardened_authorized",
        AUTHORIZED_REQUEST,
        enforce_approval=True,
        output_dir=tmp_path,
    )

    assert result.decision.granted is True
    assert len(result.effects) == 1
    assert result.effects[0].decision == "allowed"
    assert len(result.receipts) == 1
    assert result.receipts[0].effect_type == EFFECT_TYPE
    assert result.receipts[0].target == result.effects[0].target
    assert result.findings == ()
    assert result.sink_rows == (result.effects[0].model_dump(mode="json"),)
