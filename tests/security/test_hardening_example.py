# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Composition tests for the identity-approval hardening example."""

from __future__ import annotations

from pathlib import Path

import pytest

from examples.security_hardening.identity_approval import (
    AUTHORIZED_REQUEST,
    DEFENDER_REASON,
    EFFECT_TYPE,
    FINDING_TYPE,
    PROMPT_INJECTION_REQUEST,
    IdentityApprovalAgent,
    IdentityBackend,
    detect_grants_without_approval,
    install_identity_grant_defender,
    run_scenario,
)
from nooa.security import EffectRecord, SecurityReceipt


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
    assert result.effects[0].attributes["decision_source"] == "backend"
    assert len(result.backend_events) == 1
    assert result.receipts == ()
    assert len(result.findings) == 1
    assert result.findings[0].finding_type == FINDING_TYPE
    assert result.findings[0].run_id == result.run_id
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
    assert result.decision.source == "backend"
    assert len(result.backend_events) == 1
    assert len(result.effects) == 1
    assert result.effects[0].decision == "denied"
    assert result.effects[0].attributes["decision_source"] == "backend"
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
    assert result.decision.source == "backend"
    assert len(result.backend_events) == 1
    assert len(result.effects) == 1
    assert result.effects[0].decision == "allowed"
    assert result.effects[0].attributes["decision_source"] == "backend"
    assert len(result.receipts) == 1
    assert result.receipts[0].effect_type == EFFECT_TYPE
    assert result.receipts[0].run_id == result.run_id
    assert result.receipts[0].target == result.effects[0].target
    assert result.findings == ()
    assert result.sink_rows == (result.effects[0].model_dump(mode="json"),)


@pytest.mark.asyncio
async def test_defender_only_blocks_attack_before_vulnerable_backend(tmp_path: Path) -> None:
    result = await run_scenario(
        "defender_only_attack",
        PROMPT_INJECTION_REQUEST,
        enforce_approval=False,
        defender_enabled=True,
        output_dir=tmp_path,
    )

    assert result.decision.granted is False
    assert result.decision.source == "defender"
    assert result.decision.reason == DEFENDER_REASON
    assert result.backend_events == ()
    assert len(result.effects) == 1
    assert result.effects[0].decision == "denied"
    assert result.effects[0].attributes["decision_source"] == "defender"
    assert result.receipts == ()
    assert result.findings == ()
    assert result.sink_rows == (result.effects[0].model_dump(mode="json"),)


@pytest.mark.asyncio
async def test_defender_recipe_does_not_replace_backend_authorization() -> None:
    backend = IdentityBackend(enforce_approval=False)
    agent = IdentityApprovalAgent(backend)
    uninstall = install_identity_grant_defender(agent.event_manager)
    try:
        blocked = await agent.grant_access(PROMPT_INJECTION_REQUEST)
        assert backend.audit_log() == ()
        bypassed = backend.grant_access(PROMPT_INJECTION_REQUEST)
    finally:
        uninstall()

    assert blocked.granted is False
    assert blocked.source == "defender"
    assert bypassed.granted is True
    assert bypassed.source == "backend"
    assert len(backend.audit_log()) == 1


@pytest.mark.asyncio
async def test_defender_passes_authorized_request_to_backend(tmp_path: Path) -> None:
    result = await run_scenario(
        "defender_authorized",
        AUTHORIZED_REQUEST,
        enforce_approval=True,
        defender_enabled=True,
        output_dir=tmp_path,
    )

    assert result.decision.granted is True
    assert result.decision.source == "backend"
    assert len(result.backend_events) == 1
    assert len(result.receipts) == 1
    assert result.findings == ()


def test_mismatched_receipt_is_cited_as_divergence_evidence() -> None:
    effect = EffectRecord(
        effect_type=EFFECT_TYPE,
        target="contractor@prod-db",
        decision="allowed",
        attributes={"request_id": "req-attack"},
    )
    receipt = SecurityReceipt(
        receipt_id="receipt-req-attack",
        receipt_type="identity.approval",
        source="identity-backend-audit",
        run_id="identity-approval-demo/vulnerable_attack",
        target="contractor@staging-db",
        effect_type=EFFECT_TYPE,
        attributes={"request_id": "req-attack"},
    )

    findings = detect_grants_without_approval(
        (effect,),
        (receipt,),
        run_id="identity-approval-demo/vulnerable_attack",
    )

    assert len(findings) == 1
    assert findings[0].evidence_refs == (effect.id, receipt.receipt_id)


def test_other_run_receipt_does_not_suppress_current_run_finding() -> None:
    effect = EffectRecord(
        effect_type=EFFECT_TYPE,
        target="contractor@prod-db",
        decision="allowed",
        attributes={"request_id": "req-attack"},
    )
    receipt = SecurityReceipt(
        receipt_id="receipt-req-attack",
        receipt_type="identity.approval",
        source="identity-backend-audit",
        run_id="identity-approval-demo/prior-run",
        target="contractor@prod-db",
        effect_type=EFFECT_TYPE,
        attributes={"request_id": "req-attack"},
    )

    findings = detect_grants_without_approval(
        (effect,),
        (receipt,),
        run_id="identity-approval-demo/current-run",
    )

    assert len(findings) == 1
    assert findings[0].run_id == "identity-approval-demo/current-run"
    assert findings[0].evidence_refs == (effect.id,)
