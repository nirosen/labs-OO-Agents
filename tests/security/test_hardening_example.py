# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Composition tests for the identity-approval hardening example."""

from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path

import pytest

from examples.security_hardening import identity_approval
from examples.security_hardening.identity_approval import (
    DEFENDER_REASON,
    EFFECT_TYPE,
    FINDING_TYPE,
    PROMPT_INJECTION_REQUEST,
    AccessRequest,
    IdentityApprovalAgent,
    IdentityBackend,
    authorized_request_with_token,
    detect_grants_without_approval,
    install_identity_grant_defender,
    observe_identity_grant,
    run_scenario,
)
from nooa.errors import RestrictedCodeError
from nooa.security import (
    DetectorInput,
    EffectEgressIncompleteError,
    EffectEgressReadResult,
    EffectRecord,
    FdEffectSink,
    SecurityReceipt,
    framework_guard_observer,
    install_agent_call_effect_recorder,
    install_effect_recorder,
    install_effect_sink,
    read_effect_egress,
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
    assert result.effects[0].attributes["decision_source"] == "backend"
    assert len(result.backend_events) == 1
    assert result.receipts == ()
    assert len(result.findings) == 1
    assert result.findings[0].finding_type == FINDING_TYPE
    assert result.findings[0].run_id == result.run_id
    assert result.detector_input.input_id == "detector-input-vulnerable_attack"
    assert result.detector_input.effects == result.effects
    assert result.detector_input.receipts == result.receipts
    assert result.detector_input.receipt_source == "identity-backend-audit"
    assert result.detector_input.receipt_coverage == "asserted_complete"
    assert result.detector_input.effect_egress_completeness_signals == ()
    assert result.detector_input.effect_egress_completeness_gate_passed is True
    assert result.findings[0].evidence_refs == (
        result.detector_input.input_id,
        result.effects[0].id,
    )
    assert result.egress.records == result.effects
    assert result.egress.first_sequence_error is None
    assert result.egress.truncated is False


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
    assert result.detector_input.effects == result.effects
    assert result.detector_input.receipts == result.receipts
    assert result.egress.records == result.effects
    assert result.egress.first_sequence_error is None
    assert result.egress.truncated is False


@pytest.mark.asyncio
async def test_hardened_authorized_grant_correlates_receipt_without_finding(tmp_path: Path) -> None:
    result = await run_scenario(
        "hardened_authorized",
        authorized_request_with_token(),
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
    assert result.detector_input.effects == result.effects
    assert result.detector_input.receipts == result.receipts
    assert result.egress.records == result.effects
    assert result.egress.first_sequence_error is None
    assert result.egress.truncated is False


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
    assert result.detector_input.effects == result.effects
    assert result.detector_input.receipts == result.receipts
    assert result.egress.records == result.effects
    assert result.egress.first_sequence_error is None
    assert result.egress.truncated is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "egress",
    [
        EffectEgressReadResult(records=(), truncated=True),
        EffectEgressReadResult(
            records=(EffectRecord(effect_type=EFFECT_TYPE, target="contractor@prod-db"),),
            first_sequence_error=(0, 1),
        ),
    ],
    ids=["truncated", "sequence-gap"],
)
async def test_run_scenario_refuses_to_score_incomplete_egress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    egress: EffectEgressReadResult,
) -> None:
    def read_degraded_egress(_: Path) -> EffectEgressReadResult:
        return egress

    monkeypatch.setattr(identity_approval, "_read_effect_egress", read_degraded_egress)

    with pytest.raises(EffectEgressIncompleteError, match="effect egress stream is incomplete"):
        await run_scenario(
            "vulnerable_attack",
            PROMPT_INJECTION_REQUEST,
            enforce_approval=False,
            output_dir=tmp_path,
        )


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
        authorized_request_with_token(),
        enforce_approval=True,
        defender_enabled=True,
        output_dir=tmp_path,
    )

    assert result.decision.granted is True
    assert result.decision.source == "backend"
    assert len(result.backend_events) == 1
    assert len(result.receipts) == 1
    assert result.findings == ()


@pytest.mark.asyncio
async def test_defender_blocks_missing_token_without_untrusted_content(tmp_path: Path) -> None:
    result = await run_scenario(
        "defender_missing_token",
        AccessRequest(
            request_id="req-empty",
            principal="contractor",
            resource="prod-db",
            untrusted_content="",
        ),
        enforce_approval=False,
        defender_enabled=True,
        output_dir=tmp_path,
    )

    assert result.decision.granted is False
    assert result.decision.source == "defender"
    assert result.backend_events == ()


@pytest.mark.asyncio
async def test_defender_outside_recorder_short_circuits_without_effect_row() -> None:
    backend = IdentityBackend(enforce_approval=False)
    agent = IdentityApprovalAgent(backend)
    uninstall_defender = install_identity_grant_defender(agent.event_manager)
    uninstall_recorder = install_agent_call_effect_recorder(
        agent.event_manager,
        observe_identity_grant,
    )
    try:
        decision = await agent.grant_access(PROMPT_INJECTION_REQUEST)
    finally:
        uninstall_recorder()
        uninstall_defender()

    assert decision.granted is False
    assert decision.source == "defender"
    assert backend.audit_log() == ()
    assert agent.event_manager.filter(type="EffectRecord") == []


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

    detector_input = DetectorInput(
        input_id="detector-input-vulnerable_attack",
        run_id="identity-approval-demo/vulnerable_attack",
        effects=(effect,),
        effect_egress_completeness_gate_passed=True,
        receipts=(receipt,),
        receipt_coverage="asserted_complete",
    )
    findings = detect_grants_without_approval(detector_input)

    assert len(findings) == 1
    assert findings[0].evidence_refs == (
        detector_input.input_id,
        effect.id,
        receipt.receipt_id,
    )


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

    detector_input = DetectorInput(
        input_id="detector-input-current-run",
        run_id="identity-approval-demo/current-run",
        effects=(effect,),
        effect_egress_completeness_gate_passed=True,
        receipts=(receipt,),
        receipt_coverage="asserted_complete",
    )
    findings = detect_grants_without_approval(detector_input)

    assert len(findings) == 1
    assert findings[0].run_id == "identity-approval-demo/current-run"
    assert findings[0].evidence_refs == (detector_input.input_id, effect.id)


@pytest.mark.parametrize(
    ("detector_input", "match"),
    [
        (
            DetectorInput(
                input_id="detector-input-unchecked",
                effects=(EffectRecord(effect_type=EFFECT_TYPE, target="contractor@prod-db"),),
                receipt_coverage="asserted_complete",
            ),
            "effect_egress_completeness_gate_passed=True",
        ),
        (
            DetectorInput(
                input_id="detector-input-unknown-receipts",
                effects=(EffectRecord(effect_type=EFFECT_TYPE, target="contractor@prod-db"),),
                effect_egress_completeness_gate_passed=True,
            ),
            "receipt_coverage='asserted_complete'",
        ),
    ],
    ids=["unchecked-egress", "unknown-receipt-coverage"],
)
def test_identity_scorer_refuses_unscoreable_detector_input(
    detector_input: DetectorInput,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        detect_grants_without_approval(detector_input)


@pytest.mark.asyncio
async def test_application_and_framework_effects_keep_distinct_observers() -> None:
    agent = IdentityApprovalAgent(IdentityBackend(enforce_approval=False))
    uninstall_agent_call = install_agent_call_effect_recorder(
        agent.event_manager,
        observe_identity_grant,
    )
    uninstall_guard = install_effect_recorder(
        agent.event_manager,
        framework_guard_observer,
    )
    try:
        await agent.handle_request(PROMPT_INJECTION_REQUEST)
        validation_result = await agent.runtime.execute_code("eval('1 + 1')")
    finally:
        uninstall_guard()
        uninstall_agent_call()

    assert isinstance(validation_result.error, RestrictedCodeError)
    records = [
        event
        for event in agent.event_manager.filter(type="EffectRecord")
        if isinstance(event, EffectRecord)
    ]
    assert len(records) == 2
    assert {(record.effect_type, record.observer, record.decision) for record in records} == {
        (EFFECT_TYPE, "agent_call_middleware", "allowed"),
        ("code.validation", "framework_guard", "denied"),
    }


@pytest.mark.asyncio
async def test_defender_denial_and_framework_effects_keep_distinct_observers() -> None:
    agent = IdentityApprovalAgent(IdentityBackend(enforce_approval=False))
    uninstall_agent_call = install_agent_call_effect_recorder(
        agent.event_manager,
        observe_identity_grant,
    )
    uninstall_defender = install_identity_grant_defender(agent.event_manager)
    uninstall_guard = install_effect_recorder(
        agent.event_manager,
        framework_guard_observer,
    )
    try:
        decision = await agent.handle_request(PROMPT_INJECTION_REQUEST)
        validation_result = await agent.runtime.execute_code("eval('1 + 1')")
    finally:
        uninstall_guard()
        uninstall_defender()
        uninstall_agent_call()

    assert decision.granted is False
    assert decision.source == "defender"
    assert isinstance(validation_result.error, RestrictedCodeError)
    records = [
        event
        for event in agent.event_manager.filter(type="EffectRecord")
        if isinstance(event, EffectRecord)
    ]
    assert len(records) == 2
    assert {(record.effect_type, record.observer, record.decision) for record in records} == {
        (EFFECT_TYPE, "agent_call_middleware", "denied"),
        ("code.validation", "framework_guard", "denied"),
    }


@pytest.mark.asyncio
async def test_egress_keeps_defender_and_framework_observer_labels_distinct(
    tmp_path: Path,
) -> None:
    agent = IdentityApprovalAgent(IdentityBackend(enforce_approval=False))
    egress_path = tmp_path / "combined.effects.egress"
    sink_fd = os.open(egress_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with ExitStack() as cleanup:
        cleanup.callback(os.close, sink_fd)
        cleanup.callback(install_effect_sink(agent.event_manager, FdEffectSink(sink_fd)))
        cleanup.callback(
            install_agent_call_effect_recorder(
                agent.event_manager,
                observe_identity_grant,
            )
        )
        cleanup.callback(install_identity_grant_defender(agent.event_manager))
        cleanup.callback(
            install_effect_recorder(
                agent.event_manager,
                framework_guard_observer,
            )
        )
        decision = await agent.handle_request(PROMPT_INJECTION_REQUEST)
        validation_result = await agent.runtime.execute_code("eval('1 + 1')")

    assert decision.granted is False
    assert decision.source == "defender"
    assert isinstance(validation_result.error, RestrictedCodeError)
    with egress_path.open("rb") as fh:
        egress = read_effect_egress(fh)
    assert egress.first_sequence_error is None
    assert egress.truncated is False
    assert {
        (record.effect_type, record.observer, record.decision) for record in egress.records
    } == {
        (EFFECT_TYPE, "agent_call_middleware", "denied"),
        ("code.validation", "framework_guard", "denied"),
    }
