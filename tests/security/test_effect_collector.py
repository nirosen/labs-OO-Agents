# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the out-of-process effect collector example."""

from __future__ import annotations

import json
import os

import pytest

from examples.security_hardening.effect_collector import (
    CollectorSummary,
    _fd_identity,
    _has_fd_identity,
    _spawn_subprocess,
    _terminate_process,
    run_collected_scenario,
)
from examples.security_hardening.identity_approval import EFFECT_TYPE
from nooa.security import (
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
    EFFECT_EGRESS_STREAM_END_EVENT_TYPE,
    EffectRecord,
)


def _frame_line(sequence: int, record: EffectRecord) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": EFFECT_EGRESS_SCHEMA_VERSION_V2,
                "sequence": sequence,
                "record": record.model_dump(mode="json"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _stream_end_line(sequence: int, record_count: int) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": EFFECT_EGRESS_SCHEMA_VERSION_V2,
                "sequence": sequence,
                "stream_end": {
                    "event_type": EFFECT_EGRESS_STREAM_END_EVENT_TYPE,
                    "record_count": record_count,
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _collect_payload(payload: bytes) -> CollectorSummary:
    read_fd, write_fd = os.pipe()
    collector = _spawn_subprocess("collect", "--fd", str(read_fd), pass_fds=(read_fd,))
    os.close(read_fd)
    try:
        try:
            view = memoryview(payload)
            while view:
                written = os.write(write_fd, view)
                view = view[written:]
        finally:
            os.close(write_fd)

        stdout, stderr = collector.communicate(timeout=10.0)
    except BaseException:
        _terminate_process(collector)
        raise
    assert collector.returncode == 0, stderr
    return CollectorSummary.model_validate_json(stdout)


def test_collected_scenario_round_trips_identity_effect_through_subprocesses() -> None:
    result = run_collected_scenario("vulnerable_attack")

    assert result.victim is not None
    assert result.victim_returncode == 0
    assert result.victim.decision == "allowed"
    assert result.victim.decision_source == "backend"
    assert result.victim.backend_event_count == 1
    assert result.collector.record_count == 1
    assert result.collector.effect_egress_schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2
    assert result.collector.first_sequence_error is None
    assert result.collector.truncated is False
    assert result.collector.stream_end_declared is True
    assert result.collector.declared_record_count == 1
    assert result.collector.records[0].effect_type == EFFECT_TYPE
    assert result.collector.records[0].decision == "allowed"


def test_collected_scenario_preserves_defender_denial() -> None:
    result = run_collected_scenario("defender_only_attack")

    assert result.victim is not None
    assert result.victim.decision == "denied"
    assert result.victim.decision_source == "defender"
    assert result.victim.backend_event_count == 0
    assert result.collector.record_count == 1
    assert result.collector.records[0].decision == "denied"
    assert result.collector.records[0].attributes["decision_source"] == "defender"


@pytest.mark.parametrize(
    ("scenario", "decision", "record_decision", "approval_token_present"),
    [
        ("hardened_attack", "denied", "denied", False),
        ("hardened_authorized", "allowed", "allowed", True),
    ],
)
def test_collected_scenario_preserves_backend_hardened_outcomes(
    scenario: str,
    decision: str,
    record_decision: str,
    approval_token_present: bool,
) -> None:
    result = run_collected_scenario(scenario)

    assert result.victim is not None
    assert result.victim.decision == decision
    assert result.victim.decision_source == "backend"
    assert result.victim.backend_event_count == 1
    assert result.collector.record_count == 1
    assert result.collector.records[0].decision == record_decision
    assert result.collector.records[0].attributes["decision_source"] == "backend"
    assert (
        result.collector.records[0].attributes["approval_token_present"] is approval_token_present
    )


def test_collected_scenario_keeps_guard_and_agent_call_labels_distinct() -> None:
    result = run_collected_scenario("defender_only_attack", emit_guard_effect=True)

    assert result.victim is not None
    assert result.victim.decision == "denied"
    assert result.collector.record_count == 2
    assert result.collector.first_sequence_error is None
    assert result.collector.truncated is False
    assert result.collector.stream_end_declared is True
    assert result.collector.declared_record_count == 2
    assert {
        (record.effect_type, record.observer, record.decision)
        for record in result.collector.records
    } == {
        (EFFECT_TYPE, "agent_call_middleware", "denied"),
        ("code.validation", "framework_guard", "denied"),
    }


def test_victim_subprocess_does_not_receive_collector_read_fd() -> None:
    result = run_collected_scenario("vulnerable_attack")

    assert result.victim is not None
    assert result.victim.self_reported_collector_read_endpoint_open is False


def test_fd_identity_probe_detects_held_closed_and_duplicated_endpoints() -> None:
    read_fd, write_fd = os.pipe()
    duplicate_read_fd: int | None = None
    try:
        read_identity = _fd_identity(read_fd)
        write_identity = _fd_identity(write_fd)

        assert _has_fd_identity(read_identity) is True
        assert _has_fd_identity(write_identity) is True

        duplicate_read_fd = os.dup(read_fd)
        os.close(read_fd)
        read_fd = -1
        assert _has_fd_identity(read_identity) is True

        os.close(duplicate_read_fd)
        duplicate_read_fd = None
        assert _has_fd_identity(read_identity) is False
        assert _has_fd_identity(write_identity) is True
    finally:
        if duplicate_read_fd is not None:
            os.close(duplicate_read_fd)
        if read_fd >= 0:
            os.close(read_fd)
        os.close(write_fd)


def test_collector_reports_truncated_tail_from_closed_writer() -> None:
    payload = _frame_line(0, EffectRecord(effect_type="fs.write", target="/tmp/a"))[:-10]

    summary = _collect_payload(payload)

    assert summary.records == ()
    assert summary.first_sequence_error is None
    assert summary.truncated is True


def test_collector_reports_sequence_gap_from_received_bytes() -> None:
    first = EffectRecord(effect_type="fs.write", target="/tmp/a")
    third = EffectRecord(effect_type="net.request", target="service-c")

    summary = _collect_payload(
        _frame_line(0, first) + _frame_line(2, third) + _stream_end_line(3, 2)
    )

    assert summary.records == (first, third)
    assert summary.first_sequence_error == (1, 2)
    assert summary.truncated is False
    assert summary.stream_end_declared is True
    assert summary.declared_record_count == 2


def test_collector_reports_empty_writer_stream_without_truncation() -> None:
    summary = _collect_payload(b"")

    assert summary.records == ()
    assert summary.record_count == 0
    assert summary.first_sequence_error is None
    assert summary.truncated is False
    assert summary.effect_egress_schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2
    assert summary.stream_end_declared is False
    assert summary.declared_record_count is None


def test_collected_scenario_keeps_stream_facts_when_victim_crashes() -> None:
    result = run_collected_scenario(
        "vulnerable_attack",
        victim_fault="partial_tail_crash",
    )

    assert result.victim is None
    assert result.victim_returncode == 3
    assert result.collector.record_count == 1
    assert result.collector.records[0].effect_type == EFFECT_TYPE
    assert result.collector.records[0].decision == "allowed"
    assert result.collector.first_sequence_error is None
    assert result.collector.truncated is True
    assert result.collector.stream_end_declared is False


def test_collected_scenario_reports_missing_stream_end_when_victim_exits_between_frames() -> None:
    result = run_collected_scenario(
        "vulnerable_attack",
        victim_fault="exit_between_frames",
    )

    assert result.victim is None
    assert result.victim_returncode == 5
    assert result.collector.record_count == 1
    assert result.collector.truncated is False
    assert result.collector.stream_end_declared is False
    assert result.collector.declared_record_count is None


def test_collector_accepts_forged_frame_from_writer() -> None:
    forged = EffectRecord(
        effect_type="payment.process",
        target="invoice-42",
        decision="allowed",
        observer="forged_writer",
    )

    summary = _collect_payload(_frame_line(0, forged) + _stream_end_line(1, 1))

    assert summary.records == (forged,)
    assert summary.first_sequence_error is None
    assert summary.truncated is False
    assert summary.stream_end_declared is True
