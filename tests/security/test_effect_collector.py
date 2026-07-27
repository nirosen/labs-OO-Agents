# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the out-of-process effect collector example."""

from __future__ import annotations

import json
import os

from examples.security_hardening.effect_collector import (
    CollectorSummary,
    _fd_identity,
    _has_fd_identity,
    _spawn_subprocess,
    _terminate_process,
    run_collected_scenario,
)
from examples.security_hardening.identity_approval import EFFECT_TYPE
from nooa.security import EffectRecord


def _frame_line(sequence: int, record: EffectRecord) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "nooa-effect-egress-v1",
                "sequence": sequence,
                "record": record.model_dump(mode="json"),
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
    assert result.collector.first_sequence_error is None
    assert result.collector.truncated is False
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

    summary = _collect_payload(_frame_line(0, first) + _frame_line(2, third))

    assert summary.records == (first, third)
    assert summary.first_sequence_error == (1, 2)
    assert summary.truncated is False


def test_collector_reports_empty_writer_stream_without_truncation() -> None:
    summary = _collect_payload(b"")

    assert summary.records == ()
    assert summary.record_count == 0
    assert summary.first_sequence_error is None
    assert summary.truncated is False


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


def test_collector_accepts_forged_frame_from_writer() -> None:
    forged = EffectRecord(
        effect_type="payment.process",
        target="invoice-42",
        decision="allowed",
        observer="forged_writer",
    )

    summary = _collect_payload(_frame_line(0, forged))

    assert summary.records == (forged,)
    assert summary.first_sequence_error is None
    assert summary.truncated is False
