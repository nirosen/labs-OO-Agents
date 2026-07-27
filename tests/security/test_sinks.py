# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for composable security-effect sinks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nooa.context_blocks import EventBase
from nooa.events import Task
from nooa.runtime.context_vars import _pop_agent_call_id, _push_agent_call_id
from nooa.runtime.event_backend import EventBackend, InMemoryBackend
from nooa.runtime.event_manager import EventManager
from nooa.security import (
    EffectRecord,
    EffectRecordSinkBackend,
    JsonlEffectSink,
    install_effect_sink,
)


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_jsonl_effect_sink_appends_one_record_per_line(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "effects.jsonl"
    sink = JsonlEffectSink(path)

    sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
    sink(EffectRecord(effect_type="net.request", target="service-b"))

    rows = _read_jsonl(path)
    assert [row["effect_type"] for row in rows] == ["fs.write", "net.request"]
    assert [row["target"] for row in rows] == ["/tmp/a", "service-b"]


def test_jsonl_effect_sink_rejects_non_effect_records(tmp_path: Path) -> None:
    sink = JsonlEffectSink(tmp_path / "effects.jsonl")

    with pytest.raises(TypeError, match="expected EffectRecord"):
        sink("not-an-effect-record")  # type: ignore[arg-type]


def test_effect_record_sink_backend_copies_fully_tagged_records(tmp_path: Path) -> None:
    path = tmp_path / "effects.jsonl"
    backend = EffectRecordSinkBackend(InMemoryBackend(), JsonlEffectSink(path))
    event_manager = EventManager(backend=backend)
    record = EffectRecord(effect_type="fs.write", target="/tmp/report.txt")

    _push_agent_call_id("agent-call-1")
    try:
        tag = event_manager.add(record)
    finally:
        _pop_agent_call_id()

    rows = _read_jsonl(path)
    assert isinstance(backend, EventBackend)
    assert rows == [record.model_dump(mode="json")]
    assert rows[0]["tag"] == tag
    assert rows[0]["metadata"] == {"call_id": "agent-call-1"}
    assert event_manager.get(tag) is record


def test_effect_record_sink_backend_ignores_non_effect_events(tmp_path: Path) -> None:
    path = tmp_path / "effects.jsonl"
    event_manager = EventManager(
        backend=EffectRecordSinkBackend(InMemoryBackend(), JsonlEffectSink(path))
    )

    event_manager.add(Task(prompt="hello"))

    assert not path.exists()


def test_effect_record_sink_backend_propagates_sink_errors_before_local_store() -> None:
    inner = InMemoryBackend()

    def sink(_record: EffectRecord) -> None:
        raise OSError("audit sink unavailable")

    event_manager = EventManager(backend=EffectRecordSinkBackend(inner, sink))

    with pytest.raises(OSError, match="audit sink unavailable"):
        event_manager.add(EffectRecord(effect_type="fs.write", target="/tmp/report.txt"))

    assert len(inner) == 0


def test_effect_record_sink_backend_can_leave_sink_ahead_if_inner_store_fails(
    tmp_path: Path,
) -> None:
    path = tmp_path / "effects.jsonl"

    class _FailingStoreBackend(InMemoryBackend):
        def store(self, tag: str, event: EventBase) -> None:
            raise OSError("local backend unavailable")

    inner = _FailingStoreBackend()
    event_manager = EventManager(
        backend=EffectRecordSinkBackend(inner, JsonlEffectSink(path))
    )

    with pytest.raises(OSError, match="local backend unavailable"):
        event_manager.add(EffectRecord(effect_type="fs.write", target="/tmp/report.txt"))

    assert len(inner) == 0
    assert [row["effect_type"] for row in _read_jsonl(path)] == ["fs.write"]


def test_install_effect_sink_wraps_existing_backend_and_restores_it(tmp_path: Path) -> None:
    path = tmp_path / "effects.jsonl"
    event_manager = EventManager()
    original_backend = event_manager.get_backend()

    uninstall = install_effect_sink(event_manager, JsonlEffectSink(path))
    try:
        assert event_manager.get_backend() is not original_backend
        event_manager.add(EffectRecord(effect_type="fs.write", target="/tmp/a"))
    finally:
        uninstall()

    assert event_manager.get_backend() is original_backend
    event_manager.add(EffectRecord(effect_type="fs.write", target="/tmp/b"))
    assert [row["target"] for row in _read_jsonl(path)] == ["/tmp/a"]
