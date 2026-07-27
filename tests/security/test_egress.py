# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for descriptor-backed security-effect egress."""

from __future__ import annotations

import errno
import io
import json
import os
from pathlib import Path

import pytest

from nooa.runtime.event_manager import EventManager
from nooa.security import (
    EffectEgressFrameTooLargeError,
    EffectEgressSinkFailedError,
    EffectRecord,
    FdEffectSink,
    JsonlEffectSink,
    UnsupportedEffectEgressVersionError,
    install_effect_sink,
    read_effect_egress,
)


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


def _write_fd_egress(path: Path, records: list[EffectRecord]) -> bytes:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        for record in records:
            sink(record)
    finally:
        os.close(fd)
    return path.read_bytes()


def test_fd_effect_sink_round_trips_records_with_monotonic_sequence(tmp_path: Path) -> None:
    payload = _write_fd_egress(
        tmp_path / "effects.egress",
        [
            EffectRecord(effect_type="fs.write", target="/tmp/a"),
            EffectRecord(effect_type="net.request", target="service-b"),
        ],
    )

    frames = [json.loads(line) for line in payload.splitlines()]
    result = read_effect_egress(io.BytesIO(payload))

    assert [frame["sequence"] for frame in frames] == [0, 1]
    assert [record.effect_type for record in result.records] == ["fs.write", "net.request"]
    assert result.first_sequence_error is None
    assert result.truncated is False


def test_fd_effect_sink_rejects_non_effect_records(tmp_path: Path) -> None:
    fd = os.open(tmp_path / "effects.egress", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected EffectRecord"):
            sink("not-an-effect-record")  # type: ignore[arg-type]
    finally:
        os.close(fd)


@pytest.mark.parametrize("fd", [True, "1"])
def test_fd_effect_sink_rejects_non_integer_descriptors(fd: object) -> None:
    with pytest.raises(TypeError, match="expected int fd"):
        FdEffectSink(fd)  # type: ignore[arg-type]


def test_fd_effect_sink_rejects_read_only_descriptor(tmp_path: Path) -> None:
    path = tmp_path / "effects.egress"
    path.write_bytes(b"")
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="requires a writable file descriptor"):
            FdEffectSink(fd)
    finally:
        os.close(fd)


def test_fd_effect_sink_rejects_non_blocking_descriptor() -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.set_blocking(write_fd, False)
        with pytest.raises(ValueError, match="requires a blocking file descriptor"):
            FdEffectSink(write_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_fd_effect_sink_rejects_closed_descriptor(tmp_path: Path) -> None:
    fd = os.open(tmp_path / "effects.egress", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)

    with pytest.raises(OSError):
        FdEffectSink(fd)


def test_fd_effect_sink_rejects_oversized_frame_before_write(tmp_path: Path) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd, max_frame_bytes=1)
        with pytest.raises(EffectEgressFrameTooLargeError, match="max_frame_bytes=1"):
            sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
    finally:
        os.close(fd)

    assert path.read_bytes() == b""


def test_fd_effect_sink_oversized_rejection_does_not_consume_sequence(tmp_path: Path) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd, max_frame_bytes=1024)
        sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
        with pytest.raises(EffectEgressFrameTooLargeError):
            sink(
                EffectRecord(
                    effect_type="fs.write",
                    target="/tmp/b",
                    attributes={"blob": "x" * 2048},
                )
            )
        sink(EffectRecord(effect_type="fs.write", target="/tmp/c"))
    finally:
        os.close(fd)

    frames = [json.loads(line) for line in path.read_bytes().splitlines()]
    with path.open("rb") as fh:
        result = read_effect_egress(fh)
    assert [frame["sequence"] for frame in frames] == [0, 1]
    assert [record.target for record in result.records] == ["/tmp/a", "/tmp/c"]
    assert result.first_sequence_error is None


def test_fd_effect_sink_integrates_with_event_manager_sink_wrapper(tmp_path: Path) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    event_manager = EventManager()
    uninstall = install_effect_sink(event_manager, FdEffectSink(fd))
    try:
        first = EffectRecord(effect_type="fs.write", target="/tmp/a")
        second = EffectRecord(effect_type="net.request", target="service-b")
        event_manager.add(first)
        event_manager.add(second)
    finally:
        uninstall()
        os.close(fd)

    with path.open("rb") as fh:
        result = read_effect_egress(fh)
    assert result.records == (first, second)
    assert [record.tag for record in result.records] == ["1", "2"]
    assert result.first_sequence_error is None
    assert result.truncated is False


def test_fd_effect_sink_keeps_writing_original_descriptor_after_path_replacement(
    tmp_path: Path,
) -> None:
    fd_path = tmp_path / "fd-effects.jsonl"
    moved_fd_path = tmp_path / "fd-effects-original.jsonl"
    fd = os.open(fd_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
        fd_path.rename(moved_fd_path)
        fd_path.write_bytes(b"")
        sink(EffectRecord(effect_type="fs.write", target="/tmp/b"))
    finally:
        os.close(fd)

    with moved_fd_path.open("rb") as fh:
        fd_result = read_effect_egress(fh)
    assert [record.target for record in fd_result.records] == ["/tmp/a", "/tmp/b"]
    assert fd_path.read_bytes() == b""

    jsonl_path = tmp_path / "path-effects.jsonl"
    moved_jsonl_path = tmp_path / "path-effects-original.jsonl"
    jsonl_sink = JsonlEffectSink(jsonl_path)
    jsonl_sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
    jsonl_path.rename(moved_jsonl_path)
    jsonl_path.write_bytes(b"")
    jsonl_sink(EffectRecord(effect_type="fs.write", target="/tmp/b"))

    assert [json.loads(line)["target"] for line in moved_jsonl_path.read_text().splitlines()] == [
        "/tmp/a"
    ]
    assert [json.loads(line)["target"] for line in jsonl_path.read_text().splitlines()] == [
        "/tmp/b"
    ]


def test_read_effect_egress_marks_trailing_partial_frame_truncated() -> None:
    first = EffectRecord(effect_type="fs.write", target="/tmp/a")
    second = EffectRecord(effect_type="net.request", target="service-b")
    payload = _frame_line(0, first) + _frame_line(1, second)[:-10]

    result = read_effect_egress(io.BytesIO(payload))

    assert result.records == (first,)
    assert result.first_sequence_error is None
    assert result.truncated is True


def test_read_effect_egress_reports_first_sequence_gap() -> None:
    first = EffectRecord(effect_type="fs.write", target="/tmp/a")
    third = EffectRecord(effect_type="net.request", target="service-c")

    result = read_effect_egress(io.BytesIO(_frame_line(0, first) + _frame_line(2, third)))

    assert result.records == (first, third)
    assert result.first_sequence_error == (1, 2)
    assert result.truncated is False


def test_fd_effect_sink_surfaces_closed_descriptor_error(tmp_path: Path) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    sink = FdEffectSink(fd)
    sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
    os.close(fd)

    with pytest.raises(OSError):
        sink(EffectRecord(effect_type="fs.write", target="/tmp/b"))

    with path.open("rb") as fh:
        result = read_effect_egress(fh)
    assert [record.target for record in result.records] == ["/tmp/a"]
    assert result.first_sequence_error is None
    assert result.truncated is False


def test_fd_effect_sink_poisoned_after_partial_descriptor_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    sink = FdEffectSink(fd)
    real_write = os.write
    write_count = 0

    def partial_then_fail(write_fd: int, payload: bytes | memoryview) -> int:
        nonlocal write_count
        write_count += 1
        if write_count == 1:
            return real_write(write_fd, payload[:10])
        raise BlockingIOError(errno.EAGAIN, "would block")

    monkeypatch.setattr(os, "write", partial_then_fail)
    try:
        with pytest.raises(BlockingIOError):
            sink(EffectRecord(effect_type="fs.write", target="/tmp/a"))
        with pytest.raises(EffectEgressSinkFailedError, match="unusable"):
            sink(EffectRecord(effect_type="fs.write", target="/tmp/b"))
    finally:
        os.close(fd)

    with path.open("rb") as fh:
        result = read_effect_egress(fh)
    assert result.records == ()
    assert result.truncated is True


def test_read_effect_egress_accepts_valid_frame_forged_by_fd_writer(tmp_path: Path) -> None:
    forged = EffectRecord(
        effect_type="payment.process",
        target="invoice-42",
        decision="allowed",
        observer="forged_writer",
    )
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, _frame_line(0, forged))
    finally:
        os.close(fd)

    with path.open("rb") as fh:
        result = read_effect_egress(fh)

    assert result.records == (forged,)
    assert result.first_sequence_error is None
    assert result.truncated is False


@pytest.mark.parametrize(
    ("schema_version", "sequence"),
    [
        ("nooa-effect-egress-v1", "bad"),
        ("nooa-effect-egress-v1", "1"),
        (True, 0),
        (None, 0),
        ("nooa-receipt-v1", 0),
    ],
)
def test_read_effect_egress_rejects_malformed_complete_frame(
    schema_version: object,
    sequence: object,
) -> None:
    payload = (
        json.dumps(
            {
                "schema_version": schema_version,
                "sequence": sequence,
                "record": EffectRecord(effect_type="fs.write").model_dump(mode="json"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(ValueError, match="invalid effect egress frame at line 1"):
        read_effect_egress(io.BytesIO(payload))


def test_read_effect_egress_rejects_unsupported_schema_version() -> None:
    payload = (
        json.dumps(
            {
                "schema_version": "nooa-effect-egress-v2",
                "sequence": 0,
                "record": EffectRecord(effect_type="fs.write").model_dump(mode="json"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )

    with pytest.raises(
        UnsupportedEffectEgressVersionError,
        match="unsupported effect egress schema_version at line 1",
    ):
        read_effect_egress(io.BytesIO(payload))


def test_read_effect_egress_rejects_oversized_frame() -> None:
    payload = _frame_line(0, EffectRecord(effect_type="fs.write", target="/tmp/a"))

    with pytest.raises(
        EffectEgressFrameTooLargeError,
        match="frame at line 1 exceeds max_frame_bytes",
    ):
        read_effect_egress(io.BytesIO(payload), max_frame_bytes=len(payload) - 1)


def test_read_effect_egress_rejects_empty_complete_frame() -> None:
    with pytest.raises(ValueError, match="invalid effect egress frame at line 1"):
        read_effect_egress(io.BytesIO(b"\n"))


def test_read_effect_egress_rejects_text_stream() -> None:
    with pytest.raises(TypeError, match="expected binary stream"):
        read_effect_egress(io.StringIO(""))  # type: ignore[arg-type]
