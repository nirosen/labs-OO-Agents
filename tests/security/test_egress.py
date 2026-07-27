# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for descriptor-backed security-effect egress."""

from __future__ import annotations

import base64
import errno
import io
import json
import os
import re
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ConfigDict

import nooa.security.egress as egress_module
from nooa.runtime.event_manager import EventManager
from nooa.security import (
    DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES,
    EFFECT_EGRESS_COMPLETENESS_SIGNALS,
    EFFECT_EGRESS_FRAME_KEYS,
    EFFECT_EGRESS_RECORD_EVENT_TYPE,
    EFFECT_EGRESS_RECORD_KEYS,
    EFFECT_EGRESS_SCHEMA_VERSION,
    EFFECT_EGRESS_SCHEMA_VERSION_PATTERN,
    EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE,
    MAX_EFFECT_EGRESS_JSON_INTEGER,
    MAX_EFFECT_EGRESS_SEQUENCE,
    EffectEgressCompletenessSignal,
    EffectEgressFrameTooLargeError,
    EffectEgressIncompleteError,
    EffectEgressReadResult,
    EffectEgressSinkFailedError,
    EffectRecord,
    FdEffectSink,
    JsonlEffectSink,
    UnsupportedEffectEgressVersionError,
    install_effect_sink,
    read_effect_egress,
    require_complete_effect_egress,
)

CONFORMANCE_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "effect_egress_conformance_v2.json"
CONFORMANCE_FIXTURE_SCHEMA_VERSION = "nooa-effect-egress-conformance-v2"


def _frame_line(sequence: int, record: EffectRecord) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": EFFECT_EGRESS_SCHEMA_VERSION,
                "sequence": sequence,
                "record": record.model_dump(mode="json"),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _load_conformance_fixture() -> dict[str, Any]:
    return json.loads(CONFORMANCE_FIXTURE_PATH.read_text(encoding="utf-8"))


def test_effect_egress_public_contract_matches_conformance_fixture() -> None:
    fixture = _load_conformance_fixture()

    assert fixture["schema_version"] == CONFORMANCE_FIXTURE_SCHEMA_VERSION
    assert fixture["wire_schema_version"] == EFFECT_EGRESS_SCHEMA_VERSION
    assert fixture["wire_schema_version_pattern"] == EFFECT_EGRESS_SCHEMA_VERSION_PATTERN
    assert (
        fixture["wire_schema_version_pattern_match_mode"]
        == EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE
        == "full"
    )
    assert frozenset(fixture["frame_keys"]) == EFFECT_EGRESS_FRAME_KEYS
    assert fixture["record_event_type"] == EFFECT_EGRESS_RECORD_EVENT_TYPE
    assert frozenset(fixture["record_keys"]) == EFFECT_EGRESS_RECORD_KEYS
    assert tuple(fixture["completeness_signals"]) == EFFECT_EGRESS_COMPLETENESS_SIGNALS
    assert fixture["max_json_integer"] == MAX_EFFECT_EGRESS_JSON_INTEGER
    assert fixture["max_sequence"] == MAX_EFFECT_EGRESS_SEQUENCE
    assert fixture["default_max_frame_bytes"] == DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES
    assert fixture["max_frame_bytes_includes_terminating_lf"] is True
    assert re.fullmatch(EFFECT_EGRESS_SCHEMA_VERSION_PATTERN, EFFECT_EGRESS_SCHEMA_VERSION)
    assert (
        frozenset(
            field.alias or name
            for name, field in egress_module._EffectEgressFrame.model_fields.items()
        )
        == EFFECT_EGRESS_FRAME_KEYS
    )
    assert frozenset(EffectRecord.model_fields) == EFFECT_EGRESS_RECORD_KEYS
    vector_names = [vector["name"] for vector in fixture["vectors"]]
    assert len(vector_names) == len(set(vector_names))
    for vector in fixture["vectors"]:
        assert len({"payload_utf8", "payload_base64"} & vector.keys()) == 1, vector["name"]


def test_effect_egress_completeness_signals_cover_read_result_diagnostics() -> None:
    assert {field.name for field in fields(EffectEgressReadResult)} == {
        "records",
        *EFFECT_EGRESS_COMPLETENESS_SIGNALS,
    }


def _vector_payload_bytes(vector: dict[str, Any]) -> bytes:
    if "payload_utf8" in vector:
        return vector["payload_utf8"].encode("utf-8")
    return base64.b64decode(vector["payload_base64"], validate=True)


@pytest.mark.parametrize(
    "vector",
    _load_conformance_fixture()["vectors"],
    ids=lambda vector: str(vector["name"]),
)
def test_read_effect_egress_matches_conformance_vectors(vector: dict[str, Any]) -> None:
    fixture = _load_conformance_fixture()
    payload = _vector_payload_bytes(vector)
    max_frame_bytes = vector.get("max_frame_bytes", DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES)
    expected = vector["expect"]
    outcome = expected["outcome"]

    if outcome == "ok":
        result = read_effect_egress(io.BytesIO(payload), max_frame_bytes=max_frame_bytes)
        first_sequence_error = expected["first_sequence_error"]
        assert [record.model_dump(mode="json") for record in result.records] == [
            fixture["records"][record_ref] for record_ref in expected["record_refs"]
        ]
        assert result.first_sequence_error == (
            tuple(first_sequence_error) if first_sequence_error is not None else None
        )
        assert result.truncated is expected["truncated"]
        return

    if outcome == "frame_too_large_error":
        with pytest.raises(EffectEgressFrameTooLargeError) as exc_info:
            read_effect_egress(io.BytesIO(payload), max_frame_bytes=max_frame_bytes)
        assert exc_info.value.line_number == expected["line_number"]
        return

    if outcome == "unsupported_version_error":
        with pytest.raises(UnsupportedEffectEgressVersionError) as exc_info:
            read_effect_egress(io.BytesIO(payload), max_frame_bytes=max_frame_bytes)
        assert exc_info.value.line_number == expected["line_number"]
        assert exc_info.value.schema_version == expected["schema_version"]
        return

    if outcome == "invalid_frame_error":
        with pytest.raises(
            ValueError,
            match=rf"^invalid effect egress frame at line {expected['line_number']}$",
        ):
            read_effect_egress(io.BytesIO(payload), max_frame_bytes=max_frame_bytes)
        return

    raise AssertionError(f"unsupported conformance outcome: {outcome}")


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

    assert all(
        line.endswith(b"\n") and not line.endswith(b"\r\n")
        for line in payload.splitlines(keepends=True)
    )
    assert all(line[:-1] == line[:-1].strip() for line in payload.splitlines(keepends=True))
    assert all(frozenset(frame) == EFFECT_EGRESS_FRAME_KEYS for frame in frames)
    assert all(frozenset(frame["record"]) == EFFECT_EGRESS_RECORD_KEYS for frame in frames)
    assert all(frame["schema_version"] == EFFECT_EGRESS_SCHEMA_VERSION for frame in frames)
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


def test_fd_effect_sink_rejects_subclass_only_wire_fields(tmp_path: Path) -> None:
    class ExtendedEffectRecord(EffectRecord):
        extra_field: str

    fd = os.open(tmp_path / "effects.egress", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected V1-compatible EffectRecord"):
            sink(ExtendedEffectRecord(effect_type="fs.write", extra_field="must-not-drop"))
    finally:
        os.close(fd)


def test_fd_effect_sink_rejects_subclass_event_type_drift(tmp_path: Path) -> None:
    class PlainEffectRecord(EffectRecord):
        pass

    fd = os.open(tmp_path / "effects.egress", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected V1-compatible EffectRecord"):
            sink(PlainEffectRecord(effect_type="fs.write"))
    finally:
        os.close(fd)


def test_fd_effect_sink_rejects_unserializable_subclass_fields(tmp_path: Path) -> None:
    class UnserializableEffectRecord(EffectRecord):
        model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

        blob: object

    fd = os.open(tmp_path / "effects.egress", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected V1-compatible EffectRecord"):
            sink(UnserializableEffectRecord(effect_type="fs.write", blob=object()))
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "record_kwargs",
    [
        pytest.param({"attributes": {"score": float("nan")}}, id="attributes-nan"),
        pytest.param({"attributes": {"score": float("inf")}}, id="attributes-inf"),
        pytest.param({"metadata": {"score": float("-inf")}}, id="metadata-neg-inf"),
        pytest.param({"attributes": {"text": "\ud800"}}, id="attributes-lone-surrogate"),
        pytest.param(
            {"attributes": {"count": MAX_EFFECT_EGRESS_JSON_INTEGER + 1}},
            id="attributes-one-over-safe-int",
        ),
        pytest.param(
            {"metadata": {"count": -(MAX_EFFECT_EGRESS_JSON_INTEGER + 1)}},
            id="metadata-one-under-safe-int",
        ),
    ],
)
def test_fd_effect_sink_rejects_v1_invalid_scalar_values_before_write(
    tmp_path: Path,
    record_kwargs: dict[str, Any],
) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected V1-compatible EffectRecord"):
            sink(EffectRecord(effect_type="fs.write", **record_kwargs))
        sink(EffectRecord(effect_type="fs.write", target="/tmp/after-rejection"))
    finally:
        os.close(fd)

    frames = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [frame["sequence"] for frame in frames] == [0]
    assert frames[0]["record"]["target"] == "/tmp/after-rejection"


@pytest.mark.parametrize(
    "metadata_value",
    [
        pytest.param(b"raw", id="bytes"),
        pytest.param((1, 2), id="tuple"),
        pytest.param({1, 2}, id="set"),
        pytest.param(datetime(2026, 1, 1), id="datetime"),
    ],
)
def test_fd_effect_sink_rejects_non_json_native_metadata_before_write(
    tmp_path: Path,
    metadata_value: object,
) -> None:
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected V1-compatible EffectRecord"):
            sink(EffectRecord(effect_type="fs.write", metadata={"value": metadata_value}))
        sink(EffectRecord(effect_type="fs.write", target="/tmp/after-rejection"))
    finally:
        os.close(fd)

    frames = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [frame["sequence"] for frame in frames] == [0]
    assert frames[0]["record"]["target"] == "/tmp/after-rejection"


def test_fd_effect_sink_rejects_cyclic_metadata_before_write(tmp_path: Path) -> None:
    cyclic_metadata: dict[str, Any] = {}
    cyclic_metadata["self"] = cyclic_metadata
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        with pytest.raises(TypeError, match="expected V1-compatible EffectRecord"):
            sink(EffectRecord(effect_type="fs.write", metadata=cyclic_metadata))
        sink(EffectRecord(effect_type="fs.write", target="/tmp/after-rejection"))
    finally:
        os.close(fd)

    frames = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [frame["sequence"] for frame in frames] == [0]
    assert frames[0]["record"]["target"] == "/tmp/after-rejection"


def test_fd_effect_sink_accepts_shared_acyclic_metadata(tmp_path: Path) -> None:
    shared_metadata = {"value": 1}
    path = tmp_path / "effects.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(fd)
        sink(
            EffectRecord(
                effect_type="fs.write",
                metadata={"left": shared_metadata, "right": shared_metadata},
            )
        )
    finally:
        os.close(fd)

    frames = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [frame["sequence"] for frame in frames] == [0]
    assert frames[0]["record"]["metadata"] == {
        "left": {"value": 1},
        "right": {"value": 1},
    }


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


def test_require_complete_effect_egress_returns_original_records_tuple() -> None:
    records = (
        EffectRecord(effect_type="fs.write", target="/tmp/a"),
        EffectRecord(effect_type="net.request", target="service-b"),
    )
    egress = EffectEgressReadResult(records=records)

    assert require_complete_effect_egress(egress) is records


def test_empty_stream_passes_and_is_not_proof_that_no_effects_occurred() -> None:
    egress = EffectEgressReadResult(records=())

    assert require_complete_effect_egress(egress) == ()


@pytest.mark.parametrize(
    ("egress", "expected_reasons"),
    [
        pytest.param(
            EffectEgressReadResult(records=(), truncated=True),
            ("truncated",),
            id="truncated",
        ),
        pytest.param(
            EffectEgressReadResult(records=(), first_sequence_error=(0, 1)),
            ("first_sequence_error",),
            id="sequence-error",
        ),
        pytest.param(
            EffectEgressReadResult(
                records=(),
                first_sequence_error=(1, 3),
                truncated=True,
            ),
            ("first_sequence_error", "truncated"),
            id="both",
        ),
    ],
)
def test_require_complete_effect_egress_raises_structured_error(
    egress: EffectEgressReadResult,
    expected_reasons: tuple[EffectEgressCompletenessSignal, ...],
) -> None:
    with pytest.raises(EffectEgressIncompleteError) as exc_info:
        require_complete_effect_egress(egress)

    error = exc_info.value
    assert error.reasons == expected_reasons
    assert set(error.reasons).issubset(EFFECT_EGRESS_COMPLETENESS_SIGNALS)
    assert error.first_sequence_error == egress.first_sequence_error
    assert error.truncated is egress.truncated
    assert not isinstance(error, ValueError)


def test_require_complete_effect_egress_refuses_mid_stream_attachment() -> None:
    egress = read_effect_egress(
        io.BytesIO(_frame_line(3, EffectRecord(effect_type="fs.write", target="/tmp/a")))
    )

    with pytest.raises(EffectEgressIncompleteError) as exc_info:
        require_complete_effect_egress(egress)

    assert exc_info.value.first_sequence_error == (0, 3)
    assert exc_info.value.reasons == ("first_sequence_error",)


def test_require_complete_effect_egress_rejects_non_read_result() -> None:
    with pytest.raises(TypeError, match="expected EffectEgressReadResult"):
        require_complete_effect_egress("not-a-read-result")  # type: ignore[arg-type]


def test_effect_egress_incomplete_error_rejects_clean_result() -> None:
    with pytest.raises(ValueError, match="requires first_sequence_error or truncated"):
        EffectEgressIncompleteError(EffectEgressReadResult(records=()))


def test_effect_egress_incomplete_error_rejects_non_read_result() -> None:
    with pytest.raises(TypeError, match="expected EffectEgressReadResult"):
        EffectEgressIncompleteError("not-a-read-result")  # type: ignore[arg-type]


def test_require_complete_effect_egress_composes_with_real_fd_stream(tmp_path: Path) -> None:
    first = EffectRecord(effect_type="fs.write", target="/tmp/a")
    second = EffectRecord(effect_type="net.request", target="service-b")
    path = tmp_path / "effects.egress"
    _write_fd_egress(path, [first, second])

    with path.open("rb") as fh:
        records = require_complete_effect_egress(read_effect_egress(fh))

    assert records == (first, second)


def test_require_complete_effect_egress_composes_with_truncated_fd_stream(tmp_path: Path) -> None:
    path = tmp_path / "effects.egress"
    _write_fd_egress(path, [EffectRecord(effect_type="fs.write", target="/tmp/a")])
    with path.open("ab") as fh:
        fh.write(b'{"schema_version":"nooa-effect-egress-v1"')

    with path.open("rb") as fh:
        with pytest.raises(EffectEgressIncompleteError) as exc_info:
            require_complete_effect_egress(read_effect_egress(fh))

    assert exc_info.value.reasons == ("truncated",)


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
    with pytest.raises(ValueError, match=r"^invalid effect egress frame at line 1$"):
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
        match=r"^unsupported effect egress schema_version at line 1",
    ):
        read_effect_egress(io.BytesIO(payload))


def test_read_effect_egress_rejects_oversized_frame() -> None:
    first = _frame_line(0, EffectRecord(effect_type="fs.write", target="/tmp/a"))
    second = _frame_line(
        1,
        EffectRecord(
            effect_type="fs.write",
            target="/tmp/b",
            attributes={"blob": "x" * len(first)},
        ),
    )

    with pytest.raises(
        EffectEgressFrameTooLargeError,
        match=r"frame at line 2 exceeds max_frame_bytes",
    ):
        read_effect_egress(io.BytesIO(first + second), max_frame_bytes=len(first))


def test_read_effect_egress_rejects_empty_complete_frame() -> None:
    with pytest.raises(ValueError, match=r"^invalid effect egress frame at line 1$"):
        read_effect_egress(io.BytesIO(b"\n"))


def test_read_effect_egress_rejects_deeply_nested_json_as_invalid_frame() -> None:
    payload = b"[" * 10_000 + b"]" * 10_000 + b"\n"

    with pytest.raises(ValueError, match=r"^invalid effect egress frame at line 1$"):
        read_effect_egress(io.BytesIO(payload))


def test_read_effect_egress_rejects_text_stream() -> None:
    with pytest.raises(TypeError, match="expected binary stream"):
        read_effect_egress(io.StringIO(""))  # type: ignore[arg-type]
