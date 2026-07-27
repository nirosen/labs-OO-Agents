# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for checked effect-egress producer reference vectors."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from nooa.security import (
    EFFECT_EGRESS_FRAME_KEYS,
    EFFECT_EGRESS_RECORD_EVENT_TYPE,
    EFFECT_EGRESS_RECORD_KEYS,
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
    EFFECT_EGRESS_STREAM_END_EVENT_TYPE,
    EFFECT_EGRESS_STREAM_END_FRAME_KEYS,
    EFFECT_EGRESS_STREAM_END_KEYS,
    EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS,
    MAX_EFFECT_EGRESS_JSON_INTEGER,
    EffectEgressSchemaVersion,
    EffectRecord,
    FdEffectSink,
    effect_egress_completeness_signals,
    read_effect_egress,
)

PRODUCER_CONFORMANCE_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "effect_egress_producer_conformance_v1.json"
)
PRODUCER_CONFORMANCE_FIXTURE_SCHEMA_VERSION = "nooa-effect-egress-producer-conformance-v1"
SURFACE_GUIDE_PATH = Path(__file__).resolve().parents[2] / "examples" / "security_hardening" / "SURFACE.md"


def _load_fixture() -> dict[str, Any]:
    return json.loads(PRODUCER_CONFORMANCE_FIXTURE_PATH.read_text(encoding="utf-8"))


def _fixture_records() -> dict[str, EffectRecord]:
    fixture = _load_fixture()
    return {
        name: EffectRecord.model_validate(payload)
        for name, payload in fixture["records"].items()
    }


def _vector_payload(vector: dict[str, Any]) -> bytes:
    return vector["payload_utf8"].encode("utf-8")


def _write_vector(tmp_path: Path, vector: dict[str, Any]) -> bytes:
    path = tmp_path / f"{vector['name']}.egress"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        sink = FdEffectSink(
            fd,
            schema_version=cast(EffectEgressSchemaVersion, vector["schema_version"]),
        )
        records = _fixture_records()
        for record_ref in vector["record_refs"]:
            sink(records[record_ref])
        if vector["close"]:
            sink.close()
    finally:
        os.close(fd)
    return path.read_bytes()


def test_producer_conformance_fixture_matches_public_contract() -> None:
    fixture = _load_fixture()

    assert fixture["schema_version"] == PRODUCER_CONFORMANCE_FIXTURE_SCHEMA_VERSION
    assert tuple(fixture["wire_schema_versions"]) == EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS
    assert frozenset(fixture["record_frame_keys"]) == EFFECT_EGRESS_FRAME_KEYS
    assert frozenset(fixture["stream_end_frame_keys"]) == EFFECT_EGRESS_STREAM_END_FRAME_KEYS
    assert fixture["record_event_type"] == EFFECT_EGRESS_RECORD_EVENT_TYPE
    assert frozenset(fixture["record_keys"]) == EFFECT_EGRESS_RECORD_KEYS
    assert fixture["stream_end_event_type"] == EFFECT_EGRESS_STREAM_END_EVENT_TYPE
    assert frozenset(fixture["stream_end_keys"]) == EFFECT_EGRESS_STREAM_END_KEYS
    assert fixture["records"]["record_payload_encoding"]["metadata"] == {
        "source": {"kind": "fixture", "rank": 1}
    }
    assert fixture["records"]["record_payload_encoding"]["attributes"] == {
        "ratio": 0.1,
        "big": MAX_EFFECT_EGRESS_JSON_INTEGER,
        "nested": {"label": "caf\u00e9-\u6f22"},
    }

    vector_names = [vector["name"] for vector in fixture["vectors"]]
    assert len(vector_names) == len(set(vector_names))
    has_non_ascii_encoding_case = False
    for vector in fixture["vectors"]:
        assert vector["schema_version"] in EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS
        assert isinstance(vector["close"], bool)
        assert all(record_ref in fixture["records"] for record_ref in vector["record_refs"])

        payload = _vector_payload(vector)
        assert payload.endswith(b"\n")
        assert b"\r\n" not in payload
        frames = [json.loads(line) for line in payload.splitlines()]
        expected_frame_count = len(vector["record_refs"])
        if vector["schema_version"] == EFFECT_EGRESS_SCHEMA_VERSION_V2 and vector["close"]:
            expected_frame_count += 1
        assert len(frames) == expected_frame_count

        for sequence, (line, frame) in enumerate(zip(payload.splitlines(), frames, strict=True)):
            compact_utf8 = json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            compact_ascii = json.dumps(frame, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )
            assert line == compact_utf8
            has_non_ascii_encoding_case = has_non_ascii_encoding_case or (
                compact_utf8 != compact_ascii
            )
            assert frame["sequence"] == sequence
            if "record" in frame:
                assert list(frame) == fixture["record_frame_keys"]
                assert frozenset(frame) == EFFECT_EGRESS_FRAME_KEYS
                assert list(frame["record"]) == fixture["record_keys"]
                assert frozenset(frame["record"]) == EFFECT_EGRESS_RECORD_KEYS
            else:
                assert list(frame) == fixture["stream_end_frame_keys"]
                assert frozenset(frame) == EFFECT_EGRESS_STREAM_END_FRAME_KEYS
                assert list(frame["stream_end"]) == fixture["stream_end_keys"]
                assert frozenset(frame["stream_end"]) == EFFECT_EGRESS_STREAM_END_KEYS
    assert has_non_ascii_encoding_case is True


def test_surface_guide_points_to_producer_conformance_fixture() -> None:
    guide = SURFACE_GUIDE_PATH.read_text(encoding="utf-8")

    assert "`tests/security/fixtures/effect_egress_producer_conformance_v1.json`" in guide


@pytest.mark.parametrize(
    "vector",
    _load_fixture()["vectors"],
    ids=lambda vector: str(vector["name"]),
)
def test_fd_effect_sink_matches_producer_conformance_vectors(
    tmp_path: Path,
    vector: dict[str, Any],
) -> None:
    assert _write_vector(tmp_path, vector) == _vector_payload(vector)


@pytest.mark.parametrize(
    "vector",
    _load_fixture()["vectors"],
    ids=lambda vector: str(vector["name"]),
)
def test_producer_conformance_vectors_round_trip_through_reader(vector: dict[str, Any]) -> None:
    records = _fixture_records()
    schema_version = cast(EffectEgressSchemaVersion, vector["schema_version"])
    result = read_effect_egress(
        io.BytesIO(_vector_payload(vector)),
        expected_schema_version=(
            EFFECT_EGRESS_SCHEMA_VERSION_V2
            if schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2
            else None
        ),
    )

    assert result.schema_version == schema_version
    assert result.records == tuple(records[record_ref] for record_ref in vector["record_refs"])
    assert result.first_sequence_error is None
    assert result.truncated is False
    if schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2 and vector["close"]:
        assert result.stream_end_declared is True
        assert result.declared_record_count == len(vector["record_refs"])
        assert effect_egress_completeness_signals(result) == ()
    else:
        assert result.stream_end_declared is False
        assert result.declared_record_count is None
