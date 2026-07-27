# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for checked JSON vectors for public security transport shapes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from nooa.security import (
    MAX_EFFECT_EGRESS_JSON_INTEGER,
    DetectorInput,
    SecurityFinding,
    SecurityReceipt,
)

TRANSPORT_CONFORMANCE_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "security_transport_conformance_v1.json"
)
TRANSPORT_CONFORMANCE_FIXTURE_SCHEMA_VERSION = "nooa-security-transport-conformance-v1"
SURFACE_GUIDE_PATH = Path(__file__).resolve().parents[2] / "examples" / "security_hardening" / "SURFACE.md"
TRANSPORT_MODELS: dict[str, type[BaseModel]] = {
    "SecurityReceipt": SecurityReceipt,
    "SecurityFinding": SecurityFinding,
    "DetectorInput": DetectorInput,
}


def _load_fixture() -> dict[str, Any]:
    return json.loads(TRANSPORT_CONFORMANCE_FIXTURE_PATH.read_text(encoding="utf-8"))


def _vector_payload(vector: dict[str, Any]) -> bytes:
    return vector["payload_utf8"].encode("utf-8")


def test_transport_conformance_fixture_matches_public_models() -> None:
    fixture = _load_fixture()

    assert fixture["schema_version"] == TRANSPORT_CONFORMANCE_FIXTURE_SCHEMA_VERSION
    assert tuple(fixture["types"]) == tuple(TRANSPORT_MODELS)

    for type_name, model_cls in TRANSPORT_MODELS.items():
        type_fixture = fixture["types"][type_name]
        assert type_fixture["keys"] == list(model_cls.model_fields)
        assert model_cls.model_fields["schema_version"].default == type_fixture["wire_schema_version"]

        vector_names = [vector["name"] for vector in type_fixture["vectors"]]
        assert vector_names == ["defaults", "fully_populated", "payload_encoding"]
        assert len(vector_names) == len(set(vector_names))

        has_non_ascii_encoding_case = False
        for vector in type_fixture["vectors"]:
            payload = _vector_payload(vector)
            parsed_payload = json.loads(payload)
            compact_utf8 = json.dumps(parsed_payload, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
            compact_ascii = json.dumps(parsed_payload, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            )

            assert b"\n" not in payload
            assert payload == compact_utf8
            has_non_ascii_encoding_case = has_non_ascii_encoding_case or (
                compact_utf8 != compact_ascii
            )
            assert list(parsed_payload) == type_fixture["keys"]
            assert frozenset(parsed_payload) == frozenset(model_cls.model_fields)
            assert parsed_payload["schema_version"] == type_fixture["wire_schema_version"]

        assert has_non_ascii_encoding_case is True

    for type_name in ("SecurityReceipt", "SecurityFinding", "DetectorInput"):
        encoding_kwargs = fixture["types"][type_name]["vectors"][2]["construction_kwargs"]
        assert encoding_kwargs["attributes"] == {
            "ratio": 0.1,
            "big": MAX_EFFECT_EGRESS_JSON_INTEGER,
            "nested": {"label": "caf\u00e9-\u6f22"},
        }


def test_public_security_transports_match_checked_vectors() -> None:
    fixture = _load_fixture()

    for type_name, model_cls in TRANSPORT_MODELS.items():
        for vector in fixture["types"][type_name]["vectors"]:
            model = model_cls.model_validate(vector["construction_kwargs"])
            payload = _vector_payload(vector)

            assert model.model_dump_json().encode("utf-8") == payload
            assert model_cls.model_validate_json(payload) == model


def test_surface_guide_points_to_transport_conformance_fixture() -> None:
    guide = SURFACE_GUIDE_PATH.read_text(encoding="utf-8")

    assert "`tests/security/fixtures/security_transport_conformance_v1.json`" in guide
