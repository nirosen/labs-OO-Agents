# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for checked finding-bundle transport reference vectors."""

from __future__ import annotations

import base64
import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from nooa.security import (
    DEFAULT_FINDING_BUNDLE_MAX_BYTES,
    DEFAULT_FINDING_BUNDLE_MAX_FINDINGS,
    FINDING_BUNDLE_COMPLETENESS_SIGNALS,
    FINDING_BUNDLE_KEYS,
    FINDING_BUNDLE_SCHEMA_VERSION,
    FINDING_BUNDLE_SCHEMA_VERSION_PATTERN,
    FINDING_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE,
    MAX_FINDING_BUNDLE_JSON_INTEGER,
    FindingBundle,
    FindingBundleInputTooLargeError,
    SecurityFinding,
    UnsupportedFindingBundleVersionError,
    finding_bundle_completeness_signals,
    read_finding_bundle,
    write_finding_bundle,
)

CONFORMANCE_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "finding_bundle_conformance_v1.json"
)
CONFORMANCE_FIXTURE_SCHEMA_VERSION = "nooa-finding-bundle-conformance-v1"
SURFACE_GUIDE_PATH = Path(__file__).resolve().parents[2] / "examples" / "security_hardening" / "SURFACE.md"


def _load_fixture() -> dict[str, Any]:
    return json.loads(CONFORMANCE_FIXTURE_PATH.read_text(encoding="utf-8"))


def _fixture_findings() -> dict[str, SecurityFinding]:
    fixture = _load_fixture()
    return {
        name: SecurityFinding.model_validate(payload)
        for name, payload in fixture["findings"].items()
    }


def _vector_payload(vector: dict[str, Any]) -> bytes:
    if "payload_utf8" in vector:
        return vector["payload_utf8"].encode("utf-8")
    return base64.b64decode(vector["payload_base64"], validate=True)


def _reader_kwargs(vector: dict[str, Any]) -> dict[str, int]:
    return {
        key: vector[key]
        for key in ("max_bundle_bytes", "max_findings")
        if key in vector
    }


def _bundle_from_vector(vector: dict[str, Any]) -> FindingBundle:
    findings = _fixture_findings()
    return FindingBundle.model_validate(
        {
            **vector["bundle_kwargs"],
            "findings": [findings[finding_ref] for finding_ref in vector["finding_refs"]],
        }
    )


def test_finding_bundle_conformance_fixture_matches_public_contract() -> None:
    fixture = _load_fixture()

    assert fixture["schema_version"] == CONFORMANCE_FIXTURE_SCHEMA_VERSION
    assert fixture["wire_schema_version"] == FINDING_BUNDLE_SCHEMA_VERSION
    assert fixture["wire_schema_version_pattern"] == FINDING_BUNDLE_SCHEMA_VERSION_PATTERN
    assert (
        fixture["wire_schema_version_pattern_match_mode"]
        == FINDING_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE
        == "full"
    )
    assert fixture["bundle_keys"] == list(FindingBundle.model_fields)
    assert frozenset(fixture["bundle_keys"]) == FINDING_BUNDLE_KEYS
    assert fixture["finding_keys"] == list(SecurityFinding.model_fields)
    assert tuple(fixture["completeness_signals"]) == FINDING_BUNDLE_COMPLETENESS_SIGNALS
    assert fixture["max_json_integer"] == MAX_FINDING_BUNDLE_JSON_INTEGER
    assert fixture["default_max_bundle_bytes"] == DEFAULT_FINDING_BUNDLE_MAX_BYTES
    assert fixture["default_max_findings"] == DEFAULT_FINDING_BUNDLE_MAX_FINDINGS
    assert fixture["max_bundle_bytes_includes_terminating_lf"] is True
    assert re.fullmatch(FINDING_BUNDLE_SCHEMA_VERSION_PATTERN, FINDING_BUNDLE_SCHEMA_VERSION)

    writer_names = [vector["name"] for vector in fixture["writer_vectors"]]
    reader_names = [vector["name"] for vector in fixture["reader_vectors"]]
    assert len(writer_names) == len(set(writer_names))
    assert len(reader_names) == len(set(reader_names))
    assert set(writer_names).isdisjoint(reader_names)
    for vector in [*fixture["writer_vectors"], *fixture["reader_vectors"]]:
        assert len({"payload_utf8", "payload_base64"} & vector.keys()) == 1, vector["name"]

    has_non_ascii_encoding_case = False
    for vector in fixture["writer_vectors"]:
        assert "payload_utf8" in vector
        payload = _vector_payload(vector)
        assert payload.endswith(b"\n")
        assert b"\r\n" not in payload
        parsed_payload = json.loads(payload[:-1])
        compact_utf8 = json.dumps(parsed_payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        compact_ascii = json.dumps(parsed_payload, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )

        assert payload[:-1] == compact_utf8
        has_non_ascii_encoding_case = has_non_ascii_encoding_case or (
            compact_utf8 != compact_ascii
        )
        assert list(parsed_payload) == fixture["bundle_keys"]
        assert frozenset(parsed_payload) == FINDING_BUNDLE_KEYS
        assert parsed_payload["schema_version"] == FINDING_BUNDLE_SCHEMA_VERSION
        for finding in parsed_payload["findings"]:
            assert list(finding) == fixture["finding_keys"]
    assert has_non_ascii_encoding_case is True
    assert any(
        vector["expect"]["outcome"] == "ok"
        and vector.get("max_bundle_bytes") == len(_vector_payload(vector))
        for vector in fixture["reader_vectors"]
    )
    assert any(
        vector["expect"]["outcome"] == "input_too_large_error"
        and vector["expect"]["limit_name"] == "max_bundle_bytes"
        and vector.get("max_bundle_bytes") == len(_vector_payload(vector)) - 1
        for vector in fixture["reader_vectors"]
    )
    assert any(
        vector["expect"]["outcome"] == "input_too_large_error"
        and vector["expect"]["limit_name"] == "max_findings"
        for vector in fixture["reader_vectors"]
    )
    assert any(
        vector["expect"]["outcome"] == "ok"
        and "max_findings" in vector
        and vector["max_findings"] == len(vector["finding_refs"])
        for vector in fixture["reader_vectors"]
    )
    assert any(
        vector["expect"]["outcome"] == "ok"
        and vector["expect"].get("remaining_payload_utf8")
        for vector in fixture["reader_vectors"]
    )
    assert any(
        "payload_base64" in vector
        and _vector_payload(vector).startswith(b'{"schema_version"')
        and b"\xff" in _vector_payload(vector)
        for vector in fixture["reader_vectors"]
    )
    assert {"extra_key", "nan_constant", "overflow_float", "invalid_utf8"} <= set(reader_names)
    version_vectors = [
        vector for vector in fixture["reader_vectors"] if "schema_version" in vector["expect"]
    ]
    assert {
        vector["name"] for vector in version_vectors
    } >= {
        "future_version",
        "future_version_double_digit",
        "zero_version_is_invalid",
        "prerelease_version_is_invalid",
        "prefixed_version_is_invalid",
        "trailing_newline_version_is_invalid",
        "non_string_version_is_invalid",
    }
    for vector in version_vectors:
        expected = vector["expect"]
        schema_version = expected["schema_version"]
        payload_value = json.loads(_vector_payload(vector)[:-1].decode("utf-8"))
        assert payload_value["schema_version"] == schema_version
        fullmatch = (
            isinstance(schema_version, str)
            and re.fullmatch(FINDING_BUNDLE_SCHEMA_VERSION_PATTERN, schema_version) is not None
        )
        if expected["outcome"] == "unsupported_version_error":
            assert fullmatch is True
            assert schema_version != FINDING_BUNDLE_SCHEMA_VERSION
        else:
            assert expected["outcome"] == "invalid_document_error"
            assert fullmatch is False

    trailing_newline_version = next(
        vector["expect"]["schema_version"]
        for vector in version_vectors
        if vector["name"] == "trailing_newline_version_is_invalid"
    )
    assert isinstance(trailing_newline_version, str)
    assert re.match(
        rf"^{FINDING_BUNDLE_SCHEMA_VERSION_PATTERN}$",
        trailing_newline_version,
    )
    assert not re.fullmatch(FINDING_BUNDLE_SCHEMA_VERSION_PATTERN, trailing_newline_version)

    assert fixture["findings"]["finding_payload_encoding"]["attributes"] == {
        "ratio": 0.1,
        "big": MAX_FINDING_BUNDLE_JSON_INTEGER,
        "nested": {"label": "caf\u00e9-\u6f22"},
    }


@pytest.mark.parametrize(
    "vector",
    _load_fixture()["writer_vectors"],
    ids=lambda vector: str(vector["name"]),
)
def test_write_finding_bundle_matches_conformance_vectors(vector: dict[str, Any]) -> None:
    bundle = _bundle_from_vector(vector)
    payload = _vector_payload(vector)
    fh = io.BytesIO()

    write_finding_bundle(fh, bundle)

    assert fh.getvalue() == payload
    result = read_finding_bundle(io.BytesIO(fh.getvalue()))
    assert result.bundle == bundle
    assert finding_bundle_completeness_signals(result) == tuple(
        vector["expect"]["completeness_signals"]
    )

    exact_budget_fh = io.BytesIO()
    write_finding_bundle(exact_budget_fh, bundle, max_bundle_bytes=len(payload))
    assert exact_budget_fh.getvalue() == payload
    with pytest.raises(FindingBundleInputTooLargeError) as bytes_exc:
        write_finding_bundle(io.BytesIO(), bundle, max_bundle_bytes=len(payload) - 1)
    assert bytes_exc.value.limit_name == "max_bundle_bytes"
    assert bytes_exc.value.limit_value == len(payload) - 1

    if len(bundle.findings) > 1:
        with pytest.raises(FindingBundleInputTooLargeError) as findings_exc:
            write_finding_bundle(
                io.BytesIO(),
                bundle,
                max_findings=len(bundle.findings) - 1,
            )
        assert findings_exc.value.limit_name == "max_findings"
        assert findings_exc.value.limit_value == len(bundle.findings) - 1


@pytest.mark.parametrize(
    "vector",
    _load_fixture()["reader_vectors"],
    ids=lambda vector: str(vector["name"]),
)
def test_read_finding_bundle_matches_conformance_vectors(vector: dict[str, Any]) -> None:
    payload = _vector_payload(vector)
    kwargs = _reader_kwargs(vector)
    expected = vector["expect"]
    outcome = expected["outcome"]

    if outcome == "ok":
        fh = io.BytesIO(payload)
        result = read_finding_bundle(fh, **kwargs)
        expected_bundle = _bundle_from_vector(vector) if expected["bundle_present"] else None
        assert result.bundle == expected_bundle
        assert result.truncated is expected["truncated"]
        assert finding_bundle_completeness_signals(result) == tuple(
            expected["completeness_signals"]
        )
        assert fh.read() == expected.get("remaining_payload_utf8", "").encode("utf-8")
        return

    if outcome == "unsupported_version_error":
        with pytest.raises(UnsupportedFindingBundleVersionError) as exc_info:
            read_finding_bundle(io.BytesIO(payload), **kwargs)
        assert exc_info.value.schema_version == expected["schema_version"]
        return

    if outcome == "invalid_document_error":
        with pytest.raises(ValueError, match="^invalid finding bundle document$"):
            read_finding_bundle(io.BytesIO(payload), **kwargs)
        return

    if outcome == "input_too_large_error":
        with pytest.raises(FindingBundleInputTooLargeError) as exc_info:
            read_finding_bundle(io.BytesIO(payload), **kwargs)
        assert exc_info.value.limit_name == expected["limit_name"]
        assert exc_info.value.limit_value == expected["limit_value"]
        return

    raise AssertionError(f"unsupported finding-bundle conformance outcome: {outcome}")


def test_surface_guide_points_to_finding_bundle_conformance_fixture() -> None:
    guide = SURFACE_GUIDE_PATH.read_text(encoding="utf-8")

    assert "`tests/security/fixtures/finding_bundle_conformance_v1.json`" in guide
