# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for security finding transport."""

from __future__ import annotations

import json
import re
from io import BytesIO, StringIO

import pytest
from pydantic import ValidationError

from nooa.security import (
    FINDING_BUNDLE_COMPLETENESS_SIGNALS,
    FINDING_BUNDLE_KEYS,
    FINDING_BUNDLE_SCHEMA_VERSION,
    FINDING_BUNDLE_SCHEMA_VERSION_PATTERN,
    FINDING_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE,
    FINDING_SCOPE_SIGNALS,
    MAX_FINDING_BUNDLE_JSON_INTEGER,
    FindingBundle,
    FindingBundleIncompleteError,
    FindingBundleInputTooLargeError,
    FindingBundleReadResult,
    FindingScopeError,
    FindingScopeValidation,
    SecurityFinding,
    UnsupportedFindingBundleVersionError,
    finding_bundle_completeness_signals,
    finding_scope_signals,
    read_finding_bundle,
    require_complete_finding_bundle,
    require_valid_finding_scope,
    validate_finding_scope,
    write_finding_bundle,
)


def _finding(**updates: object) -> SecurityFinding:
    fields: dict[str, object] = {
        "finding_id": "finding-1",
        "finding_type": "authorization.missing_receipt",
        "producer": "identity_policy.v1",
        "run_id": "run-20260727-identity-1",
        "target": "invoice-42",
        "evidence_refs": ("effect-event-1", "receipt-audit-1"),
        "attributes": {"rule": "require_approval_token", "matched": True},
    }
    fields.update(updates)
    return SecurityFinding.model_validate(fields)


def _bundle(**updates: object) -> FindingBundle:
    fields = {
        "producer": "identity_policy.v1",
        "findings": (_finding(),),
    }
    fields.update(updates)
    return FindingBundle.model_validate(fields)


def _bundle_line(bundle: FindingBundle) -> bytes:
    return (bundle.model_dump_json() + "\n").encode("utf-8")


def test_security_finding_is_strict_json_transport() -> None:
    finding = _finding()

    assert set(finding.model_dump(mode="json")) == {
        "schema_version",
        "finding_id",
        "finding_type",
        "producer",
        "run_id",
        "target",
        "evidence_refs",
        "attributes",
    }
    assert finding.schema_version == "nooa-finding-v1"
    assert finding.finding_id == "finding-1"
    assert finding.finding_type == "authorization.missing_receipt"
    assert finding.producer == "identity_policy.v1"
    assert finding.run_id == "run-20260727-identity-1"
    assert finding.target == "invoice-42"
    assert finding.evidence_refs == ("effect-event-1", "receipt-audit-1")
    assert finding.attributes == {"rule": "require_approval_token", "matched": True}

    with pytest.raises(ValidationError):
        _finding(typo="not-allowed")
    with pytest.raises(ValidationError):
        _finding(schema_version="nooa-finding-v2")
    with pytest.raises(ValidationError):
        _finding(attributes={"unsafe": object()})
    with pytest.raises(ValidationError):
        _finding(evidence_refs=("effect-event-1", ""))


def test_security_finding_defaults_round_trip_and_freeze_field_bindings() -> None:
    finding = SecurityFinding(
        finding_id="finding-2",
        finding_type="prompt_injection.suspected",
        producer="prompt_detector.v1",
    )

    assert finding.target == ""
    assert finding.run_id == ""
    assert finding.evidence_refs == ()
    assert finding.attributes == {}
    assert SecurityFinding.model_validate_json(finding.model_dump_json()) == finding

    with pytest.raises(ValidationError):
        finding.finding_id = "finding-3"


def test_security_finding_evidence_refs_are_opaque_ids() -> None:
    finding = _finding(
        evidence_refs=("effect-event-1", "receipt-audit-1", "siem-event-9"),
    )

    assert finding.evidence_refs == ("effect-event-1", "receipt-audit-1", "siem-event-9")


def test_finding_bundle_is_strict_transport_and_publishes_version_contract() -> None:
    bundle = _bundle()

    assert set(bundle.model_dump(mode="json")) == FINDING_BUNDLE_KEYS
    assert bundle.schema_version == FINDING_BUNDLE_SCHEMA_VERSION
    assert bundle.producer == "identity_policy.v1"
    assert bundle.findings == (_finding(),)
    assert FINDING_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE == "full"
    assert re.fullmatch(FINDING_BUNDLE_SCHEMA_VERSION_PATTERN, bundle.schema_version)

    with pytest.raises(ValidationError):
        _bundle(typo="not-allowed")
    with pytest.raises(ValidationError):
        _bundle(schema_version="nooa-finding-bundle-v2")


def test_finding_bundle_writer_reader_round_trip_and_gate() -> None:
    bundle = _bundle()
    fh = BytesIO()

    write_finding_bundle(fh, bundle)

    assert fh.getvalue().endswith(b"\n")
    fh.seek(0)
    result = read_finding_bundle(fh)

    assert result == FindingBundleReadResult(bundle=bundle)
    assert finding_bundle_completeness_signals(result) == ()
    assert require_complete_finding_bundle(result) == bundle


def test_read_finding_bundle_consumes_only_one_document_line() -> None:
    first = _bundle()
    second = _bundle(
        producer="prompt_detector.v1",
        findings=(_finding(finding_id="finding-2", producer="prompt_detector.v1"),),
    )
    fh = BytesIO(_bundle_line(first) + _bundle_line(second))

    assert require_complete_finding_bundle(read_finding_bundle(fh)) == first
    assert require_complete_finding_bundle(read_finding_bundle(fh)) == second
    assert fh.read() == b""


def test_finding_bundle_completeness_signals_cover_truncation_only() -> None:
    truncated = read_finding_bundle(BytesIO(_bundle().model_dump_json().encode("utf-8")))

    assert FINDING_BUNDLE_COMPLETENESS_SIGNALS == ("truncated",)
    assert truncated.bundle is None
    assert finding_bundle_completeness_signals(truncated) == ("truncated",)

    with pytest.raises(FindingBundleIncompleteError) as exc_info:
        require_complete_finding_bundle(truncated)

    error = exc_info.value
    assert error.reasons == ("truncated",)
    assert error.producer is None
    assert error.finding_count is None
    assert not isinstance(error, ValueError)


def test_read_finding_bundle_keeps_malformed_and_future_versions_distinct() -> None:
    with pytest.raises(ValueError, match="invalid finding bundle document"):
        read_finding_bundle(BytesIO(b"{}\n"))

    future_payload = {
        "schema_version": "nooa-finding-bundle-v2",
        "producer": "",
        "findings": [],
    }
    with pytest.raises(UnsupportedFindingBundleVersionError) as exc_info:
        read_finding_bundle(
            BytesIO((json.dumps(future_payload, separators=(",", ":")) + "\n").encode("utf-8"))
        )

    assert exc_info.value.schema_version == "nooa-finding-bundle-v2"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"\xef\xbb\xbf" + _bundle_line(_bundle()), id="bom"),
        pytest.param(b" " + _bundle_line(_bundle()), id="outer-whitespace"),
        pytest.param(b"[]\n", id="non-dict"),
        pytest.param(b'{"schema_version":"nooa-finding-bundle-v1"}\n', id="missing-keys"),
        pytest.param(
            (
                _bundle().model_dump_json()[:-1]
                + ',"extra":"not-allowed"}\n'
            ).encode("utf-8"),
            id="extra-key",
        ),
        pytest.param(
            b'{"schema_version":"nooa-finding-bundle-v1","producer":"a",'
            b'"producer":"b","findings":[]}\n',
            id="duplicate-key",
        ),
        pytest.param(
            b'{"schema_version":"nooa-finding-bundle-v1","producer":"",'
            b'"findings":[{"schema_version":"nooa-finding-v1","finding_id":"f",'
            b'"finding_type":"t","producer":"p","run_id":"","target":"",'
            b'"evidence_refs":[],"attributes":{"score":NaN}}]}\n',
            id="nan",
        ),
        pytest.param(
            b'{"schema_version":"nooa-finding-bundle-v1","producer":"",'
            b'"findings":[{"schema_version":"nooa-finding-v1","finding_id":"f",'
            b'"finding_type":"t","producer":"p","run_id":"","target":"",'
            b'"evidence_refs":[],"attributes":{"score":1e999}}]}\n',
            id="overflow-float",
        ),
        pytest.param(
            (
                b'{"schema_version":"nooa-finding-bundle-v1","producer":"",'
                b'"findings":[{"schema_version":"nooa-finding-v1","finding_id":"f",'
                b'"finding_type":"t","producer":"p","run_id":"","target":"",'
                b'"evidence_refs":[],"attributes":{"score":'
                + str(MAX_FINDING_BUNDLE_JSON_INTEGER + 1).encode("ascii")
                + b"}}]}\n"
            ),
            id="unsafe-int",
        ),
        pytest.param(
            b'{"schema_version":"nooa-finding-bundle-v1","producer":"\\ud800",'
            b'"findings":[]}\n',
            id="lone-surrogate",
        ),
        pytest.param(
            b'{"schema_version":"nooa-finding-bundle-v1","producer":"\xff",'
            b'"findings":[]}\n',
            id="invalid-utf8",
        ),
    ],
)
def test_read_finding_bundle_rejects_nonportable_terminated_documents(payload: bytes) -> None:
    with pytest.raises(ValueError, match="invalid finding bundle document"):
        read_finding_bundle(BytesIO(payload))


def test_finding_bundle_reader_and_writer_enforce_budgets() -> None:
    bundle = _bundle()
    payload = _bundle_line(bundle)
    two_finding_bundle = _bundle(
        findings=(_finding(), _finding(finding_id="finding-2")),
    )
    two_finding_payload = _bundle_line(two_finding_bundle)

    assert read_finding_bundle(BytesIO(payload), max_bundle_bytes=len(payload)).bundle == bundle
    with pytest.raises(FindingBundleInputTooLargeError) as bytes_exc:
        read_finding_bundle(BytesIO(payload), max_bundle_bytes=len(payload) - 1)
    assert bytes_exc.value.limit_name == "max_bundle_bytes"
    assert bytes_exc.value.limit_value == len(payload) - 1

    with pytest.raises(FindingBundleInputTooLargeError) as findings_exc:
        read_finding_bundle(BytesIO(two_finding_payload), max_findings=1)
    assert findings_exc.value.limit_name == "max_findings"
    assert findings_exc.value.limit_value == 1

    with pytest.raises(FindingBundleInputTooLargeError):
        write_finding_bundle(BytesIO(), bundle, max_bundle_bytes=len(payload) - 1)
    with pytest.raises(FindingBundleInputTooLargeError):
        write_finding_bundle(BytesIO(), two_finding_bundle, max_findings=1)


def test_write_finding_bundle_rejects_subclass_only_fields_and_short_write() -> None:
    class ExtendedFinding(SecurityFinding):
        extra_field: str

    class ExtendedBundle(FindingBundle):
        extra_field: str

    finding = ExtendedFinding(
        finding_id="finding-extended",
        finding_type="authorization.missing_receipt",
        producer="identity_policy.v1",
        extra_field="must-not-drop",
    )
    with pytest.raises(TypeError, match="expected SecurityFinding at index 0"):
        write_finding_bundle(BytesIO(), _bundle(findings=(finding,)))
    with pytest.raises(TypeError, match="expected FindingBundle"):
        write_finding_bundle(
            BytesIO(),
            ExtendedBundle(producer="identity_policy.v1", extra_field="must-not-drop"),
        )

    class ShortWriteBuffer(BytesIO):
        def write(self, data: bytes) -> int:
            super().write(data[:-1])
            return len(data) - 1

    with pytest.raises(OSError, match="finding bundle writer wrote"):
        write_finding_bundle(ShortWriteBuffer(), _bundle())


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1024"])
def test_finding_bundle_rejects_invalid_budget_values(value: object) -> None:
    expected_exception = (
        TypeError if not isinstance(value, int) or isinstance(value, bool) else ValueError
    )
    with pytest.raises(expected_exception):
        read_finding_bundle(
            BytesIO(b""),
            max_bundle_bytes=value,  # type: ignore[arg-type]
        )
    with pytest.raises(expected_exception):
        write_finding_bundle(
            BytesIO(),
            _bundle(),
            max_findings=value,  # type: ignore[arg-type]
        )


def test_finding_bundle_helpers_reject_invalid_inputs_and_clean_error() -> None:
    clean = FindingBundleReadResult(bundle=_bundle())

    with pytest.raises(TypeError, match="expected FindingBundle"):
        write_finding_bundle(BytesIO(), "not-a-bundle")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="binary stream"):
        read_finding_bundle(StringIO(""))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingBundleReadResult"):
        finding_bundle_completeness_signals("not-a-result")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingBundleReadResult"):
        require_complete_finding_bundle("not-a-result")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingBundleReadResult"):
        FindingBundleIncompleteError("not-a-result")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one completeness signal"):
        FindingBundleIncompleteError(clean)
    with pytest.raises(ValueError, match="without a bundle must be truncated"):
        FindingBundleReadResult(bundle=None)


def test_validate_finding_scope_materializes_once_and_preserves_order() -> None:
    source = iter(
        (
            _finding(finding_id="finding-1"),
            _finding(finding_id="finding-2"),
        )
    )

    validation = validate_finding_scope(
        source,
        expected_run_id="run-20260727-identity-1",
    )

    assert tuple(source) == ()
    assert [finding.finding_id for finding in validation.findings] == ["finding-1", "finding-2"]
    assert validation.expected_run_id == "run-20260727-identity-1"
    assert validation.missing_run_id_finding_ids == ()
    assert validation.mismatched_run_id_finding_ids == ()
    assert finding_scope_signals(validation) == ()
    assert require_valid_finding_scope(validation) is validation.findings


def test_validate_finding_scope_reports_canonical_run_scope_diagnostics() -> None:
    validation = validate_finding_scope(
        (
            _finding(finding_id="finding-current"),
            _finding(finding_id="finding-missing", run_id=""),
            _finding(finding_id="finding-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    assert validation.missing_run_id_finding_ids == ("finding-missing",)
    assert validation.mismatched_run_id_finding_ids == ("finding-stale",)
    assert finding_scope_signals(validation) == ("missing_run_id", "run_id_mismatch")
    assert FINDING_SCOPE_SIGNALS == ("missing_run_id", "run_id_mismatch")


@pytest.mark.parametrize(
    ("findings", "expected_signals", "expected_missing_ids", "expected_mismatched_ids"),
    [
        pytest.param(
            (
                _finding(finding_id="finding-missing-1", run_id=""),
                _finding(finding_id="finding-missing-2", run_id=""),
            ),
            ("missing_run_id",),
            ("finding-missing-1", "finding-missing-2"),
            (),
            id="missing-only",
        ),
        pytest.param(
            (
                _finding(finding_id="finding-stale-1", run_id="run-prior"),
                _finding(finding_id="finding-stale-2", run_id="run-other"),
            ),
            ("run_id_mismatch",),
            (),
            ("finding-stale-1", "finding-stale-2"),
            id="mismatch-only",
        ),
    ],
)
def test_validate_finding_scope_preserves_each_single_signal_category(
    findings: tuple[SecurityFinding, ...],
    expected_signals: tuple[str, ...],
    expected_missing_ids: tuple[str, ...],
    expected_mismatched_ids: tuple[str, ...],
) -> None:
    validation = validate_finding_scope(
        findings,
        expected_run_id="run-20260727-identity-1",
    )

    assert finding_scope_signals(validation) == expected_signals
    assert validation.missing_run_id_finding_ids == expected_missing_ids
    assert validation.mismatched_run_id_finding_ids == expected_mismatched_ids


def test_require_valid_finding_scope_raises_structured_error() -> None:
    validation = validate_finding_scope(
        (
            _finding(finding_id="finding-missing", run_id=""),
            _finding(finding_id="finding-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    with pytest.raises(FindingScopeError) as exc_info:
        require_valid_finding_scope(validation)

    error = exc_info.value
    assert error.reasons == ("missing_run_id", "run_id_mismatch")
    assert error.expected_run_id == "run-20260727-identity-1"
    assert error.missing_run_id_finding_ids == ("finding-missing",)
    assert error.mismatched_run_id_finding_ids == ("finding-stale",)
    assert not isinstance(error, ValueError)


def test_empty_finding_scope_passes_without_claiming_coverage() -> None:
    validation = validate_finding_scope((), expected_run_id="run-20260727-identity-1")

    assert validation.findings == ()
    assert finding_scope_signals(validation) == ()
    assert require_valid_finding_scope(validation) == ()


@pytest.mark.parametrize("expected_run_id", ["", None, 0])
def test_validate_finding_scope_rejects_invalid_expected_run_id(expected_run_id: object) -> None:
    error_type = ValueError if expected_run_id == "" else TypeError
    with pytest.raises(error_type):
        validate_finding_scope(
            (),
            expected_run_id=expected_run_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("findings", ["not-findings", b"not-findings", [object()]])
def test_validate_finding_scope_rejects_non_finding_inputs(findings: object) -> None:
    with pytest.raises(TypeError, match="SecurityFinding"):
        validate_finding_scope(
            findings,  # type: ignore[arg-type]
            expected_run_id="run-20260727-identity-1",
        )


def test_finding_scope_helpers_reject_non_validation_inputs_and_clean_error() -> None:
    with pytest.raises(TypeError, match="expected FindingScopeValidation"):
        finding_scope_signals("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingScopeValidation"):
        require_valid_finding_scope("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected FindingScopeValidation"):
        FindingScopeError("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one scope signal"):
        FindingScopeError(FindingScopeValidation(findings=(), expected_run_id="run-1"))
