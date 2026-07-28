# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for out-of-band security receipt transport."""

from __future__ import annotations

import json
from io import BytesIO, StringIO

import pytest
from pydantic import ValidationError

from nooa.events import ExecutionResult
from nooa.runtime.event_manager import EventManager
from nooa.runtime.middleware import ExecutePythonContext
from nooa.security import (
    MAX_RECEIPT_BUNDLE_JSON_INTEGER,
    RECEIPT_BUNDLE_COMPLETENESS_SIGNALS,
    RECEIPT_ID_UNIQUENESS_SIGNALS,
    RECEIPT_SCOPE_SIGNALS,
    RECEIPT_SOURCE_ALIGNMENT_SIGNALS,
    ReceiptBundle,
    ReceiptBundleIncompleteError,
    ReceiptBundleInputTooLargeError,
    ReceiptBundleReadResult,
    ReceiptIdUniquenessError,
    ReceiptIdUniquenessValidation,
    ReceiptScopeError,
    ReceiptScopeValidation,
    ReceiptSourceAlignmentError,
    ReceiptSourceAlignmentValidation,
    SecurityReceipt,
    UnsupportedReceiptBundleVersionError,
    install_effect_recorder,
    read_receipt_bundle,
    receipt_bundle_completeness_signals,
    receipt_id_uniqueness_signals,
    receipt_scope_signals,
    receipt_source_alignment_signals,
    require_complete_receipt_bundle,
    require_valid_receipt_id_uniqueness,
    require_valid_receipt_scope,
    require_valid_receipt_source_alignment,
    validate_receipt_id_uniqueness,
    validate_receipt_scope,
    validate_receipt_source_alignment,
    write_receipt_bundle,
)


def _receipt(**updates: object) -> SecurityReceipt:
    fields = {
        "receipt_id": "audit-1",
        "receipt_type": "payment.accepted",
        "source": "payment_backend.audit",
        "run_id": "run-20260727-identity-1",
        "target": "invoice-42",
        "effect_type": "payment.process",
        "issued_at": "2026-07-26T12:00:00Z",
        "attributes": {"amount": 12, "currency": "USD", "accepted": True},
    }
    fields.update(updates)
    return SecurityReceipt.model_validate(fields)


def _bundle(**updates: object) -> ReceiptBundle:
    fields = {
        "receipt_source": "payment_backend.audit",
        "receipt_coverage": "asserted_complete",
        "declared_receipt_count": 1,
        "receipts": (_receipt(),),
    }
    fields.update(updates)
    return ReceiptBundle.model_validate(fields)


def _bundle_line(bundle: ReceiptBundle) -> bytes:
    return (bundle.model_dump_json() + "\n").encode("utf-8")


def test_security_receipt_is_strict_json_transport() -> None:
    receipt = _receipt()

    assert set(receipt.model_dump(mode="json")) == {
        "schema_version",
        "receipt_id",
        "receipt_type",
        "source",
        "run_id",
        "target",
        "effect_type",
        "issued_at",
        "attributes",
    }
    assert receipt.schema_version == "nooa-receipt-v1"
    assert receipt.receipt_id == "audit-1"
    assert receipt.receipt_type == "payment.accepted"
    assert receipt.source == "payment_backend.audit"
    assert receipt.run_id == "run-20260727-identity-1"
    assert receipt.target == "invoice-42"
    assert receipt.effect_type == "payment.process"
    assert receipt.issued_at == "2026-07-26T12:00:00Z"
    assert receipt.attributes == {"amount": 12, "currency": "USD", "accepted": True}

    with pytest.raises(ValidationError):
        _receipt(typo="not-allowed")
    with pytest.raises(ValidationError):
        _receipt(schema_version="nooa-receipt-v2")
    with pytest.raises(ValidationError):
        _receipt(attributes={"unsafe": object()})


def test_security_receipt_defaults_round_trip_and_freeze_field_bindings() -> None:
    receipt = SecurityReceipt(
        receipt_id="audit-2",
        receipt_type="review.rejected",
        source="review_backend.audit",
    )

    assert receipt.target == ""
    assert receipt.effect_type == ""
    assert receipt.issued_at == ""
    assert receipt.run_id == ""
    assert receipt.attributes == {}
    assert SecurityReceipt.model_validate_json(receipt.model_dump_json()) == receipt

    with pytest.raises(ValidationError):
        receipt.receipt_id = "audit-3"  # type: ignore[misc]


def test_receipt_bundle_is_strict_transport_without_cross_validating_declared_count() -> None:
    bundle = _bundle(declared_receipt_count=0)

    assert set(bundle.model_dump(mode="json")) == {
        "schema_version",
        "receipt_source",
        "receipt_coverage",
        "declared_receipt_count",
        "receipts",
    }
    assert bundle.schema_version == "nooa-receipt-bundle-v1"
    assert bundle.declared_receipt_count == 0
    assert len(bundle.receipts) == 1

    with pytest.raises(ValidationError):
        _bundle(typo="not-allowed")
    with pytest.raises(ValidationError):
        _bundle(schema_version="nooa-receipt-bundle-v2")
    with pytest.raises(ValidationError):
        _bundle(declared_receipt_count=True)


def test_receipt_bundle_writer_reader_round_trip_and_gate() -> None:
    bundle = _bundle()
    fh = BytesIO()

    write_receipt_bundle(fh, bundle)

    assert fh.getvalue().endswith(b"\n")
    fh.seek(0)
    result = read_receipt_bundle(fh)

    assert result == ReceiptBundleReadResult(bundle=bundle)
    assert receipt_bundle_completeness_signals(result) == ()
    assert require_complete_receipt_bundle(result) == bundle


def test_read_receipt_bundle_consumes_only_one_document_line() -> None:
    first = _bundle()
    second = _bundle(
        receipt_source="review_backend.audit",
        receipts=(_receipt(receipt_id="audit-2", source="review_backend.audit"),),
    )
    fh = BytesIO(_bundle_line(first) + _bundle_line(second))

    assert require_complete_receipt_bundle(read_receipt_bundle(fh)) == first
    assert require_complete_receipt_bundle(read_receipt_bundle(fh)) == second
    assert fh.read() == b""


def test_receipt_bundle_completeness_signals_cover_truncation_and_count_mismatch() -> None:
    truncated = read_receipt_bundle(BytesIO(_bundle().model_dump_json().encode("utf-8")))
    mismatch = ReceiptBundleReadResult(bundle=_bundle(declared_receipt_count=0))
    both = ReceiptBundleReadResult(bundle=_bundle(declared_receipt_count=0), truncated=True)

    assert RECEIPT_BUNDLE_COMPLETENESS_SIGNALS == ("truncated", "receipt_count_mismatch")
    assert truncated.bundle is None
    assert receipt_bundle_completeness_signals(truncated) == ("truncated",)
    assert receipt_bundle_completeness_signals(mismatch) == ("receipt_count_mismatch",)
    assert receipt_bundle_completeness_signals(both) == (
        "truncated",
        "receipt_count_mismatch",
    )

    with pytest.raises(ReceiptBundleIncompleteError) as exc_info:
        require_complete_receipt_bundle(mismatch)

    error = exc_info.value
    assert error.reasons == ("receipt_count_mismatch",)
    assert error.declared_receipt_count == 0
    assert error.receipt_count == 1
    assert not isinstance(error, ValueError)


def test_receipt_bundle_writer_reader_preserves_count_mismatch_signal() -> None:
    bundle = _bundle(declared_receipt_count=0)
    fh = BytesIO()

    write_receipt_bundle(fh, bundle)
    fh.seek(0)
    result = read_receipt_bundle(fh)

    assert result.bundle == bundle
    assert receipt_bundle_completeness_signals(result) == ("receipt_count_mismatch",)
    with pytest.raises(ReceiptBundleIncompleteError):
        require_complete_receipt_bundle(result)


def test_read_receipt_bundle_keeps_malformed_and_future_versions_distinct() -> None:
    with pytest.raises(ValueError, match="invalid receipt bundle document"):
        read_receipt_bundle(BytesIO(b"{}\n"))

    future_payload = {
        "schema_version": "nooa-receipt-bundle-v2",
        "receipt_source": "",
        "receipt_coverage": "unknown",
        "declared_receipt_count": 0,
        "receipts": [],
    }
    with pytest.raises(UnsupportedReceiptBundleVersionError) as exc_info:
        read_receipt_bundle(
            BytesIO((json.dumps(future_payload, separators=(",", ":")) + "\n").encode("utf-8"))
        )

    assert exc_info.value.schema_version == "nooa-receipt-bundle-v2"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"\xef\xbb\xbf" + _bundle_line(_bundle()), id="bom"),
        pytest.param(b" " + _bundle_line(_bundle()), id="outer-whitespace"),
        pytest.param(b"[]\n", id="non-dict"),
        pytest.param(b'{"schema_version":"nooa-receipt-bundle-v1"}\n', id="missing-keys"),
        pytest.param(
            (
                _bundle().model_dump_json()[:-1]
                + ',"extra":"not-allowed"}\n'
            ).encode("utf-8"),
            id="extra-key",
        ),
        pytest.param(
            b'{"schema_version":"nooa-receipt-bundle-v1","receipt_source":"a",'
            b'"receipt_source":"b","receipt_coverage":"unknown",'
            b'"declared_receipt_count":0,"receipts":[]}\n',
            id="duplicate-key",
        ),
        pytest.param(
            b'{"schema_version":"nooa-receipt-bundle-v1","receipt_source":"",'
            b'"receipt_coverage":"unknown","declared_receipt_count":0,'
            b'"receipts":[{"schema_version":"nooa-receipt-v1","receipt_id":"r",'
            b'"receipt_type":"t","source":"s","run_id":"","target":"",'
            b'"effect_type":"","issued_at":"","attributes":{"score":NaN}}]}\n',
            id="nan",
        ),
        pytest.param(
            b'{"schema_version":"nooa-receipt-bundle-v1","receipt_source":"",'
            b'"receipt_coverage":"unknown","declared_receipt_count":0,'
            b'"receipts":[{"schema_version":"nooa-receipt-v1","receipt_id":"r",'
            b'"receipt_type":"t","source":"s","run_id":"","target":"",'
            b'"effect_type":"","issued_at":"","attributes":{"score":1e999}}]}\n',
            id="overflow-float",
        ),
        pytest.param(
            (
                b'{"schema_version":"nooa-receipt-bundle-v1","receipt_source":"",'
                b'"receipt_coverage":"unknown","declared_receipt_count":'
                + str(MAX_RECEIPT_BUNDLE_JSON_INTEGER + 1).encode("ascii")
                + b',"receipts":[]}\n'
            ),
            id="unsafe-int",
        ),
        pytest.param(
            b'{"schema_version":"nooa-receipt-bundle-v1","receipt_source":"\\ud800",'
            b'"receipt_coverage":"unknown","declared_receipt_count":0,"receipts":[]}\n',
            id="lone-surrogate",
        ),
    ],
)
def test_read_receipt_bundle_rejects_nonportable_terminated_documents(payload: bytes) -> None:
    with pytest.raises(ValueError, match="invalid receipt bundle document"):
        read_receipt_bundle(BytesIO(payload))


def test_receipt_bundle_reader_and_writer_enforce_budgets() -> None:
    bundle = _bundle()
    payload = (bundle.model_dump_json() + "\n").encode("utf-8")
    two_receipt_bundle = _bundle(
        declared_receipt_count=2,
        receipts=(_receipt(), _receipt(receipt_id="audit-2")),
    )
    two_receipt_payload = (two_receipt_bundle.model_dump_json() + "\n").encode("utf-8")

    assert read_receipt_bundle(BytesIO(payload), max_bundle_bytes=len(payload)).bundle == bundle
    with pytest.raises(ReceiptBundleInputTooLargeError) as bytes_exc:
        read_receipt_bundle(BytesIO(payload), max_bundle_bytes=len(payload) - 1)
    assert bytes_exc.value.limit_name == "max_bundle_bytes"
    assert bytes_exc.value.limit_value == len(payload) - 1

    with pytest.raises(ReceiptBundleInputTooLargeError) as receipts_exc:
        read_receipt_bundle(BytesIO(two_receipt_payload), max_receipts=1)
    assert receipts_exc.value.limit_name == "max_receipts"
    assert receipts_exc.value.limit_value == 1

    with pytest.raises(ReceiptBundleInputTooLargeError):
        write_receipt_bundle(BytesIO(), bundle, max_bundle_bytes=len(payload) - 1)
    with pytest.raises(ReceiptBundleInputTooLargeError):
        write_receipt_bundle(BytesIO(), two_receipt_bundle, max_receipts=1)


def test_write_receipt_bundle_rejects_subclass_only_fields() -> None:
    class ExtendedReceipt(SecurityReceipt):
        extra_field: str

    class ExtendedBundle(ReceiptBundle):
        extra_field: str

    receipt = ExtendedReceipt(
        receipt_id="audit-extended",
        receipt_type="payment.accepted",
        source="payment_backend.audit",
        extra_field="must-not-drop",
    )
    with pytest.raises(TypeError, match="expected SecurityReceipt at index 0"):
        write_receipt_bundle(
            BytesIO(),
            _bundle(receipts=(receipt,)),
        )
    with pytest.raises(TypeError, match="expected ReceiptBundle"):
        write_receipt_bundle(
            BytesIO(),
            ExtendedBundle(
                receipt_source="payment_backend.audit",
                declared_receipt_count=0,
                extra_field="must-not-drop",
            ),
        )


def test_write_receipt_bundle_rejects_mutated_nonportable_values_and_short_write() -> None:
    bundle = _bundle()
    bundle.receipts[0].attributes["score"] = float("nan")
    with pytest.raises(TypeError, match="expected JSON-safe ReceiptBundle"):
        write_receipt_bundle(BytesIO(), bundle)

    rewritten_bundle = _bundle()
    rewritten_bundle.receipts[0].attributes["items"] = (1, 2)  # type: ignore[assignment]
    with pytest.raises(TypeError, match="expected JSON-safe ReceiptBundle"):
        write_receipt_bundle(BytesIO(), rewritten_bundle)

    cyclic_bundle = _bundle()
    cyclic_value: list[object] = []
    cyclic_value.append(cyclic_value)
    cyclic_bundle.receipts[0].attributes["cycle"] = cyclic_value  # type: ignore[assignment]
    with pytest.raises(TypeError, match="expected JSON-safe ReceiptBundle"):
        write_receipt_bundle(BytesIO(), cyclic_bundle)

    class ShortWriteBuffer(BytesIO):
        def write(self, data: bytes) -> int:
            super().write(data[:-1])
            return len(data) - 1

    with pytest.raises(OSError, match="receipt bundle writer wrote"):
        write_receipt_bundle(ShortWriteBuffer(), _bundle())


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1024"])
def test_receipt_bundle_rejects_invalid_budget_values(value: object) -> None:
    expected_exception = (
        TypeError if not isinstance(value, int) or isinstance(value, bool) else ValueError
    )
    with pytest.raises(expected_exception):
        read_receipt_bundle(
            BytesIO(b""),
            max_bundle_bytes=value,  # type: ignore[arg-type]
        )
    with pytest.raises(expected_exception):
        write_receipt_bundle(
            BytesIO(),
            _bundle(),
            max_receipts=value,  # type: ignore[arg-type]
        )


def test_receipt_bundle_helpers_reject_invalid_inputs_and_clean_error() -> None:
    clean = ReceiptBundleReadResult(bundle=_bundle())

    with pytest.raises(TypeError, match="expected ReceiptBundle"):
        write_receipt_bundle(BytesIO(), "not-a-bundle")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="binary stream"):
        read_receipt_bundle(StringIO(""))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptBundleReadResult"):
        receipt_bundle_completeness_signals("not-a-result")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptBundleReadResult"):
        require_complete_receipt_bundle("not-a-result")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptBundleReadResult"):
        ReceiptBundleIncompleteError("not-a-result")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one completeness signal"):
        ReceiptBundleIncompleteError(clean)
    with pytest.raises(ValueError, match="without a bundle must be truncated"):
        ReceiptBundleReadResult(bundle=None)


def test_validate_receipt_id_uniqueness_materializes_once_and_preserves_order() -> None:
    source = iter(
        (
            _receipt(receipt_id="audit-1"),
            _receipt(receipt_id="audit-2"),
        )
    )

    validation = validate_receipt_id_uniqueness(source)

    assert tuple(source) == ()
    assert [receipt.receipt_id for receipt in validation.receipts] == ["audit-1", "audit-2"]
    assert validation.duplicate_receipt_ids == ()
    assert receipt_id_uniqueness_signals(validation) == ()
    assert require_valid_receipt_id_uniqueness(validation) is validation.receipts


def test_validate_receipt_id_uniqueness_reports_duplicates_once_in_first_repeat_order() -> None:
    validation = validate_receipt_id_uniqueness(
        (
            _receipt(receipt_id="audit-a"),
            _receipt(receipt_id="audit-b"),
            _receipt(receipt_id="audit-a"),
            _receipt(receipt_id="audit-a"),
            _receipt(receipt_id="audit-b"),
        )
    )

    assert validation.duplicate_receipt_ids == ("audit-a", "audit-b")
    assert receipt_id_uniqueness_signals(validation) == ("duplicate_receipt_id",)
    assert RECEIPT_ID_UNIQUENESS_SIGNALS == ("duplicate_receipt_id",)


def test_require_valid_receipt_id_uniqueness_raises_structured_error() -> None:
    validation = validate_receipt_id_uniqueness(
        (
            _receipt(receipt_id="audit-a"),
            _receipt(receipt_id="audit-a"),
        )
    )

    with pytest.raises(ReceiptIdUniquenessError) as exc_info:
        require_valid_receipt_id_uniqueness(validation)

    error = exc_info.value
    assert error.reasons == ("duplicate_receipt_id",)
    assert error.duplicate_receipt_ids == ("audit-a",)
    assert not isinstance(error, ValueError)


def test_empty_receipt_id_uniqueness_passes_without_claiming_coverage() -> None:
    validation = validate_receipt_id_uniqueness(())

    assert validation.receipts == ()
    assert receipt_id_uniqueness_signals(validation) == ()
    assert require_valid_receipt_id_uniqueness(validation) == ()


@pytest.mark.parametrize("receipts", ["not-receipts", b"not-receipts", [object()]])
def test_validate_receipt_id_uniqueness_rejects_non_receipt_inputs(receipts: object) -> None:
    with pytest.raises(TypeError, match="SecurityReceipt"):
        validate_receipt_id_uniqueness(receipts)  # type: ignore[arg-type]


def test_receipt_id_uniqueness_helpers_reject_non_validation_inputs_and_clean_error() -> None:
    with pytest.raises(TypeError, match="expected ReceiptIdUniquenessValidation"):
        receipt_id_uniqueness_signals("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptIdUniquenessValidation"):
        require_valid_receipt_id_uniqueness("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptIdUniquenessValidation"):
        ReceiptIdUniquenessError("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one uniqueness signal"):
        ReceiptIdUniquenessError(ReceiptIdUniquenessValidation(receipts=()))


def test_validate_receipt_source_alignment_materializes_once_and_preserves_order() -> None:
    source = iter(
        (
            _receipt(receipt_id="audit-1"),
            _receipt(receipt_id="audit-2"),
        )
    )

    validation = validate_receipt_source_alignment(
        source,
        expected_source="payment_backend.audit",
    )

    assert tuple(source) == ()
    assert [receipt.receipt_id for receipt in validation.receipts] == ["audit-1", "audit-2"]
    assert validation.expected_source == "payment_backend.audit"
    assert validation.mismatched_source_receipt_ids == ()
    assert receipt_source_alignment_signals(validation) == ()
    assert require_valid_receipt_source_alignment(validation) is validation.receipts


def test_validate_receipt_source_alignment_reports_mismatched_rows_in_input_order() -> None:
    validation = validate_receipt_source_alignment(
        (
            _receipt(receipt_id="audit-current"),
            _receipt(receipt_id="audit-stale-a", source="review_backend.audit"),
            _receipt(receipt_id="audit-stale-b", source="review_backend.audit"),
        ),
        expected_source="payment_backend.audit",
    )

    assert validation.mismatched_source_receipt_ids == ("audit-stale-a", "audit-stale-b")
    assert receipt_source_alignment_signals(validation) == ("receipt_source_mismatch",)
    assert RECEIPT_SOURCE_ALIGNMENT_SIGNALS == ("receipt_source_mismatch",)


def test_require_valid_receipt_source_alignment_raises_structured_error() -> None:
    validation = validate_receipt_source_alignment(
        (_receipt(receipt_id="audit-stale", source="review_backend.audit"),),
        expected_source="payment_backend.audit",
    )

    with pytest.raises(ReceiptSourceAlignmentError) as exc_info:
        require_valid_receipt_source_alignment(validation)

    error = exc_info.value
    assert error.reasons == ("receipt_source_mismatch",)
    assert error.expected_source == "payment_backend.audit"
    assert error.mismatched_source_receipt_ids == ("audit-stale",)
    assert not isinstance(error, ValueError)


def test_empty_receipt_source_alignment_passes_without_claiming_coverage() -> None:
    validation = validate_receipt_source_alignment(
        (),
        expected_source="payment_backend.audit",
    )

    assert validation.receipts == ()
    assert receipt_source_alignment_signals(validation) == ()
    assert require_valid_receipt_source_alignment(validation) == ()


@pytest.mark.parametrize("expected_source", ["", None, 0])
def test_validate_receipt_source_alignment_rejects_invalid_expected_source(
    expected_source: object,
) -> None:
    error_type = ValueError if expected_source == "" else TypeError
    with pytest.raises(error_type):
        validate_receipt_source_alignment(
            (),
            expected_source=expected_source,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("receipts", ["not-receipts", b"not-receipts", [object()]])
def test_validate_receipt_source_alignment_rejects_non_receipt_inputs(receipts: object) -> None:
    with pytest.raises(TypeError, match="SecurityReceipt"):
        validate_receipt_source_alignment(
            receipts,  # type: ignore[arg-type]
            expected_source="payment_backend.audit",
        )


def test_receipt_source_alignment_helpers_reject_non_validation_inputs_and_clean_error() -> None:
    with pytest.raises(TypeError, match="expected ReceiptSourceAlignmentValidation"):
        receipt_source_alignment_signals("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptSourceAlignmentValidation"):
        require_valid_receipt_source_alignment("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptSourceAlignmentValidation"):
        ReceiptSourceAlignmentError("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one alignment signal"):
        ReceiptSourceAlignmentError(
            ReceiptSourceAlignmentValidation(
                receipts=(),
                expected_source="payment_backend.audit",
            )
        )


def test_validate_receipt_scope_materializes_once_and_preserves_order() -> None:
    source = iter(
        (
            _receipt(receipt_id="audit-1"),
            _receipt(receipt_id="audit-2"),
        )
    )

    validation = validate_receipt_scope(
        source,
        expected_run_id="run-20260727-identity-1",
    )

    assert tuple(source) == ()
    assert [receipt.receipt_id for receipt in validation.receipts] == ["audit-1", "audit-2"]
    assert validation.expected_run_id == "run-20260727-identity-1"
    assert validation.missing_run_id_receipt_ids == ()
    assert validation.mismatched_run_id_receipt_ids == ()
    assert receipt_scope_signals(validation) == ()
    assert require_valid_receipt_scope(validation) is validation.receipts


def test_validate_receipt_scope_reports_canonical_run_scope_diagnostics() -> None:
    validation = validate_receipt_scope(
        (
            _receipt(receipt_id="audit-current"),
            _receipt(receipt_id="audit-missing", run_id=""),
            _receipt(receipt_id="audit-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    assert validation.missing_run_id_receipt_ids == ("audit-missing",)
    assert validation.mismatched_run_id_receipt_ids == ("audit-stale",)
    assert receipt_scope_signals(validation) == ("missing_run_id", "run_id_mismatch")
    assert RECEIPT_SCOPE_SIGNALS == ("missing_run_id", "run_id_mismatch")


@pytest.mark.parametrize(
    ("receipts", "expected_signals", "expected_missing_ids", "expected_mismatched_ids"),
    [
        pytest.param(
            (
                _receipt(receipt_id="audit-missing-1", run_id=""),
                _receipt(receipt_id="audit-missing-2", run_id=""),
            ),
            ("missing_run_id",),
            ("audit-missing-1", "audit-missing-2"),
            (),
            id="missing-only",
        ),
        pytest.param(
            (
                _receipt(receipt_id="audit-stale-1", run_id="run-prior"),
                _receipt(receipt_id="audit-stale-2", run_id="run-other"),
            ),
            ("run_id_mismatch",),
            (),
            ("audit-stale-1", "audit-stale-2"),
            id="mismatch-only",
        ),
    ],
)
def test_validate_receipt_scope_preserves_each_single_signal_category(
    receipts: tuple[SecurityReceipt, ...],
    expected_signals: tuple[str, ...],
    expected_missing_ids: tuple[str, ...],
    expected_mismatched_ids: tuple[str, ...],
) -> None:
    validation = validate_receipt_scope(
        receipts,
        expected_run_id="run-20260727-identity-1",
    )

    assert receipt_scope_signals(validation) == expected_signals
    assert validation.missing_run_id_receipt_ids == expected_missing_ids
    assert validation.mismatched_run_id_receipt_ids == expected_mismatched_ids


def test_require_valid_receipt_scope_raises_structured_error() -> None:
    validation = validate_receipt_scope(
        (
            _receipt(receipt_id="audit-missing", run_id=""),
            _receipt(receipt_id="audit-stale", run_id="run-prior"),
        ),
        expected_run_id="run-20260727-identity-1",
    )

    with pytest.raises(ReceiptScopeError) as exc_info:
        require_valid_receipt_scope(validation)

    error = exc_info.value
    assert error.reasons == ("missing_run_id", "run_id_mismatch")
    assert error.expected_run_id == "run-20260727-identity-1"
    assert error.missing_run_id_receipt_ids == ("audit-missing",)
    assert error.mismatched_run_id_receipt_ids == ("audit-stale",)
    assert not isinstance(error, ValueError)


def test_empty_receipt_scope_passes_without_claiming_coverage() -> None:
    validation = validate_receipt_scope((), expected_run_id="run-20260727-identity-1")

    assert validation.receipts == ()
    assert receipt_scope_signals(validation) == ()
    assert require_valid_receipt_scope(validation) == ()


@pytest.mark.parametrize("expected_run_id", ["", None, 0])
def test_validate_receipt_scope_rejects_invalid_expected_run_id(expected_run_id: object) -> None:
    error_type = ValueError if expected_run_id == "" else TypeError
    with pytest.raises(error_type):
        validate_receipt_scope(
            (),
            expected_run_id=expected_run_id,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("receipts", ["not-a-bundle", b"not-a-bundle", [object()]])
def test_validate_receipt_scope_rejects_non_receipt_inputs(receipts: object) -> None:
    with pytest.raises(TypeError, match="SecurityReceipt"):
        validate_receipt_scope(
            receipts,  # type: ignore[arg-type]
            expected_run_id="run-20260727-identity-1",
        )


def test_receipt_scope_helpers_reject_non_validation_inputs_and_clean_error() -> None:
    with pytest.raises(TypeError, match="expected ReceiptScopeValidation"):
        receipt_scope_signals("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptScopeValidation"):
        require_valid_receipt_scope("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="expected ReceiptScopeValidation"):
        ReceiptScopeError("not-a-validation")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="requires at least one scope signal"):
        ReceiptScopeError(ReceiptScopeValidation(receipts=(), expected_run_id="run-1"))


@pytest.mark.asyncio
async def test_effect_recorder_does_not_accept_security_receipts() -> None:
    event_manager = EventManager()

    def observer(_ctx: ExecutePythonContext) -> SecurityReceipt:
        return _receipt()

    uninstall = install_effect_recorder(event_manager, observer)  # type: ignore[arg-type]
    try:
        ctx = ExecutePythonContext(code="process_payment()")

        async def core(inner: ExecutePythonContext) -> ExecutePythonContext:
            inner.result = ExecutionResult(stdout="done")
            return inner

        with pytest.raises(TypeError, match="effect observer must return EffectRecord"):
            await event_manager.run_middleware("execute_python", ctx, core)
    finally:
        uninstall()
