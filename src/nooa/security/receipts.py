# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security receipt transport and opt-in run-scope helpers."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO, Literal, Never

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError
from pydantic_core import PydanticSerializationError

RECEIPT_BUNDLE_SCHEMA_VERSION: Literal["nooa-receipt-bundle-v1"] = "nooa-receipt-bundle-v1"
RECEIPT_BUNDLE_SCHEMA_VERSION_PATTERN: str = r"nooa-receipt-bundle-v[1-9][0-9]*"
RECEIPT_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE: Literal["full"] = "full"
RECEIPT_BUNDLE_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "receipt_source",
        "receipt_coverage",
        "declared_receipt_count",
        "receipts",
    }
)
ReceiptBundleCompletenessSignal = Literal["truncated", "receipt_count_mismatch"]
# Tuple order is public because ReceiptBundleIncompleteError.reasons preserves it.
RECEIPT_BUNDLE_COMPLETENESS_SIGNALS: tuple[ReceiptBundleCompletenessSignal, ...] = (
    "truncated",
    "receipt_count_mismatch",
)
MAX_RECEIPT_BUNDLE_JSON_INTEGER: int = (1 << 53) - 1
DEFAULT_RECEIPT_BUNDLE_MAX_BYTES: int = 1024 * 1024
DEFAULT_RECEIPT_BUNDLE_MAX_RECEIPTS: int = 1 << 20

ReceiptIdUniquenessSignal = Literal["duplicate_receipt_id"]
# Tuple order is public because ReceiptIdUniquenessError.reasons preserves it.
RECEIPT_ID_UNIQUENESS_SIGNALS: tuple[ReceiptIdUniquenessSignal, ...] = (
    "duplicate_receipt_id",
)

ReceiptSourceAlignmentSignal = Literal["receipt_source_mismatch"]
# Tuple order is public because ReceiptSourceAlignmentError.reasons preserves it.
RECEIPT_SOURCE_ALIGNMENT_SIGNALS: tuple[ReceiptSourceAlignmentSignal, ...] = (
    "receipt_source_mismatch",
)

ReceiptScopeSignal = Literal["missing_run_id", "run_id_mismatch"]
# Tuple order is public because ReceiptScopeError.reasons preserves it.
RECEIPT_SCOPE_SIGNALS: tuple[ReceiptScopeSignal, ...] = (
    "missing_run_id",
    "run_id_mismatch",
)

_RECEIPT_BUNDLE_SCHEMA_VERSION_RE = re.compile(RECEIPT_BUNDLE_SCHEMA_VERSION_PATTERN)


class SecurityReceipt(BaseModel):
    """Transport schema for backend receipts intended for out-of-band collection.

    A ``SecurityReceipt`` is a transport schema for application-supplied
    backend truth. The type does not authenticate its source, establish where
    collection happened, or make data constructed inside the victim process
    trustworthy. Construct receipts only from an out-of-band collector or
    separately trusted sink; do not emit them from an observer or generated
    code.

    Fields are intentionally generic so applications can preserve stable
    receipt identity, provenance, and optional run scope without standardizing
    policy or scorer semantics into NOOA. ``run_id`` is application-assigned;
    NOOA does not mint it, verify it, or infer that equal values establish
    trusted provenance. ``target`` and ``effect_type`` mirror
    :class:`~nooa.security.effects.EffectRecord` only for application-defined
    correlation; NOOA does not join receipts to effect records or guarantee
    that a backend knows runtime lineage fields such as ``generation_id`` or
    ``tool_call_id``. Field bindings are frozen for transport stability, but
    nested ``attributes`` values remain ordinary Python containers and are not
    a tamper-resistance boundary. ``attributes`` must contain sanitized JSON
    values only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-receipt-v1"] = Field(
        default="nooa-receipt-v1",
        description="Receipt wire-format discriminator.",
    )
    receipt_id: str = Field(
        min_length=1,
        description="Stable receipt identifier assigned by the source system.",
    )
    receipt_type: str = Field(
        min_length=1,
        description="Application-defined receipt category, e.g. 'payment.accepted'.",
    )
    source: str = Field(
        min_length=1,
        description="Sanitized identifier for the out-of-band source that issued the receipt.",
    )
    run_id: str = Field(
        default="",
        description="Application-assigned run or assessment scope for grouping related receipts.",
    )
    target: str = Field(
        default="",
        description="Sanitized target identifier for the receipt, if any.",
    )
    effect_type: str = Field(
        default="",
        description="Effect category this receipt corroborates, if known.",
    )
    issued_at: str = Field(
        default="",
        description="Serialized source-issued timestamp, if available.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined receipt details.",
    )


class UnsupportedReceiptBundleVersionError(ValueError):
    """Raised when a reader sees a well-formed future receipt bundle version."""

    def __init__(self, schema_version: object) -> None:
        self.schema_version = schema_version
        super().__init__(f"unsupported receipt bundle schema_version: {schema_version!r}")


class ReceiptBundleInputTooLargeError(ValueError):
    """Raised when a writer or reader refuses an over-bound receipt bundle."""

    def __init__(
        self,
        limit_name: Literal["max_bundle_bytes", "max_receipts"],
        limit_value: int,
    ) -> None:
        self.limit_name = limit_name
        self.limit_value = limit_value
        super().__init__(f"receipt bundle exceeds {limit_name}={limit_value}")


class ReceiptBundle(BaseModel):
    """One collector-facing receipt bundle document.

    The bundle is an aggregate transport shape, not an authenticity or
    completeness proof. ``receipt_source`` and ``receipt_coverage`` are
    caller-supplied assertions for downstream policy. ``declared_receipt_count``
    is preserved so a reader can report a visible count mismatch, but the model
    intentionally does not reject a mismatch during construction: doing so
    would collapse a transport diagnostic into a generic validation error.

    A writer can still lie by emitting a well-formed bundle with a truthful
    declared count after omitting receipts. A clean bundle also does not prove
    source identity, receipt-id uniqueness, receipt-to-effect correlation, run
    scope, or backend truth.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-receipt-bundle-v1"] = Field(
        default=RECEIPT_BUNDLE_SCHEMA_VERSION,
        description="Receipt bundle wire-format discriminator.",
    )
    receipt_source: str = Field(
        default="",
        description="Sanitized identifier for the asserted receipt collection source.",
    )
    receipt_coverage: Literal["asserted_complete", "partial", "unknown"] = Field(
        default="unknown",
        description="Caller assertion about the supplied receipt collection coverage.",
    )
    declared_receipt_count: int = Field(
        default=0,
        ge=0,
        le=MAX_RECEIPT_BUNDLE_JSON_INTEGER,
        strict=True,
        description="Writer-declared count retained for reader-visible mismatch diagnostics.",
    )
    receipts: tuple[SecurityReceipt, ...] = Field(
        default_factory=tuple,
        description="Application-supplied receipt copies carried by the document.",
    )


@dataclass(frozen=True)
class ReceiptBundleReadResult:
    """Parsed receipt bundle plus reader-visible document diagnostics.

    ``truncated=True`` means the reader reached EOF before the first required LF
    terminator. The reader does not parse an unterminated prefix, even when the
    prefix is otherwise valid JSON. ``bundle`` is therefore ``None`` for
    reader-produced truncated results. Direct construction only asserts these
    fields; it does not perform the checks in :func:`read_receipt_bundle`.
    """

    bundle: ReceiptBundle | None
    truncated: bool = False

    def __post_init__(self) -> None:
        if self.bundle is None and not self.truncated:
            raise ValueError("ReceiptBundleReadResult without a bundle must be truncated")


class ReceiptBundleIncompleteError(RuntimeError):
    """Raised when known reader diagnostics show degraded receipt transport.

    This error reports only degradation visible in a
    :class:`ReceiptBundleReadResult`. It does not authenticate receipt bytes,
    verify collection coverage, or prove that a writer emitted every receipt.
    """

    def __init__(self, result: ReceiptBundleReadResult) -> None:
        if not isinstance(result, ReceiptBundleReadResult):
            raise TypeError(
                "ReceiptBundleIncompleteError expected ReceiptBundleReadResult, "
                f"got {type(result).__name__}"
            )
        reasons = receipt_bundle_completeness_signals(result)
        if not reasons:
            raise ValueError(
                "ReceiptBundleIncompleteError requires at least one completeness signal"
            )
        self.bundle = result.bundle
        self.truncated = result.truncated
        self.declared_receipt_count = (
            result.bundle.declared_receipt_count if result.bundle is not None else None
        )
        self.receipt_count = len(result.bundle.receipts) if result.bundle is not None else None
        self.reasons = reasons
        super().__init__(
            "receipt bundle is incomplete: "
            f"truncated={result.truncated!r}, "
            f"declared_receipt_count={self.declared_receipt_count!r}, "
            f"receipt_count={self.receipt_count!r}"
        )


def write_receipt_bundle(
    fh: BinaryIO,
    bundle: ReceiptBundle,
    *,
    max_bundle_bytes: int = DEFAULT_RECEIPT_BUNDLE_MAX_BYTES,
    max_receipts: int = DEFAULT_RECEIPT_BUNDLE_MAX_RECEIPTS,
) -> None:
    """Write one LF-terminated receipt bundle document to a binary stream.

    The helper preserves the caller-supplied ``declared_receipt_count`` rather
    than repairing it. A reader that receives a mismatched count can therefore
    surface ``receipt_count_mismatch`` instead of losing the fact inside writer
    behavior. The helper bounds one serialized document and the number of
    receipt copies it is willing to emit; those limits are resource backstops,
    not authenticity guarantees.
    """

    if type(bundle) is not ReceiptBundle:
        raise TypeError(
            "write_receipt_bundle expected ReceiptBundle, "
            f"got {type(bundle).__name__}"
        )
    max_bundle_bytes = _validate_max_bundle_bytes(max_bundle_bytes)
    max_receipts = _validate_max_receipts(max_receipts)
    if len(bundle.receipts) > max_receipts:
        raise ReceiptBundleInputTooLargeError("max_receipts", max_receipts)
    for index, receipt in enumerate(bundle.receipts):
        if type(receipt) is not SecurityReceipt:
            raise TypeError(
                "write_receipt_bundle expected SecurityReceipt at "
                f"index {index}, got {type(receipt).__name__}"
            )
    try:
        for receipt in bundle.receipts:
            _validate_receipt_bundle_json_value_graph(receipt.attributes)
        payload_value = bundle.model_dump(mode="json")
        _validate_receipt_bundle_json_value_graph(payload_value)
        payload = (bundle.model_dump_json() + "\n").encode("utf-8")
    except (PydanticSerializationError, UnicodeEncodeError, ValidationError, ValueError) as exc:
        raise TypeError(
            f"write_receipt_bundle expected JSON-safe ReceiptBundle, got {type(bundle).__name__}"
        ) from exc
    if len(payload) > max_bundle_bytes:
        raise ReceiptBundleInputTooLargeError("max_bundle_bytes", max_bundle_bytes)
    written = fh.write(payload)
    if written != len(payload):
        raise OSError(f"receipt bundle writer wrote {written} of {len(payload)} bytes")
    fh.flush()


def read_receipt_bundle(
    fh: BinaryIO,
    *,
    max_bundle_bytes: int = DEFAULT_RECEIPT_BUNDLE_MAX_BYTES,
    max_receipts: int = DEFAULT_RECEIPT_BUNDLE_MAX_RECEIPTS,
) -> ReceiptBundleReadResult:
    """Read exactly one bounded LF-terminated receipt bundle document.

    The reader consumes at most one document line from the stream's current
    position and leaves any later bytes unread. Empty input and an unterminated
    first line return
    ``ReceiptBundleReadResult(truncated=True)``. A malformed terminated
    document raises :class:`ValueError`; a well-formed future schema version
    raises :class:`UnsupportedReceiptBundleVersionError`; and over-bound input
    raises :class:`ReceiptBundleInputTooLargeError`.

    ``max_bundle_bytes`` includes the required trailing LF byte. ``max_receipts``
    is an admission bound checked after the bounded JSON document has been
    parsed; callers that need a tighter parser-memory ceiling should reduce the
    byte budget as well.
    """

    max_bundle_bytes = _validate_max_bundle_bytes(max_bundle_bytes)
    max_receipts = _validate_max_receipts(max_receipts)
    payload = _read_receipt_bundle_binary_chunk(fh.readline(max_bundle_bytes + 1))
    if len(payload) > max_bundle_bytes:
        raise ReceiptBundleInputTooLargeError("max_bundle_bytes", max_bundle_bytes)
    if not payload or not payload.endswith(b"\n"):
        return ReceiptBundleReadResult(bundle=None, truncated=True)

    bundle = _parse_receipt_bundle_document(payload)
    if len(bundle.receipts) > max_receipts:
        raise ReceiptBundleInputTooLargeError("max_receipts", max_receipts)
    return ReceiptBundleReadResult(bundle=bundle)


def require_complete_receipt_bundle(result: ReceiptBundleReadResult) -> ReceiptBundle:
    """Return one parsed bundle only when received bytes show no known degradation.

    A clean result means only that the reader received one LF-terminated
    document and that its declared receipt count matched the receipts retained
    from that document. It does not authenticate bytes, prove collection
    coverage, or establish that no omitted receipts exist.
    """

    if not isinstance(result, ReceiptBundleReadResult):
        raise TypeError(
            "require_complete_receipt_bundle expected ReceiptBundleReadResult, "
            f"got {type(result).__name__}"
        )
    if receipt_bundle_completeness_signals(result):
        raise ReceiptBundleIncompleteError(result)
    if result.bundle is None:
        raise ValueError("complete ReceiptBundleReadResult requires a parsed bundle")
    return result.bundle


def receipt_bundle_completeness_signals(
    result: ReceiptBundleReadResult,
) -> tuple[ReceiptBundleCompletenessSignal, ...]:
    """Return known receipt-bundle diagnostics in canonical public order.

    The returned tuple describes only degradation visible in one
    :class:`ReceiptBundleReadResult`. An empty tuple does not prove that the
    producer emitted every receipt or that the bytes are authentic.
    """

    if not isinstance(result, ReceiptBundleReadResult):
        raise TypeError(
            "receipt_bundle_completeness_signals expected ReceiptBundleReadResult, "
            f"got {type(result).__name__}"
        )
    reasons: list[ReceiptBundleCompletenessSignal] = []
    if result.truncated:
        reasons.append("truncated")
    if (
        result.bundle is not None
        and result.bundle.declared_receipt_count != len(result.bundle.receipts)
    ):
        reasons.append("receipt_count_mismatch")
    return tuple(reasons)


@dataclass(frozen=True)
class ReceiptIdUniquenessValidation:
    """Identifier-uniqueness diagnostics for one materialized receipt iterable.

    This result preserves the input order in ``receipts`` and reports only
    repeated ``receipt_id`` values inside one supplied iterable. It does not
    authenticate receipts, sources, or identifiers; prove that distinct
    identifiers denote distinct receipts; establish uniqueness across bundles,
    runs, or sources; dereference identifiers against any external system; or
    prove receipt coverage.

    A clean empty result means only that none of the supplied receipts shared a
    ``receipt_id``. It does not prove that no receipts exist or that collection
    was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_receipt_id_uniqueness` performs.
    """

    receipts: tuple[SecurityReceipt, ...]
    duplicate_receipt_ids: tuple[str, ...] = ()


class ReceiptIdUniquenessError(RuntimeError):
    """Raised when supplied receipts reuse one or more receipt identifiers.

    This error reports only diagnostics visible in a
    :class:`ReceiptIdUniquenessValidation`. It does not establish receipt
    authenticity, collection coverage, or semantic correctness.
    """

    def __init__(self, validation: ReceiptIdUniquenessValidation) -> None:
        if not isinstance(validation, ReceiptIdUniquenessValidation):
            raise TypeError(
                "ReceiptIdUniquenessError expected ReceiptIdUniquenessValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = receipt_id_uniqueness_signals(validation)
        if not reasons:
            raise ValueError(
                "ReceiptIdUniquenessError requires at least one uniqueness signal"
            )
        self.duplicate_receipt_ids = validation.duplicate_receipt_ids
        self.reasons = reasons
        super().__init__(
            "receipt rows reuse receipt_id values: "
            f"duplicate_receipt_ids={validation.duplicate_receipt_ids!r}"
        )


def receipt_id_uniqueness_signals(
    validation: ReceiptIdUniquenessValidation,
) -> tuple[ReceiptIdUniquenessSignal, ...]:
    """Return canonical identifier diagnostics for one receipt iterable."""
    if not isinstance(validation, ReceiptIdUniquenessValidation):
        raise TypeError(
            "receipt_id_uniqueness_signals expected ReceiptIdUniquenessValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[ReceiptIdUniquenessSignal] = []
    if validation.duplicate_receipt_ids:
        signals.append("duplicate_receipt_id")
    return tuple(signals)


def validate_receipt_id_uniqueness(
    receipts: Iterable[SecurityReceipt],
) -> ReceiptIdUniquenessValidation:
    """Materialize receipts and report repeated receipt identifiers.

    ``receipts`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_receipt_id_uniqueness` when no
    uniqueness signal is present.

    The helper checks only whether the supplied rows reuse ``receipt_id``
    values. It does not authenticate receipts, sources, or identifiers; prove
    that distinct identifiers denote distinct receipts; establish uniqueness
    across bundles, runs, or sources; dereference identifiers against any
    external system; or prove receipt coverage.
    """
    if isinstance(receipts, (str, bytes, bytearray)) or not isinstance(receipts, Iterable):
        raise TypeError(
            "validate_receipt_id_uniqueness expected iterable of SecurityReceipt, "
            f"got {type(receipts).__name__}"
        )

    materialized = tuple(receipts)
    for index, receipt in enumerate(materialized):
        if not isinstance(receipt, SecurityReceipt):
            raise TypeError(
                "validate_receipt_id_uniqueness expected SecurityReceipt at "
                f"index {index}, got {type(receipt).__name__}"
            )

    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    reported_duplicate_ids: set[str] = set()
    for receipt in materialized:
        receipt_id = receipt.receipt_id
        if receipt_id in seen_ids and receipt_id not in reported_duplicate_ids:
            duplicate_ids.append(receipt_id)
            reported_duplicate_ids.add(receipt_id)
        seen_ids.add(receipt_id)

    return ReceiptIdUniquenessValidation(
        receipts=materialized,
        duplicate_receipt_ids=tuple(duplicate_ids),
    )


def require_valid_receipt_id_uniqueness(
    validation: ReceiptIdUniquenessValidation,
) -> tuple[SecurityReceipt, ...]:
    """Return supplied receipts or fail closed on repeated receipt identifiers."""
    if not isinstance(validation, ReceiptIdUniquenessValidation):
        raise TypeError(
            "require_valid_receipt_id_uniqueness expected ReceiptIdUniquenessValidation, "
            f"got {type(validation).__name__}"
        )
    if receipt_id_uniqueness_signals(validation):
        raise ReceiptIdUniquenessError(validation)
    return validation.receipts


@dataclass(frozen=True)
class ReceiptSourceAlignmentValidation:
    """Source-alignment diagnostics for one materialized receipt iterable.

    This result preserves the input order in ``receipts`` and reports only
    supplied rows whose ``source`` differs from one caller-supplied
    ``expected_source`` exact string. Both the row values and the expected
    value are producer-controlled unless a caller supplies an independently
    trusted value, so agreement is coherence rather than provenance.

    Case, whitespace, and Unicode normalization remain caller policy. A clean
    empty result means only that no supplied receipt contradicted this one
    expected-source requirement. It does not prove that no receipts exist or
    that collection was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_receipt_source_alignment` performs.
    """

    receipts: tuple[SecurityReceipt, ...]
    expected_source: str
    mismatched_source_receipt_ids: tuple[str, ...] = ()


class ReceiptSourceAlignmentError(RuntimeError):
    """Raised when supplied receipts do not match one expected source string.

    This error reports only diagnostics visible in a
    :class:`ReceiptSourceAlignmentValidation`. It does not establish receipt
    authenticity, collection coverage, or semantic correctness.
    """

    def __init__(self, validation: ReceiptSourceAlignmentValidation) -> None:
        if not isinstance(validation, ReceiptSourceAlignmentValidation):
            raise TypeError(
                "ReceiptSourceAlignmentError expected ReceiptSourceAlignmentValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = receipt_source_alignment_signals(validation)
        if not reasons:
            raise ValueError(
                "ReceiptSourceAlignmentError requires at least one alignment signal"
            )
        self.expected_source = validation.expected_source
        self.mismatched_source_receipt_ids = validation.mismatched_source_receipt_ids
        self.reasons = reasons
        super().__init__(
            "receipt rows do not match expected source: "
            f"expected_source={validation.expected_source!r}, "
            "mismatched_source_receipt_ids="
            f"{validation.mismatched_source_receipt_ids!r}"
        )


def receipt_source_alignment_signals(
    validation: ReceiptSourceAlignmentValidation,
) -> tuple[ReceiptSourceAlignmentSignal, ...]:
    """Return canonical source-alignment diagnostics for one receipt iterable."""
    if not isinstance(validation, ReceiptSourceAlignmentValidation):
        raise TypeError(
            "receipt_source_alignment_signals expected ReceiptSourceAlignmentValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[ReceiptSourceAlignmentSignal] = []
    if validation.mismatched_source_receipt_ids:
        signals.append("receipt_source_mismatch")
    return tuple(signals)


def validate_receipt_source_alignment(
    receipts: Iterable[SecurityReceipt],
    *,
    expected_source: str,
) -> ReceiptSourceAlignmentValidation:
    """Materialize receipts and report exact source-label inconsistencies.

    ``receipts`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_receipt_source_alignment` when no
    alignment signal is present. ``expected_source`` must be a non-empty
    caller-selected exact string; this helper does not mint or authenticate it.

    The helper checks only that each supplied receipt carries a ``source``
    exactly equal to ``expected_source``. Both the row source values and the
    expected value are producer-controlled unless a caller supplies an
    independently trusted value, so agreement is coherence rather than
    provenance. It does not authenticate receipts or sources; prove that the
    receipts originated from the named source; establish alignment across
    bundles, runs, or sources; dereference or correlate source labels against
    any external system; or prove receipt coverage.
    """
    if not isinstance(expected_source, str):
        raise TypeError(
            "validate_receipt_source_alignment expected str expected_source, "
            f"got {type(expected_source).__name__}"
        )
    if not expected_source:
        raise ValueError(
            "validate_receipt_source_alignment requires non-empty expected_source"
        )
    if isinstance(receipts, (str, bytes, bytearray)) or not isinstance(receipts, Iterable):
        raise TypeError(
            "validate_receipt_source_alignment expected iterable of SecurityReceipt, "
            f"got {type(receipts).__name__}"
        )

    materialized = tuple(receipts)
    for index, receipt in enumerate(materialized):
        if not isinstance(receipt, SecurityReceipt):
            raise TypeError(
                "validate_receipt_source_alignment expected SecurityReceipt at "
                f"index {index}, got {type(receipt).__name__}"
            )

    return ReceiptSourceAlignmentValidation(
        receipts=materialized,
        expected_source=expected_source,
        mismatched_source_receipt_ids=tuple(
            receipt.receipt_id
            for receipt in materialized
            if receipt.source != expected_source
        ),
    )


def require_valid_receipt_source_alignment(
    validation: ReceiptSourceAlignmentValidation,
) -> tuple[SecurityReceipt, ...]:
    """Return supplied receipts or fail closed on visible source-label drift."""
    if not isinstance(validation, ReceiptSourceAlignmentValidation):
        raise TypeError(
            "require_valid_receipt_source_alignment expected "
            f"ReceiptSourceAlignmentValidation, got {type(validation).__name__}"
        )
    if receipt_source_alignment_signals(validation):
        raise ReceiptSourceAlignmentError(validation)
    return validation.receipts


@dataclass(frozen=True)
class ReceiptScopeValidation:
    """Run-scope diagnostics for one materialized receipt bundle.

    This result preserves the input order in ``receipts`` and reports only
    collector-visible ``run_id`` inconsistencies against one caller-selected
    ``expected_run_id``. It does not authenticate receipt sources, verify
    coverage, inspect application attributes, enforce receipt-id uniqueness,
    correlate receipts to effects, or prove backend truth.

    A clean empty result means only that none of the supplied receipts
    contradicted the requested run scope. It does not prove that no receipts
    exist or that collection was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_receipt_scope` performs.
    """

    receipts: tuple[SecurityReceipt, ...]
    expected_run_id: str
    missing_run_id_receipt_ids: tuple[str, ...] = ()
    mismatched_run_id_receipt_ids: tuple[str, ...] = ()


class ReceiptScopeError(RuntimeError):
    """Raised when supplied receipts do not fit one expected run scope.

    This error reports only diagnostics visible in a
    :class:`ReceiptScopeValidation`. It does not establish receipt
    authenticity, coverage, or semantic correctness.
    """

    def __init__(self, validation: ReceiptScopeValidation) -> None:
        if not isinstance(validation, ReceiptScopeValidation):
            raise TypeError(
                "ReceiptScopeError expected ReceiptScopeValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = receipt_scope_signals(validation)
        if not reasons:
            raise ValueError("ReceiptScopeError requires at least one scope signal")
        self.expected_run_id = validation.expected_run_id
        self.missing_run_id_receipt_ids = validation.missing_run_id_receipt_ids
        self.mismatched_run_id_receipt_ids = validation.mismatched_run_id_receipt_ids
        self.reasons = reasons
        super().__init__(
            "receipt bundle does not match expected run scope: "
            f"expected_run_id={validation.expected_run_id!r}, "
            f"missing_run_id_receipt_ids={validation.missing_run_id_receipt_ids!r}, "
            f"mismatched_run_id_receipt_ids={validation.mismatched_run_id_receipt_ids!r}"
        )


def receipt_scope_signals(validation: ReceiptScopeValidation) -> tuple[ReceiptScopeSignal, ...]:
    """Return canonical run-scope diagnostics for one receipt bundle."""
    if not isinstance(validation, ReceiptScopeValidation):
        raise TypeError(
            "receipt_scope_signals expected ReceiptScopeValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[ReceiptScopeSignal] = []
    if validation.missing_run_id_receipt_ids:
        signals.append("missing_run_id")
    if validation.mismatched_run_id_receipt_ids:
        signals.append("run_id_mismatch")
    return tuple(signals)


def validate_receipt_scope(
    receipts: Iterable[SecurityReceipt],
    *,
    expected_run_id: str,
) -> ReceiptScopeValidation:
    """Materialize receipts and report run-scope inconsistencies.

    ``receipts`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_receipt_scope` when no scope signal
    is present. ``expected_run_id`` must be a non-empty caller-selected scope;
    this helper does not mint or authenticate it.

    The helper checks only that each supplied receipt carries a non-empty
    ``run_id`` equal to ``expected_run_id``. It does not verify source identity,
    receipt coverage, receipt-id uniqueness, receipt-to-effect joins, or
    application-specific receipt semantics.
    """
    if not isinstance(expected_run_id, str):
        raise TypeError(
            "validate_receipt_scope expected str expected_run_id, "
            f"got {type(expected_run_id).__name__}"
        )
    if not expected_run_id:
        raise ValueError("validate_receipt_scope requires non-empty expected_run_id")
    if isinstance(receipts, (str, bytes, bytearray)) or not isinstance(receipts, Iterable):
        raise TypeError(
            "validate_receipt_scope expected iterable of SecurityReceipt, "
            f"got {type(receipts).__name__}"
        )

    materialized = tuple(receipts)
    for index, receipt in enumerate(materialized):
        if not isinstance(receipt, SecurityReceipt):
            raise TypeError(
                "validate_receipt_scope expected SecurityReceipt at "
                f"index {index}, got {type(receipt).__name__}"
            )

    return ReceiptScopeValidation(
        receipts=materialized,
        expected_run_id=expected_run_id,
        missing_run_id_receipt_ids=tuple(
            receipt.receipt_id for receipt in materialized if not receipt.run_id
        ),
        mismatched_run_id_receipt_ids=tuple(
            receipt.receipt_id
            for receipt in materialized
            if receipt.run_id and receipt.run_id != expected_run_id
        ),
    )


def require_valid_receipt_scope(
    validation: ReceiptScopeValidation,
) -> tuple[SecurityReceipt, ...]:
    """Return supplied receipts or fail closed on visible run-scope drift."""
    if not isinstance(validation, ReceiptScopeValidation):
        raise TypeError(
            "require_valid_receipt_scope expected ReceiptScopeValidation, "
            f"got {type(validation).__name__}"
        )
    if receipt_scope_signals(validation):
        raise ReceiptScopeError(validation)
    return validation.receipts


def _parse_receipt_bundle_document(
    payload: bytes,
) -> ReceiptBundle:
    """Parse one terminated receipt bundle and keep future versions distinct."""
    body = payload[:-1]
    try:
        if body.startswith(b"\xef\xbb\xbf") or body != body.strip():
            raise ValueError("document has BOM or outer whitespace")
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_receipt_bundle_json_object_pairs,
            parse_constant=_reject_non_finite_receipt_bundle_json_constant,
            parse_float=_parse_finite_receipt_bundle_json_float,
            parse_int=_parse_safe_receipt_bundle_json_int,
        )
        _validate_receipt_bundle_json_value_graph(value)
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid receipt bundle document") from exc

    if isinstance(value, dict) and "schema_version" in value:
        schema_version = value["schema_version"]
        if (
            schema_version != RECEIPT_BUNDLE_SCHEMA_VERSION
            and isinstance(schema_version, str)
            and _RECEIPT_BUNDLE_SCHEMA_VERSION_RE.fullmatch(schema_version)
        ):
            raise UnsupportedReceiptBundleVersionError(schema_version)
    if not isinstance(value, dict) or frozenset(value) != RECEIPT_BUNDLE_KEYS:
        raise ValueError("invalid receipt bundle document")

    try:
        return ReceiptBundle.model_validate(value)
    except ValidationError as exc:
        raise ValueError("invalid receipt bundle document") from exc


def _reject_duplicate_receipt_bundle_json_object_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """Reject duplicate object keys so readers cannot disagree on last-wins behavior."""
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON object key: {key}")
        payload[key] = value
    return payload


def _reject_non_finite_receipt_bundle_json_constant(token: str) -> Never:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""
    raise ValueError(f"non-finite JSON constant: {token}")


def _parse_finite_receipt_bundle_json_float(token: str) -> float:
    """Parse a JSON float while rejecting finite-looking overflow literals."""
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON float: {token}")
    return value


def _parse_safe_receipt_bundle_json_int(token: str) -> int:
    """Parse a JSON integer while rejecting values unsafe in IEEE-754 readers."""
    value = int(token)
    if abs(value) > MAX_RECEIPT_BUNDLE_JSON_INTEGER:
        raise ValueError(f"JSON integer exceeds safe range: {token}")
    return value


def _validate_receipt_bundle_json_value_graph(payload: object) -> None:
    """Reject strings and values that make receipt-bundle JSON non-portable."""
    pending: list[tuple[object, bool]] = [(payload, False)]
    active_container_ids: set[int] = set()
    validated_container_ids: set[int] = set()
    while pending:
        value, exiting = pending.pop()
        if exiting:
            container_id = id(value)
            active_container_ids.remove(container_id)
            validated_container_ids.add(container_id)
            continue
        if value is None or isinstance(value, bool):
            continue
        if isinstance(value, int):
            if abs(value) > MAX_RECEIPT_BUNDLE_JSON_INTEGER:
                raise ValueError("JSON integer exceeds safe range")
            continue
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("JSON value contains a non-finite float")
            continue
        if isinstance(value, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                raise ValueError("JSON string contains a lone surrogate")
            continue
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("JSON object key is not a string")
            container_id = id(value)
            if container_id in active_container_ids:
                raise ValueError("JSON value graph contains a cycle")
            if container_id in validated_container_ids:
                continue
            active_container_ids.add(container_id)
            pending.append((value, True))
            pending.extend((child, False) for child in value.keys())
            pending.extend((child, False) for child in value.values())
            continue
        if isinstance(value, list):
            container_id = id(value)
            if container_id in active_container_ids:
                raise ValueError("JSON value graph contains a cycle")
            if container_id in validated_container_ids:
                continue
            active_container_ids.add(container_id)
            pending.append((value, True))
            pending.extend((child, False) for child in value)
            continue
        raise ValueError(f"value is not JSON-native: {type(value).__name__}")


def _validate_max_bundle_bytes(max_bundle_bytes: int) -> int:
    """Validate a receipt-bundle byte budget."""
    return _validate_positive_receipt_bundle_int(max_bundle_bytes, name="max_bundle_bytes")


def _validate_max_receipts(max_receipts: int) -> int:
    """Validate a receipt-bundle count budget."""
    return _validate_positive_receipt_bundle_int(max_receipts, name="max_receipts")


def _validate_positive_receipt_bundle_int(value: int, *, name: str) -> int:
    """Validate one positive integer limit while rejecting bools explicitly."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} expected int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _read_receipt_bundle_binary_chunk(chunk: object) -> bytes:
    """Keep binary-stream type failures consistent across receipt reads."""
    if not isinstance(chunk, bytes):
        raise TypeError(f"read_receipt_bundle expected binary stream, got {type(chunk).__name__}")
    return chunk
