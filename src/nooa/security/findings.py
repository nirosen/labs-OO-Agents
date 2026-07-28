# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security finding transport and opt-in row-validation helpers."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Annotated, BinaryIO, Literal, Never

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError
from pydantic_core import PydanticSerializationError

EvidenceRef = Annotated[str, Field(min_length=1)]
FINDING_BUNDLE_SCHEMA_VERSION: Literal["nooa-finding-bundle-v1"] = "nooa-finding-bundle-v1"
FINDING_BUNDLE_SCHEMA_VERSION_PATTERN: str = r"nooa-finding-bundle-v[1-9][0-9]*"
FINDING_BUNDLE_SCHEMA_VERSION_PATTERN_MATCH_MODE: Literal["full"] = "full"
FINDING_BUNDLE_KEYS: frozenset[str] = frozenset({"schema_version", "producer", "findings"})
FindingBundleCompletenessSignal = Literal["truncated"]
# Tuple order is public because FindingBundleIncompleteError.reasons preserves it.
FINDING_BUNDLE_COMPLETENESS_SIGNALS: tuple[FindingBundleCompletenessSignal, ...] = (
    "truncated",
)
MAX_FINDING_BUNDLE_JSON_INTEGER: int = (1 << 53) - 1
DEFAULT_FINDING_BUNDLE_MAX_BYTES: int = 1024 * 1024
DEFAULT_FINDING_BUNDLE_MAX_FINDINGS: int = 1 << 20

FindingIdUniquenessSignal = Literal["duplicate_finding_id"]
# Tuple order is public because FindingIdUniquenessError.reasons preserves it.
FINDING_ID_UNIQUENESS_SIGNALS: tuple[FindingIdUniquenessSignal, ...] = (
    "duplicate_finding_id",
)

FindingEvidenceRefSignal = Literal["unknown_evidence_ref"]
# Tuple order is public because FindingEvidenceRefError.reasons preserves it.
FINDING_EVIDENCE_REF_SIGNALS: tuple[FindingEvidenceRefSignal, ...] = (
    "unknown_evidence_ref",
)

FindingRequiredEvidenceRefSignal = Literal["missing_required_evidence_ref"]
# Tuple order is public because FindingRequiredEvidenceRefError.reasons preserves it.
FINDING_REQUIRED_EVIDENCE_REF_SIGNALS: tuple[FindingRequiredEvidenceRefSignal, ...] = (
    "missing_required_evidence_ref",
)

FindingScopeSignal = Literal["missing_run_id", "run_id_mismatch"]
# Tuple order is public because FindingScopeError.reasons preserves it.
FINDING_SCOPE_SIGNALS: tuple[FindingScopeSignal, ...] = (
    "missing_run_id",
    "run_id_mismatch",
)

_FINDING_BUNDLE_SCHEMA_VERSION_RE = re.compile(FINDING_BUNDLE_SCHEMA_VERSION_PATTERN)


class SecurityFinding(BaseModel):
    """Transport schema for detector or scorer findings.

    A ``SecurityFinding`` is a portable record shape, not a detector, policy
    engine, or trust boundary. It does not authenticate ``producer``, verify
    that ``evidence_refs`` exist, or make data constructed inside a victim
    process trustworthy. A finding is only as trustworthy as the execution and
    collection boundary that produced it.

    ``run_id`` is application-assigned scope for grouping findings from one
    run or assessment; NOOA does not mint it, verify it, or infer that equal
    values establish trusted provenance. ``evidence_refs`` are opaque
    identifiers so applications can point at ``EffectRecord.id``,
    ``SecurityReceipt.receipt_id``, SIEM records, or other evidence without
    making NOOA own the join semantics. The schema
    intentionally does not standardize severity, verdict, or enforcement
    action; those remain application policy. Field bindings are frozen for
    transport stability, but nested ``attributes`` values remain ordinary
    Python containers and are not a tamper-resistance boundary.

    ``attributes`` must contain sanitized JSON values only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-finding-v1"] = Field(
        default="nooa-finding-v1",
        description="Finding wire-format discriminator.",
    )
    finding_id: str = Field(
        min_length=1,
        description="Stable finding identifier assigned by the producer.",
    )
    finding_type: str = Field(
        min_length=1,
        description="Application-defined finding category, e.g. 'prompt_injection.suspected'.",
    )
    producer: str = Field(
        min_length=1,
        description="Sanitized identifier for the detector, scorer, or policy producer.",
    )
    run_id: str = Field(
        default="",
        description="Application-assigned run or assessment scope for grouping related findings.",
    )
    target: str = Field(
        default="",
        description="Sanitized target identifier for the finding, if any.",
    )
    evidence_refs: tuple[EvidenceRef, ...] = Field(
        default_factory=tuple,
        description="Opaque identifiers for evidence that supports this finding.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined finding details.",
    )


class UnsupportedFindingBundleVersionError(ValueError):
    """Raised when a reader sees a well-formed future finding bundle version."""

    def __init__(self, schema_version: object) -> None:
        self.schema_version = schema_version
        super().__init__(f"unsupported finding bundle schema_version: {schema_version!r}")


class FindingBundleInputTooLargeError(ValueError):
    """Raised when a writer or reader refuses an over-bound finding bundle."""

    def __init__(
        self,
        limit_name: Literal["max_bundle_bytes", "max_findings"],
        limit_value: int,
    ) -> None:
        self.limit_name = limit_name
        self.limit_value = limit_value
        super().__init__(f"finding bundle exceeds {limit_name}={limit_value}")


class FindingBundle(BaseModel):
    """One collector-facing finding bundle document.

    The bundle is a transport shape, not a verdict, severity, enforcement
    action, detector-coverage proof, finding-id uniqueness guarantee, or
    evidence-reference validator. ``producer`` is a caller-supplied assertion
    about the bundle source; it does not constrain row-level
    :attr:`SecurityFinding.producer` values or authenticate either one.

    A clean empty bundle means only that the reader saw one terminated document
    with zero supplied findings. It does not prove that nothing was found.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-finding-bundle-v1"] = Field(
        default=FINDING_BUNDLE_SCHEMA_VERSION,
        description="Finding bundle wire-format discriminator.",
    )
    producer: str = Field(
        default="",
        description="Sanitized identifier for the asserted finding bundle producer.",
    )
    findings: tuple[SecurityFinding, ...] = Field(
        default_factory=tuple,
        description="Application-supplied finding copies carried by the document.",
    )


@dataclass(frozen=True)
class FindingBundleReadResult:
    """Parsed finding bundle plus reader-visible document diagnostics.

    ``truncated=True`` means the reader reached EOF before the first required LF
    terminator. The reader does not parse an unterminated prefix, even when the
    prefix is otherwise valid JSON. ``bundle`` is therefore ``None`` for
    reader-produced truncated results. Direct construction only asserts these
    fields; it does not perform the checks in :func:`read_finding_bundle`.
    """

    bundle: FindingBundle | None
    truncated: bool = False

    def __post_init__(self) -> None:
        if self.bundle is None and not self.truncated:
            raise ValueError("FindingBundleReadResult without a bundle must be truncated")


class FindingBundleIncompleteError(RuntimeError):
    """Raised when known reader diagnostics show degraded finding transport.

    This error reports only degradation visible in a
    :class:`FindingBundleReadResult`. It does not authenticate finding bytes,
    prove detector coverage, or establish that no omitted findings exist.
    """

    def __init__(self, result: FindingBundleReadResult) -> None:
        if not isinstance(result, FindingBundleReadResult):
            raise TypeError(
                "FindingBundleIncompleteError expected FindingBundleReadResult, "
                f"got {type(result).__name__}"
            )
        reasons = finding_bundle_completeness_signals(result)
        if not reasons:
            raise ValueError(
                "FindingBundleIncompleteError requires at least one completeness signal"
            )
        self.bundle = result.bundle
        self.truncated = result.truncated
        self.producer = result.bundle.producer if result.bundle is not None else None
        self.finding_count = len(result.bundle.findings) if result.bundle is not None else None
        self.reasons = reasons
        super().__init__(
            "finding bundle is incomplete: "
            f"truncated={result.truncated!r}, "
            f"producer={self.producer!r}, "
            f"finding_count={self.finding_count!r}"
        )


def write_finding_bundle(
    fh: BinaryIO,
    bundle: FindingBundle,
    *,
    max_bundle_bytes: int = DEFAULT_FINDING_BUNDLE_MAX_BYTES,
    max_findings: int = DEFAULT_FINDING_BUNDLE_MAX_FINDINGS,
) -> None:
    """Write one LF-terminated finding bundle document to a binary stream.

    The helper bounds one serialized document and the number of finding copies
    it is willing to emit; those limits are resource backstops, not
    authenticity, coverage, or verdict guarantees.
    """
    if type(bundle) is not FindingBundle:
        raise TypeError(
            "write_finding_bundle expected FindingBundle, "
            f"got {type(bundle).__name__}"
        )
    max_bundle_bytes = _validate_max_bundle_bytes(max_bundle_bytes)
    max_findings = _validate_max_findings(max_findings)
    if len(bundle.findings) > max_findings:
        raise FindingBundleInputTooLargeError("max_findings", max_findings)
    for index, finding in enumerate(bundle.findings):
        if type(finding) is not SecurityFinding:
            raise TypeError(
                "write_finding_bundle expected SecurityFinding at "
                f"index {index}, got {type(finding).__name__}"
            )
    try:
        for finding in bundle.findings:
            _validate_finding_bundle_json_value_graph(finding.attributes)
        payload_value = bundle.model_dump(mode="json")
        _validate_finding_bundle_json_value_graph(payload_value)
        payload = (bundle.model_dump_json() + "\n").encode("utf-8")
    except (PydanticSerializationError, UnicodeEncodeError, ValidationError, ValueError) as exc:
        raise TypeError(
            f"write_finding_bundle expected JSON-safe FindingBundle, got {type(bundle).__name__}"
        ) from exc
    if len(payload) > max_bundle_bytes:
        raise FindingBundleInputTooLargeError("max_bundle_bytes", max_bundle_bytes)
    written = fh.write(payload)
    if written != len(payload):
        raise OSError(f"finding bundle writer wrote {written} of {len(payload)} bytes")
    fh.flush()


def read_finding_bundle(
    fh: BinaryIO,
    *,
    max_bundle_bytes: int = DEFAULT_FINDING_BUNDLE_MAX_BYTES,
    max_findings: int = DEFAULT_FINDING_BUNDLE_MAX_FINDINGS,
) -> FindingBundleReadResult:
    """Read exactly one bounded LF-terminated finding bundle document.

    The reader consumes at most one document line from the stream's current
    position and leaves any later bytes unread. Empty input and an unterminated
    first line return ``FindingBundleReadResult(truncated=True)``. A malformed
    terminated document raises :class:`ValueError`; a well-formed future schema
    version raises :class:`UnsupportedFindingBundleVersionError`; and
    over-bound input raises :class:`FindingBundleInputTooLargeError`.

    ``max_bundle_bytes`` includes the required trailing LF byte. ``max_findings``
    is an admission bound checked after the bounded JSON document has been
    parsed; callers that need a tighter parser-memory ceiling should reduce the
    byte budget as well.
    """
    max_bundle_bytes = _validate_max_bundle_bytes(max_bundle_bytes)
    max_findings = _validate_max_findings(max_findings)
    payload = _read_finding_bundle_binary_chunk(fh.readline(max_bundle_bytes + 1))
    if len(payload) > max_bundle_bytes:
        raise FindingBundleInputTooLargeError("max_bundle_bytes", max_bundle_bytes)
    if not payload or not payload.endswith(b"\n"):
        return FindingBundleReadResult(bundle=None, truncated=True)

    bundle = _parse_finding_bundle_document(payload)
    if len(bundle.findings) > max_findings:
        raise FindingBundleInputTooLargeError("max_findings", max_findings)
    return FindingBundleReadResult(bundle=bundle)


def require_complete_finding_bundle(result: FindingBundleReadResult) -> FindingBundle:
    """Return one parsed bundle only when received bytes show no known degradation.

    A clean result means only that the reader received one LF-terminated
    document. It does not authenticate finding bytes, prove detector coverage,
    or establish that no omitted findings exist.
    """
    if not isinstance(result, FindingBundleReadResult):
        raise TypeError(
            "require_complete_finding_bundle expected FindingBundleReadResult, "
            f"got {type(result).__name__}"
        )
    if finding_bundle_completeness_signals(result):
        raise FindingBundleIncompleteError(result)
    if result.bundle is None:
        raise ValueError("complete FindingBundleReadResult requires a parsed bundle")
    return result.bundle


def finding_bundle_completeness_signals(
    result: FindingBundleReadResult,
) -> tuple[FindingBundleCompletenessSignal, ...]:
    """Return known finding-bundle diagnostics in canonical public order.

    The returned tuple describes only degradation visible in one
    :class:`FindingBundleReadResult`. An empty tuple does not prove that the
    producer emitted every finding or that the bytes are authentic.
    """
    if not isinstance(result, FindingBundleReadResult):
        raise TypeError(
            "finding_bundle_completeness_signals expected FindingBundleReadResult, "
            f"got {type(result).__name__}"
        )
    reasons: list[FindingBundleCompletenessSignal] = []
    if result.truncated:
        reasons.append("truncated")
    return tuple(reasons)


@dataclass(frozen=True)
class FindingIdUniquenessValidation:
    """Identifier-uniqueness diagnostics for one materialized finding iterable.

    This result preserves the input order in ``findings`` and reports only
    repeated ``finding_id`` values inside one supplied iterable. It does not
    authenticate finding rows, producers, or identifiers; prove that distinct
    identifiers denote distinct findings; establish uniqueness across bundles,
    runs, or producers; dereference identifiers against any external system;
    or prove detector coverage.

    A clean empty result means only that none of the supplied rows shared a
    ``finding_id``. It does not prove that no findings exist or that detector
    coverage was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_finding_id_uniqueness` performs.
    """

    findings: tuple[SecurityFinding, ...]
    duplicate_finding_ids: tuple[str, ...] = ()


class FindingIdUniquenessError(RuntimeError):
    """Raised when supplied findings reuse one or more finding identifiers.

    This error reports only diagnostics visible in a
    :class:`FindingIdUniquenessValidation`. It does not establish finding
    authenticity, detector coverage, or semantic correctness.
    """

    def __init__(self, validation: FindingIdUniquenessValidation) -> None:
        if not isinstance(validation, FindingIdUniquenessValidation):
            raise TypeError(
                "FindingIdUniquenessError expected FindingIdUniquenessValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = finding_id_uniqueness_signals(validation)
        if not reasons:
            raise ValueError(
                "FindingIdUniquenessError requires at least one uniqueness signal"
            )
        self.duplicate_finding_ids = validation.duplicate_finding_ids
        self.reasons = reasons
        super().__init__(
            "finding rows reuse finding_id values: "
            f"duplicate_finding_ids={validation.duplicate_finding_ids!r}"
        )


def finding_id_uniqueness_signals(
    validation: FindingIdUniquenessValidation,
) -> tuple[FindingIdUniquenessSignal, ...]:
    """Return canonical identifier diagnostics for one finding iterable."""
    if not isinstance(validation, FindingIdUniquenessValidation):
        raise TypeError(
            "finding_id_uniqueness_signals expected FindingIdUniquenessValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[FindingIdUniquenessSignal] = []
    if validation.duplicate_finding_ids:
        signals.append("duplicate_finding_id")
    return tuple(signals)


def validate_finding_id_uniqueness(
    findings: Iterable[SecurityFinding],
) -> FindingIdUniquenessValidation:
    """Materialize findings and report repeated finding identifiers.

    ``findings`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_finding_id_uniqueness` when no
    uniqueness signal is present.

    The helper checks only whether the supplied rows reuse ``finding_id``
    values. It does not authenticate rows, producers, or identifiers; prove
    that distinct identifiers denote distinct findings; establish uniqueness
    across bundles, runs, or producers; dereference identifiers against any
    external system; or prove detector coverage.
    """
    if isinstance(findings, (str, bytes, bytearray)) or not isinstance(findings, Iterable):
        raise TypeError(
            "validate_finding_id_uniqueness expected iterable of SecurityFinding, "
            f"got {type(findings).__name__}"
        )

    materialized = tuple(findings)
    for index, finding in enumerate(materialized):
        if not isinstance(finding, SecurityFinding):
            raise TypeError(
                "validate_finding_id_uniqueness expected SecurityFinding at "
                f"index {index}, got {type(finding).__name__}"
            )

    seen_ids: set[str] = set()
    duplicate_ids: list[str] = []
    reported_duplicate_ids: set[str] = set()
    for finding in materialized:
        finding_id = finding.finding_id
        if finding_id in seen_ids and finding_id not in reported_duplicate_ids:
            duplicate_ids.append(finding_id)
            reported_duplicate_ids.add(finding_id)
        seen_ids.add(finding_id)

    return FindingIdUniquenessValidation(
        findings=materialized,
        duplicate_finding_ids=tuple(duplicate_ids),
    )


def require_valid_finding_id_uniqueness(
    validation: FindingIdUniquenessValidation,
) -> tuple[SecurityFinding, ...]:
    """Return supplied findings or fail closed on repeated finding identifiers."""
    if not isinstance(validation, FindingIdUniquenessValidation):
        raise TypeError(
            "require_valid_finding_id_uniqueness expected FindingIdUniquenessValidation, "
            f"got {type(validation).__name__}"
        )
    if finding_id_uniqueness_signals(validation):
        raise FindingIdUniquenessError(validation)
    return validation.findings


@dataclass(frozen=True)
class FindingEvidenceRefValidation:
    """Evidence-reference membership diagnostics for one finding iterable.

    This result preserves the input order in ``findings`` and reports only
    evidence references not present in one caller-supplied
    ``allowed_evidence_ids`` iterable. It does not authenticate findings,
    evidence identifiers, or the allowed set; dereference identifiers against
    any external system; prove that present references support a finding;
    require that a finding cite any evidence at all; or prove detector
    coverage.

    ``allowed_evidence_ids`` is stored in first-seen unique order after exact
    string comparison. Case, whitespace, and Unicode normalization remain
    caller policy. A clean empty result means only that no supplied finding
    referenced an ID outside the supplied set.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_finding_evidence_ref_membership`
    performs.
    """

    findings: tuple[SecurityFinding, ...]
    allowed_evidence_ids: tuple[str, ...]
    unknown_evidence_refs: tuple[str, ...] = ()
    unknown_evidence_ref_finding_ids: tuple[str, ...] = ()


class FindingEvidenceRefError(RuntimeError):
    """Raised when supplied findings reference IDs outside one supplied set.

    This error reports only diagnostics visible in a
    :class:`FindingEvidenceRefValidation`. It does not establish finding or
    evidence authenticity, detector coverage, or semantic correctness.
    """

    def __init__(self, validation: FindingEvidenceRefValidation) -> None:
        if not isinstance(validation, FindingEvidenceRefValidation):
            raise TypeError(
                "FindingEvidenceRefError expected FindingEvidenceRefValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = finding_evidence_ref_signals(validation)
        if not reasons:
            raise ValueError(
                "FindingEvidenceRefError requires at least one evidence-ref signal"
            )
        self.unknown_evidence_refs = validation.unknown_evidence_refs
        self.unknown_evidence_ref_finding_ids = validation.unknown_evidence_ref_finding_ids
        self.allowed_evidence_id_count = len(validation.allowed_evidence_ids)
        self.reasons = reasons
        super().__init__(
            "finding rows reference evidence IDs outside the allowed set: "
            f"unknown_evidence_refs={validation.unknown_evidence_refs!r}, "
            "unknown_evidence_ref_finding_ids="
            f"{validation.unknown_evidence_ref_finding_ids!r}, "
            f"allowed_evidence_id_count={self.allowed_evidence_id_count!r}"
        )


def finding_evidence_ref_signals(
    validation: FindingEvidenceRefValidation,
) -> tuple[FindingEvidenceRefSignal, ...]:
    """Return canonical evidence-reference diagnostics for one finding iterable."""
    if not isinstance(validation, FindingEvidenceRefValidation):
        raise TypeError(
            "finding_evidence_ref_signals expected FindingEvidenceRefValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[FindingEvidenceRefSignal] = []
    if validation.unknown_evidence_refs:
        signals.append("unknown_evidence_ref")
    return tuple(signals)


def validate_finding_evidence_ref_membership(
    findings: Iterable[SecurityFinding],
    *,
    allowed_evidence_ids: Iterable[str],
) -> FindingEvidenceRefValidation:
    """Materialize findings and report references outside one supplied ID set.

    ``findings`` and ``allowed_evidence_ids`` are each consumed once. Findings
    preserve input order; allowed IDs are stored in first-seen unique order and
    compared exactly as supplied. The tuple returned by
    :func:`require_valid_finding_evidence_ref_membership` is the materialized
    finding tuple when no evidence-reference signal is present.

    The helper checks only whether each supplied ``evidence_ref`` is present in
    one caller-supplied allowed-ID iterable. It does not authenticate findings,
    producers, identifiers, or the allowed set; dereference identifiers;
    establish that present references support the finding; require evidence to
    exist; or prove detector coverage.
    """
    if isinstance(findings, (str, bytes, bytearray)) or not isinstance(findings, Iterable):
        raise TypeError(
            "validate_finding_evidence_ref_membership expected iterable of "
            f"SecurityFinding, got {type(findings).__name__}"
        )
    if isinstance(allowed_evidence_ids, (str, bytes, bytearray)) or not isinstance(
        allowed_evidence_ids, Iterable
    ):
        raise TypeError(
            "validate_finding_evidence_ref_membership expected iterable of str "
            f"allowed_evidence_ids, got {type(allowed_evidence_ids).__name__}"
        )

    materialized = tuple(findings)
    for index, finding in enumerate(materialized):
        if not isinstance(finding, SecurityFinding):
            raise TypeError(
                "validate_finding_evidence_ref_membership expected SecurityFinding at "
                f"index {index}, got {type(finding).__name__}"
            )

    allowed_ids = tuple(allowed_evidence_ids)
    for index, evidence_id in enumerate(allowed_ids):
        if not isinstance(evidence_id, str):
            raise TypeError(
                "validate_finding_evidence_ref_membership expected str "
                f"allowed_evidence_ids at index {index}, got {type(evidence_id).__name__}"
            )
        if not evidence_id:
            raise ValueError(
                "validate_finding_evidence_ref_membership requires non-empty "
                f"allowed_evidence_ids at index {index}"
            )

    canonical_allowed_ids = tuple(dict.fromkeys(allowed_ids))
    allowed_id_set = set(canonical_allowed_ids)
    unknown_refs: list[str] = []
    reported_unknown_refs: set[str] = set()
    unknown_ref_finding_ids: list[str] = []
    for finding in materialized:
        finding_has_unknown_ref = False
        for evidence_ref in finding.evidence_refs:
            if evidence_ref in allowed_id_set:
                continue
            finding_has_unknown_ref = True
            if evidence_ref not in reported_unknown_refs:
                unknown_refs.append(evidence_ref)
                reported_unknown_refs.add(evidence_ref)
        if finding_has_unknown_ref:
            unknown_ref_finding_ids.append(finding.finding_id)

    return FindingEvidenceRefValidation(
        findings=materialized,
        allowed_evidence_ids=canonical_allowed_ids,
        unknown_evidence_refs=tuple(unknown_refs),
        unknown_evidence_ref_finding_ids=tuple(unknown_ref_finding_ids),
    )


def require_valid_finding_evidence_ref_membership(
    validation: FindingEvidenceRefValidation,
) -> tuple[SecurityFinding, ...]:
    """Return supplied findings or fail closed on references outside one ID set."""
    if not isinstance(validation, FindingEvidenceRefValidation):
        raise TypeError(
            "require_valid_finding_evidence_ref_membership expected "
            f"FindingEvidenceRefValidation, got {type(validation).__name__}"
        )
    if finding_evidence_ref_signals(validation):
        raise FindingEvidenceRefError(validation)
    return validation.findings


@dataclass(frozen=True)
class FindingRequiredEvidenceRefValidation:
    """Required evidence-reference diagnostics for one finding iterable.

    This result preserves the input order in ``findings`` and reports only
    supplied rows that do not contain one caller-selected
    ``required_evidence_ref`` exact string. It does not authenticate findings,
    evidence identifiers, or the required ref; prove that the required ref
    resolves to anything real or supports a finding; require any additional
    references; or prove detector coverage.

    A clean empty result means only that no supplied finding contradicted this
    one presence requirement. Direct construction only asserts these
    diagnostic fields; it does not perform the check that
    :func:`validate_finding_required_evidence_ref` performs.
    """

    findings: tuple[SecurityFinding, ...]
    required_evidence_ref: str
    missing_required_evidence_ref_finding_ids: tuple[str, ...] = ()


class FindingRequiredEvidenceRefError(RuntimeError):
    """Raised when supplied findings omit one caller-selected required ref.

    This error reports only diagnostics visible in a
    :class:`FindingRequiredEvidenceRefValidation`. It does not establish
    finding or evidence authenticity, detector coverage, or semantic
    correctness.
    """

    def __init__(self, validation: FindingRequiredEvidenceRefValidation) -> None:
        if not isinstance(validation, FindingRequiredEvidenceRefValidation):
            raise TypeError(
                "FindingRequiredEvidenceRefError expected "
                f"FindingRequiredEvidenceRefValidation, got {type(validation).__name__}"
            )
        reasons = finding_required_evidence_ref_signals(validation)
        if not reasons:
            raise ValueError(
                "FindingRequiredEvidenceRefError requires at least one "
                "required-evidence-ref signal"
            )
        self.required_evidence_ref = validation.required_evidence_ref
        self.missing_required_evidence_ref_finding_ids = (
            validation.missing_required_evidence_ref_finding_ids
        )
        self.reasons = reasons
        super().__init__(
            "finding rows omit required evidence ref: "
            f"required_evidence_ref={validation.required_evidence_ref!r}, "
            "missing_required_evidence_ref_finding_ids="
            f"{validation.missing_required_evidence_ref_finding_ids!r}"
        )


def finding_required_evidence_ref_signals(
    validation: FindingRequiredEvidenceRefValidation,
) -> tuple[FindingRequiredEvidenceRefSignal, ...]:
    """Return canonical required-evidence-ref diagnostics for one finding iterable."""
    if not isinstance(validation, FindingRequiredEvidenceRefValidation):
        raise TypeError(
            "finding_required_evidence_ref_signals expected "
            f"FindingRequiredEvidenceRefValidation, got {type(validation).__name__}"
        )
    signals: list[FindingRequiredEvidenceRefSignal] = []
    if validation.missing_required_evidence_ref_finding_ids:
        signals.append("missing_required_evidence_ref")
    return tuple(signals)


def validate_finding_required_evidence_ref(
    findings: Iterable[SecurityFinding],
    *,
    required_evidence_ref: str,
) -> FindingRequiredEvidenceRefValidation:
    """Materialize findings and report rows missing one required exact ref.

    ``findings`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_finding_required_evidence_ref` when
    no required-evidence-ref signal is present. ``required_evidence_ref`` must
    be a non-empty caller-selected exact string; this helper does not mint or
    authenticate it.

    The helper checks only whether each supplied finding contains that exact
    string in ``evidence_refs``. It does not authenticate findings, producers,
    identifiers, or the required ref; dereference identifiers; prove that the
    present ref supports the finding; require any other evidence; or prove
    detector coverage.
    """
    if not isinstance(required_evidence_ref, str):
        raise TypeError(
            "validate_finding_required_evidence_ref expected str required_evidence_ref, "
            f"got {type(required_evidence_ref).__name__}"
        )
    if not required_evidence_ref:
        raise ValueError(
            "validate_finding_required_evidence_ref requires non-empty "
            "required_evidence_ref"
        )
    if isinstance(findings, (str, bytes, bytearray)) or not isinstance(findings, Iterable):
        raise TypeError(
            "validate_finding_required_evidence_ref expected iterable of "
            f"SecurityFinding, got {type(findings).__name__}"
        )

    materialized = tuple(findings)
    for index, finding in enumerate(materialized):
        if not isinstance(finding, SecurityFinding):
            raise TypeError(
                "validate_finding_required_evidence_ref expected SecurityFinding at "
                f"index {index}, got {type(finding).__name__}"
            )

    return FindingRequiredEvidenceRefValidation(
        findings=materialized,
        required_evidence_ref=required_evidence_ref,
        missing_required_evidence_ref_finding_ids=tuple(
            finding.finding_id
            for finding in materialized
            if required_evidence_ref not in finding.evidence_refs
        ),
    )


def require_valid_finding_required_evidence_ref(
    validation: FindingRequiredEvidenceRefValidation,
) -> tuple[SecurityFinding, ...]:
    """Return supplied findings or fail closed when one required ref is absent."""
    if not isinstance(validation, FindingRequiredEvidenceRefValidation):
        raise TypeError(
            "require_valid_finding_required_evidence_ref expected "
            f"FindingRequiredEvidenceRefValidation, got {type(validation).__name__}"
        )
    if finding_required_evidence_ref_signals(validation):
        raise FindingRequiredEvidenceRefError(validation)
    return validation.findings


@dataclass(frozen=True)
class FindingScopeValidation:
    """Run-scope diagnostics for one materialized finding iterable.

    This result preserves the input order in ``findings`` and reports only
    caller-visible ``run_id`` inconsistencies against one caller-selected
    ``expected_run_id``. It does not authenticate finding producers, verify
    evidence references, enforce finding-id uniqueness, determine verdicts or
    severity, or prove that a detector found everything it should have.

    A clean empty result means only that none of the supplied findings
    contradicted the requested run scope. It does not prove that no findings
    exist or that detector coverage was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_finding_scope` performs.
    """

    findings: tuple[SecurityFinding, ...]
    expected_run_id: str
    missing_run_id_finding_ids: tuple[str, ...] = ()
    mismatched_run_id_finding_ids: tuple[str, ...] = ()


class FindingScopeError(RuntimeError):
    """Raised when supplied findings do not fit one expected run scope.

    This error reports only diagnostics visible in a
    :class:`FindingScopeValidation`. It does not establish finding
    authenticity, detector coverage, or semantic correctness.
    """

    def __init__(self, validation: FindingScopeValidation) -> None:
        if not isinstance(validation, FindingScopeValidation):
            raise TypeError(
                "FindingScopeError expected FindingScopeValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = finding_scope_signals(validation)
        if not reasons:
            raise ValueError("FindingScopeError requires at least one scope signal")
        self.expected_run_id = validation.expected_run_id
        self.missing_run_id_finding_ids = validation.missing_run_id_finding_ids
        self.mismatched_run_id_finding_ids = validation.mismatched_run_id_finding_ids
        self.reasons = reasons
        super().__init__(
            "finding rows do not match expected run scope: "
            f"expected_run_id={validation.expected_run_id!r}, "
            f"missing_run_id_finding_ids={validation.missing_run_id_finding_ids!r}, "
            f"mismatched_run_id_finding_ids={validation.mismatched_run_id_finding_ids!r}"
        )


def finding_scope_signals(validation: FindingScopeValidation) -> tuple[FindingScopeSignal, ...]:
    """Return canonical run-scope diagnostics for one finding iterable."""
    if not isinstance(validation, FindingScopeValidation):
        raise TypeError(
            "finding_scope_signals expected FindingScopeValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[FindingScopeSignal] = []
    if validation.missing_run_id_finding_ids:
        signals.append("missing_run_id")
    if validation.mismatched_run_id_finding_ids:
        signals.append("run_id_mismatch")
    return tuple(signals)


def validate_finding_scope(
    findings: Iterable[SecurityFinding],
    *,
    expected_run_id: str,
) -> FindingScopeValidation:
    """Materialize findings and report run-scope inconsistencies.

    ``findings`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_finding_scope` when no scope signal
    is present. ``expected_run_id`` must be a non-empty caller-selected scope;
    this helper does not mint or authenticate it.

    The helper checks only that each supplied finding carries a non-empty
    ``run_id`` equal to ``expected_run_id``. It does not verify producer
    identity, detector coverage, finding-id uniqueness, evidence references,
    or application-specific finding semantics.
    """
    if not isinstance(expected_run_id, str):
        raise TypeError(
            "validate_finding_scope expected str expected_run_id, "
            f"got {type(expected_run_id).__name__}"
        )
    if not expected_run_id:
        raise ValueError("validate_finding_scope requires non-empty expected_run_id")
    if isinstance(findings, (str, bytes, bytearray)) or not isinstance(findings, Iterable):
        raise TypeError(
            "validate_finding_scope expected iterable of SecurityFinding, "
            f"got {type(findings).__name__}"
        )

    materialized = tuple(findings)
    for index, finding in enumerate(materialized):
        if not isinstance(finding, SecurityFinding):
            raise TypeError(
                "validate_finding_scope expected SecurityFinding at "
                f"index {index}, got {type(finding).__name__}"
            )

    return FindingScopeValidation(
        findings=materialized,
        expected_run_id=expected_run_id,
        missing_run_id_finding_ids=tuple(
            finding.finding_id for finding in materialized if not finding.run_id
        ),
        mismatched_run_id_finding_ids=tuple(
            finding.finding_id
            for finding in materialized
            if finding.run_id and finding.run_id != expected_run_id
        ),
    )


def require_valid_finding_scope(
    validation: FindingScopeValidation,
) -> tuple[SecurityFinding, ...]:
    """Return supplied findings or fail closed on visible run-scope drift."""
    if not isinstance(validation, FindingScopeValidation):
        raise TypeError(
            "require_valid_finding_scope expected FindingScopeValidation, "
            f"got {type(validation).__name__}"
        )
    if finding_scope_signals(validation):
        raise FindingScopeError(validation)
    return validation.findings


def _parse_finding_bundle_document(payload: bytes) -> FindingBundle:
    """Parse one terminated finding bundle and keep future versions distinct."""
    body = payload[:-1]
    try:
        if body.startswith(b"\xef\xbb\xbf") or body != body.strip():
            raise ValueError("document has BOM or outer whitespace")
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_finding_bundle_json_object_pairs,
            parse_constant=_reject_non_finite_finding_bundle_json_constant,
            parse_float=_parse_finite_finding_bundle_json_float,
            parse_int=_parse_safe_finding_bundle_json_int,
        )
        _validate_finding_bundle_json_value_graph(value)
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid finding bundle document") from exc

    if isinstance(value, dict) and "schema_version" in value:
        schema_version = value["schema_version"]
        if (
            schema_version != FINDING_BUNDLE_SCHEMA_VERSION
            and isinstance(schema_version, str)
            and _FINDING_BUNDLE_SCHEMA_VERSION_RE.fullmatch(schema_version)
        ):
            raise UnsupportedFindingBundleVersionError(schema_version)
    if not isinstance(value, dict) or frozenset(value) != FINDING_BUNDLE_KEYS:
        raise ValueError("invalid finding bundle document")

    try:
        return FindingBundle.model_validate(value)
    except ValidationError as exc:
        raise ValueError("invalid finding bundle document") from exc


def _reject_duplicate_finding_bundle_json_object_pairs(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    """Reject duplicate object keys so readers cannot disagree on last-wins behavior."""
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON object key: {key}")
        payload[key] = value
    return payload


def _reject_non_finite_finding_bundle_json_constant(token: str) -> Never:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""
    raise ValueError(f"non-finite JSON constant: {token}")


def _parse_finite_finding_bundle_json_float(token: str) -> float:
    """Parse a JSON float while rejecting finite-looking overflow literals."""
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON float: {token}")
    return value


def _parse_safe_finding_bundle_json_int(token: str) -> int:
    """Parse a JSON integer while rejecting values unsafe in IEEE-754 readers."""
    value = int(token)
    if abs(value) > MAX_FINDING_BUNDLE_JSON_INTEGER:
        raise ValueError(f"JSON integer exceeds safe range: {token}")
    return value


def _validate_finding_bundle_json_value_graph(payload: object) -> None:
    """Reject strings and values that make finding-bundle JSON non-portable."""
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
            if abs(value) > MAX_FINDING_BUNDLE_JSON_INTEGER:
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
    """Validate a finding-bundle byte budget."""
    return _validate_positive_finding_bundle_int(max_bundle_bytes, name="max_bundle_bytes")


def _validate_max_findings(max_findings: int) -> int:
    """Validate a finding-bundle count budget."""
    return _validate_positive_finding_bundle_int(max_findings, name="max_findings")


def _validate_positive_finding_bundle_int(value: int, *, name: str) -> int:
    """Validate one positive integer limit while rejecting bools explicitly."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} expected int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _read_finding_bundle_binary_chunk(chunk: object) -> bytes:
    """Keep binary-stream type failures consistent across finding reads."""
    if not isinstance(chunk, bytes):
        raise TypeError(f"read_finding_bundle expected binary stream, got {type(chunk).__name__}")
    return chunk
