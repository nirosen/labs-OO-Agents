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

FindingIdentitySignal = Literal["duplicate_finding_id"]
# Tuple order is public because FindingIdentityError.reasons preserves it.
FINDING_IDENTITY_SIGNALS: tuple[FindingIdentitySignal, ...] = (
    "duplicate_finding_id",
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
class FindingIdentityValidation:
    """Identity diagnostics for one materialized finding iterable.

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
    perform the check that :func:`validate_finding_identity` performs.
    """

    findings: tuple[SecurityFinding, ...]
    duplicate_finding_ids: tuple[str, ...] = ()


class FindingIdentityError(RuntimeError):
    """Raised when supplied findings reuse one or more finding identifiers.

    This error reports only diagnostics visible in a
    :class:`FindingIdentityValidation`. It does not establish finding
    authenticity, detector coverage, or semantic correctness.
    """

    def __init__(self, validation: FindingIdentityValidation) -> None:
        if not isinstance(validation, FindingIdentityValidation):
            raise TypeError(
                "FindingIdentityError expected FindingIdentityValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = finding_identity_signals(validation)
        if not reasons:
            raise ValueError("FindingIdentityError requires at least one identity signal")
        self.duplicate_finding_ids = validation.duplicate_finding_ids
        self.reasons = reasons
        super().__init__(
            "finding rows reuse finding_id values: "
            f"duplicate_finding_ids={validation.duplicate_finding_ids!r}"
        )


def finding_identity_signals(
    validation: FindingIdentityValidation,
) -> tuple[FindingIdentitySignal, ...]:
    """Return canonical identifier diagnostics for one finding iterable."""
    if not isinstance(validation, FindingIdentityValidation):
        raise TypeError(
            "finding_identity_signals expected FindingIdentityValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[FindingIdentitySignal] = []
    if validation.duplicate_finding_ids:
        signals.append("duplicate_finding_id")
    return tuple(signals)


def validate_finding_identity(
    findings: Iterable[SecurityFinding],
) -> FindingIdentityValidation:
    """Materialize findings and report repeated finding identifiers.

    ``findings`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_finding_identity` when no identity
    signal is present.

    The helper checks only whether the supplied rows reuse ``finding_id``
    values. It does not authenticate rows, producers, or identifiers; prove
    that distinct identifiers denote distinct findings; establish uniqueness
    across bundles, runs, or producers; dereference identifiers against any
    external system; or prove detector coverage.
    """
    if isinstance(findings, (str, bytes, bytearray)) or not isinstance(findings, Iterable):
        raise TypeError(
            "validate_finding_identity expected iterable of SecurityFinding, "
            f"got {type(findings).__name__}"
        )

    materialized = tuple(findings)
    for index, finding in enumerate(materialized):
        if not isinstance(finding, SecurityFinding):
            raise TypeError(
                "validate_finding_identity expected SecurityFinding at "
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

    return FindingIdentityValidation(
        findings=materialized,
        duplicate_finding_ids=tuple(duplicate_ids),
    )


def require_valid_finding_identity(
    validation: FindingIdentityValidation,
) -> tuple[SecurityFinding, ...]:
    """Return supplied findings or fail closed on repeated finding identifiers."""
    if not isinstance(validation, FindingIdentityValidation):
        raise TypeError(
            "require_valid_finding_identity expected FindingIdentityValidation, "
            f"got {type(validation).__name__}"
        )
    if finding_identity_signals(validation):
        raise FindingIdentityError(validation)
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
