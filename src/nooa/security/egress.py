# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Descriptor-backed egress for structured security-effect telemetry."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import BinaryIO, Literal, Never

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_core import PydanticSerializationError

from nooa.security.effects import EffectRecord

EffectEgressSchemaVersion = Literal["nooa-effect-egress-v1", "nooa-effect-egress-v2"]
EFFECT_EGRESS_SCHEMA_VERSION: Literal["nooa-effect-egress-v1"] = "nooa-effect-egress-v1"
EFFECT_EGRESS_SCHEMA_VERSION_V2: Literal["nooa-effect-egress-v2"] = "nooa-effect-egress-v2"
EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS: tuple[EffectEgressSchemaVersion, ...] = (
    EFFECT_EGRESS_SCHEMA_VERSION,
    EFFECT_EGRESS_SCHEMA_VERSION_V2,
)
# Apply this pattern to the whole token. Prefix or substring matching changes
# unsupported-version classification into a compatibility bug.
EFFECT_EGRESS_SCHEMA_VERSION_PATTERN: str = r"nooa-effect-egress-v[1-9][0-9]*"
EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE: Literal["full"] = "full"
EFFECT_EGRESS_FRAME_KEYS: frozenset[str] = frozenset({"schema_version", "sequence", "record"})
EFFECT_EGRESS_STREAM_END_FRAME_KEYS: frozenset[str] = frozenset(
    {"schema_version", "sequence", "stream_end"}
)
EFFECT_EGRESS_RECORD_EVENT_TYPE: Literal["EffectRecord"] = "EffectRecord"
EFFECT_EGRESS_STREAM_END_EVENT_TYPE: Literal["EffectEgressStreamEnd"] = "EffectEgressStreamEnd"
EFFECT_EGRESS_RECORD_KEYS: frozenset[str] = frozenset(
    {
        "event_type",
        "id",
        "metadata",
        "status",
        "tag",
        "timestamp",
        "effect_type",
        "target",
        "decision",
        "observer",
        "generation_id",
        "tool_call_id",
        "attributes",
    }
)
EFFECT_EGRESS_STREAM_END_KEYS: frozenset[str] = frozenset({"event_type", "record_count"})
EffectEgressCompletenessSignal = Literal[
    "first_sequence_error",
    "truncated",
    "missing_stream_end",
    "record_count_mismatch",
]
# Tuple order is public because EffectEgressIncompleteError.reasons preserves it.
EFFECT_EGRESS_COMPLETENESS_SIGNALS: tuple[EffectEgressCompletenessSignal, ...] = (
    "first_sequence_error",
    "truncated",
    "missing_stream_end",
    "record_count_mismatch",
)
MAX_EFFECT_EGRESS_JSON_INTEGER: int = (1 << 53) - 1
MAX_EFFECT_EGRESS_SEQUENCE: int = MAX_EFFECT_EGRESS_JSON_INTEGER
DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES: int = 1024 * 1024
DEFAULT_EFFECT_EGRESS_MAX_TOTAL_BYTES: int = 256 * 1024 * 1024
DEFAULT_EFFECT_EGRESS_MAX_RECORDS: int = 1 << 20

_EFFECT_EGRESS_SCHEMA_VERSION_RE = re.compile(EFFECT_EGRESS_SCHEMA_VERSION_PATTERN)


class UnsupportedEffectEgressVersionError(ValueError):
    """Raised when a collector sees a well-formed future egress wire version."""

    def __init__(self, line_number: int, schema_version: object) -> None:
        self.line_number = line_number
        self.schema_version = schema_version
        super().__init__(
            f"unsupported effect egress schema_version at line {line_number}: {schema_version!r}"
        )


class EffectEgressFrameTooLargeError(ValueError):
    """Raised when a writer or collector refuses an over-bound frame."""

    def __init__(self, max_frame_bytes: int, *, line_number: int | None = None) -> None:
        self.max_frame_bytes = max_frame_bytes
        self.line_number = line_number
        location = f" at line {line_number}" if line_number is not None else ""
        super().__init__(f"effect egress frame{location} exceeds max_frame_bytes={max_frame_bytes}")


class EffectEgressInputTooLargeError(ValueError):
    """Raised when a collector refuses a stream that exceeds an input budget."""

    def __init__(
        self,
        limit_name: Literal["max_total_bytes", "max_records"],
        limit_value: int,
        *,
        line_number: int | None = None,
    ) -> None:
        self.limit_name = limit_name
        self.limit_value = limit_value
        self.line_number = line_number
        location = f" at line {line_number}" if line_number is not None else ""
        super().__init__(f"effect egress input{location} exceeds {limit_name}={limit_value}")


class EffectEgressSinkFailedError(RuntimeError):
    """Raised when a sink is reused after an uncertain descriptor failure."""


class EffectEgressSinkClosedError(RuntimeError):
    """Raised when a sink is reused after orderly stream-end emission."""


class _EffectEgressFrame(BaseModel):
    """One collector-facing record frame written by :class:`FdEffectSink`."""

    model_config = ConfigDict(extra="forbid")

    schema_version: EffectEgressSchemaVersion
    sequence: int = Field(ge=0, le=MAX_EFFECT_EGRESS_SEQUENCE, strict=True)
    record: EffectRecord


class _EffectEgressStreamEnd(BaseModel):
    """One V2 writer-declared stream-end payload."""

    model_config = ConfigDict(extra="forbid")

    event_type: Literal["EffectEgressStreamEnd"] = EFFECT_EGRESS_STREAM_END_EVENT_TYPE
    record_count: int = Field(ge=0, le=MAX_EFFECT_EGRESS_JSON_INTEGER, strict=True)


class _EffectEgressStreamEndFrame(BaseModel):
    """One V2 stream-end frame written by :class:`FdEffectSink.close`."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["nooa-effect-egress-v2"] = EFFECT_EGRESS_SCHEMA_VERSION_V2
    sequence: int = Field(ge=0, le=MAX_EFFECT_EGRESS_SEQUENCE, strict=True)
    stream_end: _EffectEgressStreamEnd


@dataclass(frozen=True)
class EffectEgressReadResult:
    """Parsed egress records plus stream-shape diagnostics.

    ``first_sequence_error`` is the first ``(expected, observed)`` pair seen by
    the collector. It detects gaps and reordering in the bytes that reached the
    collector; it does not authenticate those bytes or their origin.
    """

    records: tuple[EffectRecord, ...]
    first_sequence_error: tuple[int, int] | None = None
    truncated: bool = False
    schema_version: EffectEgressSchemaVersion | None = None
    stream_end_declared: bool = False
    declared_record_count: int | None = None


class EffectEgressIncompleteError(RuntimeError):
    """Raised when known reader diagnostics show degraded effect egress.

    This error reports only degradation visible in an
    :class:`EffectEgressReadResult`. It does not authenticate records or prove
    that a writer emitted every effect.
    """

    def __init__(self, egress: EffectEgressReadResult) -> None:
        if not isinstance(egress, EffectEgressReadResult):
            raise TypeError(
                "EffectEgressIncompleteError expected EffectEgressReadResult, "
                f"got {type(egress).__name__}"
            )
        reasons = effect_egress_completeness_signals(egress)
        if not reasons:
            raise ValueError(
                "EffectEgressIncompleteError requires at least one completeness signal"
            )
        self.first_sequence_error = egress.first_sequence_error
        self.truncated = egress.truncated
        self.stream_end_declared = egress.stream_end_declared
        self.declared_record_count = egress.declared_record_count
        self.reasons = reasons
        super().__init__(
            "effect egress stream is incomplete: "
            f"first_sequence_error={egress.first_sequence_error!r}, "
            f"truncated={egress.truncated!r}, "
            f"stream_end_declared={egress.stream_end_declared!r}, "
            f"declared_record_count={egress.declared_record_count!r}"
        )


class FdEffectSink:
    """Write framed ``EffectRecord`` copies to a borrowed file descriptor.

    The sink never opens or re-resolves a filesystem path after construction.
    Applications can therefore hand it a descriptor already connected to a
    supervisor-owned pipe, socket, or file and keep path selection outside this
    helper. Each sink instance emits a zero-based monotonic sequence number in
    the frame around each record. V1 is the default for compatibility. A V2
    sink can emit one explicit stream-end frame through :meth:`close`; that
    frame consumes the next sequence number and carries a writer-declared
    record count.

    The descriptor is borrowed, not owned: this class does not close it. A file
    descriptor is also not an integrity boundary by itself. Code that can
    access, close, seek, truncate, or write to the same descriptor can still
    tamper with the stream or forge valid-looking frames. Multiple writers can
    also interleave or restart sequences. Sequence continuity only detects loss
    or reordering in a cooperative single-writer stream. A V2 stream-end frame
    distinguishes declared completion from a writer that simply stopped
    emitting, but it still does not prove that the writer emitted every effect
    before declaring completion.

    An over-bound record is refused before any bytes are written and does not
    consume a sequence number. The caller sees
    :class:`EffectEgressFrameTooLargeError`; the collector does not see a gap
    for a frame that was never emitted.

    V2 record frames intentionally reuse the exact V1 record payload shape.
    Records that cannot be represented in that shared payload shape, including
    subclass-only fields, event-type drift, out-of-range integers, non-finite
    floats, lone surrogates, cyclic values, or non-JSON-native metadata values
    that would be rewritten during serialization, are refused with
    :class:`TypeError` before any bytes are written.

    The constructor rejects non-blocking descriptors. If a descriptor write or
    ``fsync`` raises :class:`OSError`, the sink is poisoned and subsequent calls
    raise :class:`EffectEgressSinkFailedError` rather than appending after a
    possibly partial frame. The collector may still see a trailing partial
    frame from the failed call.

    Args:
        fd: Open descriptor supplied by the caller.
        schema_version: V1 for legacy record-only streams or V2 for explicit
            stream-end support.
        fsync: If True, call :func:`os.fsync` after each frame.
        max_frame_bytes: Maximum encoded bytes per frame, including the
            trailing newline. The same bound should be used by the collector.
    """

    def __init__(
        self,
        fd: int,
        *,
        schema_version: EffectEgressSchemaVersion = EFFECT_EGRESS_SCHEMA_VERSION,
        fsync: bool = False,
        max_frame_bytes: int = DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES,
    ) -> None:
        if not isinstance(fd, int) or isinstance(fd, bool):
            raise TypeError(f"FdEffectSink expected int fd, got {type(fd).__name__}")
        os.fstat(fd)
        fd_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if fd_flags & os.O_ACCMODE == os.O_RDONLY:
            raise ValueError("FdEffectSink requires a writable file descriptor")
        if fd_flags & os.O_NONBLOCK:
            raise ValueError("FdEffectSink requires a blocking file descriptor")
        self._fd = fd
        self._schema_version = _validate_schema_version(schema_version)
        self._fsync = fsync
        self._max_frame_bytes = _validate_max_frame_bytes(max_frame_bytes)
        self._sequence = 0
        self._record_count = 0
        self._failed = False
        self._closed = False
        self._lock = threading.Lock()

    def __call__(self, record: EffectRecord) -> None:
        """Write one framed record to the borrowed descriptor."""
        record = _coerce_v1_effect_record(record)

        with self._lock:
            if self._closed:
                raise EffectEgressSinkClosedError("FdEffectSink is closed")
            if self._failed:
                raise EffectEgressSinkFailedError(
                    "FdEffectSink is unusable after a descriptor failure"
                )
            frame = _EffectEgressFrame(
                schema_version=self._schema_version,
                sequence=self._sequence,
                record=record,
            )
            self._write_frame(frame)
            self._sequence += 1
            self._record_count += 1

    def close(self) -> None:
        """Emit one V2 stream-end frame without closing the borrowed descriptor.

        Calling ``close()`` twice is idempotent. V1 sinks have no stream-end
        frame; for them this method only marks the sink closed so later writes
        are refused consistently.
        """
        with self._lock:
            if self._closed:
                return
            if self._failed:
                raise EffectEgressSinkFailedError(
                    "FdEffectSink is unusable after a descriptor failure"
                )
            if self._schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2:
                self._write_frame(
                    _EffectEgressStreamEndFrame(
                        sequence=self._sequence,
                        stream_end=_EffectEgressStreamEnd(record_count=self._record_count),
                    )
                )
                self._sequence += 1
            self._closed = True

    def _write_frame(self, frame: BaseModel) -> None:
        """Write one validated frame and poison the sink on descriptor failure."""
        payload = (frame.model_dump_json() + "\n").encode("utf-8")
        if len(payload) > self._max_frame_bytes:
            raise EffectEgressFrameTooLargeError(self._max_frame_bytes)
        try:
            _write_all(self._fd, payload)
            if self._fsync:
                os.fsync(self._fd)
        except OSError:
            self._failed = True
            raise


def _write_all(fd: int, payload: bytes) -> None:
    """Write all bytes or propagate the descriptor error."""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written == 0:
            raise OSError("effect egress descriptor accepted zero bytes")
        view = view[written:]


def _coerce_v1_effect_record(record: EffectRecord) -> EffectRecord:
    """Keep subclass-only fields from disappearing across the shared record envelope."""
    if not isinstance(record, EffectRecord):
        raise TypeError(f"FdEffectSink expected EffectRecord, got {type(record).__name__}")
    try:
        raw_payload = record.model_dump()
        _validate_json_value_graph(raw_payload)
        _validate_json_value_graph(raw_payload.get("metadata"), require_json_native=True)
        payload = record.model_dump(mode="json")
        _validate_json_value_graph(payload, require_json_native=True)
        if payload.get("event_type") != EFFECT_EGRESS_RECORD_EVENT_TYPE:
            raise ValueError("V1 record.event_type must be 'EffectRecord'")
        return EffectRecord.model_validate(payload)
    except (PydanticSerializationError, ValidationError, ValueError) as exc:
        raise TypeError(
            f"FdEffectSink expected V1-compatible EffectRecord, got {type(record).__name__}"
        ) from exc


def read_effect_egress(
    fh: BinaryIO,
    *,
    max_frame_bytes: int = DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES,
    max_total_bytes: int = DEFAULT_EFFECT_EGRESS_MAX_TOTAL_BYTES,
    max_records: int = DEFAULT_EFFECT_EGRESS_MAX_RECORDS,
    supported_schema_versions: Sequence[EffectEgressSchemaVersion] = (
        EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS
    ),
    expected_schema_version: EffectEgressSchemaVersion | None = None,
) -> EffectEgressReadResult:
    """Read complete frames from a binary collector stream.

    The reader consumes the stream from its current position until EOF. A
    trailing unterminated line is treated as a truncated final frame and
    ignored. Complete frames must be UTF-8 JSON objects ending in one LF byte
    with no BOM or outer whitespace. A malformed newline-terminated frame
    raises :class:`ValueError` because it is not distinguishable from a
    corrupted or forged frame.
    ``max_frame_bytes`` bounds memory consumed by one newline-delimited frame,
    including its trailing LF byte; over-bound input raises
    :class:`EffectEgressFrameTooLargeError`. Callers should set the bound to the
    same value used by :class:`FdEffectSink`. ``max_total_bytes`` bounds payload
    bytes admitted to parsing, including an unterminated trailing line, and
    ``max_records`` bounds complete parsed records retained in memory. The
    reader may perform one bounded lookahead byte to distinguish exact EOF from
    overflow. Exceeding either collector-wide budget raises
    :class:`EffectEgressInputTooLargeError` rather than reporting truncation.

    ``supported_schema_versions`` lets a caller model a V1-only collector even
    when this implementation also understands V2; a well-formed frame from a
    newer supported family then raises
    :class:`UnsupportedEffectEgressVersionError`. ``expected_schema_version``
    is optional context for an otherwise empty stream. It is required only when
    a caller wants an empty V2 stream without a terminator to surface
    ``missing_stream_end`` rather than remain version-unknown.
    """

    max_frame_bytes = _validate_max_frame_bytes(max_frame_bytes)
    max_total_bytes = _validate_max_total_bytes(max_total_bytes)
    max_records = _validate_max_records(max_records)
    supported_schema_versions = _validate_supported_schema_versions(supported_schema_versions)
    expected_schema_version = _validate_expected_schema_version(
        expected_schema_version,
        supported_schema_versions=supported_schema_versions,
    )
    records: list[EffectRecord] = []
    schema_version = expected_schema_version
    expected_sequence = 0
    first_sequence_error: tuple[int, int] | None = None
    truncated = False
    stream_end_declared = False
    declared_record_count: int | None = None
    line_number = 0
    total_bytes_read = 0
    while True:
        if total_bytes_read == max_total_bytes:
            if _stream_has_more_input(fh):
                raise EffectEgressInputTooLargeError(
                    "max_total_bytes",
                    max_total_bytes,
                    line_number=line_number + 1,
                )
            break

        remaining_total_bytes = max_total_bytes - total_bytes_read
        line = _read_binary_chunk(fh.readline(min(max_frame_bytes + 1, remaining_total_bytes + 1)))
        if not line:
            break

        line_number += 1
        if len(line) > max_frame_bytes:
            raise EffectEgressFrameTooLargeError(
                max_frame_bytes,
                line_number=line_number,
            )
        if len(line) > remaining_total_bytes:
            raise EffectEgressInputTooLargeError(
                "max_total_bytes",
                max_total_bytes,
                line_number=line_number,
            )
        total_bytes_read += len(line)
        if stream_end_declared:
            raise ValueError(f"invalid effect egress frame at line {line_number}")
        if not line.endswith(b"\n"):
            truncated = True
            break

        frame = _parse_frame(
            line,
            line_number,
            supported_schema_versions=supported_schema_versions,
        )
        if schema_version is None:
            schema_version = frame.schema_version
        elif frame.schema_version != schema_version:
            raise ValueError(f"invalid effect egress frame at line {line_number}")
        if first_sequence_error is None and frame.sequence != expected_sequence:
            first_sequence_error = (expected_sequence, frame.sequence)
        expected_sequence = frame.sequence + 1
        if isinstance(frame, _EffectEgressStreamEndFrame):
            stream_end_declared = True
            declared_record_count = frame.stream_end.record_count
            continue

        if len(records) == max_records:
            raise EffectEgressInputTooLargeError(
                "max_records",
                max_records,
                line_number=line_number,
            )
        records.append(frame.record)

    return EffectEgressReadResult(
        records=tuple(records),
        schema_version=schema_version,
        first_sequence_error=first_sequence_error,
        truncated=truncated,
        stream_end_declared=stream_end_declared,
        declared_record_count=declared_record_count,
    )


def require_complete_effect_egress(
    egress: EffectEgressReadResult,
) -> tuple[EffectRecord, ...]:
    """Return records only when received bytes show no known degradation.

    A clean V1 result, including an empty stream, means only that the reader did
    not observe a sequence discontinuity or a trailing partial frame. A clean
    V2 result additionally means that the writer emitted one stream-end frame
    whose declared record count matched the records the reader retained. None
    of those facts prove that a writer emitted every effect or that the bytes
    are genuine. Because :func:`read_effect_egress` starts sequence validation
    at zero, attaching to a mid-stream writer produces ``first_sequence_error``
    and is rejected by this helper.

    This helper is the second half of a fail-closed collector read:
    :func:`read_effect_egress` raises :class:`ValueError`, including its
    :class:`UnsupportedEffectEgressVersionError` and
    :class:`EffectEgressFrameTooLargeError` and
    :class:`EffectEgressInputTooLargeError` subclasses, for malformed complete
    frames, unsupported versions, or over-bound input. This helper raises
    :class:`EffectEgressIncompleteError` for parsed results that carry known
    short-stream or sequence-discontinuity diagnostics.

    Raises:
        TypeError: If ``egress`` is not an :class:`EffectEgressReadResult`.
        EffectEgressIncompleteError: If the reader reported any public
            completeness signal.
    """

    if not isinstance(egress, EffectEgressReadResult):
        raise TypeError(
            "require_complete_effect_egress expected EffectEgressReadResult, "
            f"got {type(egress).__name__}"
        )
    if effect_egress_completeness_signals(egress):
        raise EffectEgressIncompleteError(egress)
    return egress.records


def effect_egress_completeness_signals(
    egress: EffectEgressReadResult,
) -> tuple[EffectEgressCompletenessSignal, ...]:
    """Return known reader diagnostics in canonical public order.

    The returned tuple describes only degradation visible in one
    :class:`EffectEgressReadResult`. ``missing_stream_end`` is version
    conditional: it applies only when the result is explicitly V2. An empty
    tuple does not prove that a writer emitted every effect or that the bytes
    are authentic.

    Raises:
        TypeError: If ``egress`` is not an :class:`EffectEgressReadResult`.
    """
    if not isinstance(egress, EffectEgressReadResult):
        raise TypeError(
            "effect_egress_completeness_signals expected EffectEgressReadResult, "
            f"got {type(egress).__name__}"
        )
    reasons: list[EffectEgressCompletenessSignal] = []
    if egress.first_sequence_error is not None:
        reasons.append("first_sequence_error")
    if egress.truncated:
        reasons.append("truncated")
    if egress.schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2 and not egress.stream_end_declared:
        reasons.append("missing_stream_end")
    if (
        egress.stream_end_declared
        and egress.declared_record_count is not None
        and egress.declared_record_count != len(egress.records)
    ):
        reasons.append("record_count_mismatch")
    return tuple(reasons)


def _parse_frame(
    line: bytes,
    line_number: int,
    *,
    supported_schema_versions: tuple[EffectEgressSchemaVersion, ...],
) -> _EffectEgressFrame | _EffectEgressStreamEndFrame:
    """Parse one complete frame and keep unsupported versions distinguishable."""
    body = line[:-1]
    try:
        if body.startswith(b"\xef\xbb\xbf") or body != body.strip():
            raise ValueError("frame has BOM or outer whitespace")
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_object_pairs,
            parse_constant=_reject_non_finite_json_constant,
            parse_float=_parse_finite_json_float,
            parse_int=_parse_safe_json_int,
        )
        _validate_json_value_graph(payload, require_json_native=True)
    except (RecursionError, ValueError) as exc:
        raise ValueError(f"invalid effect egress frame at line {line_number}") from exc

    if isinstance(payload, dict) and "schema_version" in payload:
        schema_version = payload["schema_version"]
        if (
            schema_version not in supported_schema_versions
            and isinstance(schema_version, str)
            and _EFFECT_EGRESS_SCHEMA_VERSION_RE.fullmatch(schema_version)
        ):
            raise UnsupportedEffectEgressVersionError(line_number, schema_version)
        if schema_version == EFFECT_EGRESS_SCHEMA_VERSION_V2 and frozenset(payload) == (
            EFFECT_EGRESS_STREAM_END_FRAME_KEYS
        ):
            stream_end_payload = payload.get("stream_end")
            if (
                isinstance(stream_end_payload, dict)
                and frozenset(stream_end_payload) != EFFECT_EGRESS_STREAM_END_KEYS
            ):
                raise ValueError(f"invalid effect egress frame at line {line_number}")
            if (
                isinstance(stream_end_payload, dict)
                and stream_end_payload.get("event_type") != EFFECT_EGRESS_STREAM_END_EVENT_TYPE
            ):
                raise ValueError(f"invalid effect egress frame at line {line_number}")
            try:
                return _EffectEgressStreamEndFrame.model_validate(payload)
            except ValidationError as exc:
                raise ValueError(f"invalid effect egress frame at line {line_number}") from exc
        record_payload = payload.get("record")
        if (
            isinstance(record_payload, dict)
            and frozenset(record_payload) != EFFECT_EGRESS_RECORD_KEYS
        ):
            raise ValueError(f"invalid effect egress frame at line {line_number}")
        if (
            isinstance(record_payload, dict)
            and record_payload.get("event_type") != EFFECT_EGRESS_RECORD_EVENT_TYPE
        ):
            raise ValueError(f"invalid effect egress frame at line {line_number}")

    try:
        frame = _EffectEgressFrame.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid effect egress frame at line {line_number}") from exc
    if frame.record.event_type != EFFECT_EGRESS_RECORD_EVENT_TYPE:
        raise ValueError(f"invalid effect egress frame at line {line_number}")
    return frame


def _reject_duplicate_json_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object keys so parsers cannot disagree on last-wins behavior."""
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON object key: {key}")
        payload[key] = value
    return payload


def _reject_non_finite_json_constant(token: str) -> Never:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""
    raise ValueError(f"non-finite JSON constant: {token}")


def _parse_finite_json_float(token: str) -> float:
    """Parse a JSON float while rejecting finite-looking overflow literals."""
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON float: {token}")
    return value


def _parse_safe_json_int(token: str) -> int:
    """Parse a JSON integer while rejecting values unsafe in IEEE-754 readers."""
    value = int(token)
    if abs(value) > MAX_EFFECT_EGRESS_JSON_INTEGER:
        raise ValueError(f"JSON integer exceeds safe range: {token}")
    return value


def _validate_json_value_graph(payload: object, *, require_json_native: bool = False) -> None:
    """Reject cycles and scalar values that make effect-egress JSON non-portable."""
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
            if abs(value) > MAX_EFFECT_EGRESS_JSON_INTEGER:
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
            if require_json_native and any(not isinstance(key, str) for key in value):
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
        if require_json_native:
            raise ValueError(f"value is not JSON-native: {type(value).__name__}")


def _validate_schema_version(schema_version: str) -> EffectEgressSchemaVersion:
    """Validate one schema version implemented by this writer."""
    if schema_version not in EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported effect egress schema_version: {schema_version!r}")
    return schema_version


def _validate_supported_schema_versions(
    supported_schema_versions: Sequence[EffectEgressSchemaVersion],
) -> tuple[EffectEgressSchemaVersion, ...]:
    """Validate an ordered non-empty set of schema versions accepted by a reader."""
    if isinstance(supported_schema_versions, str):
        raise TypeError("supported_schema_versions expected a sequence, got str")
    versions = tuple(supported_schema_versions)
    if not versions:
        raise ValueError("supported_schema_versions must not be empty")
    if len(set(versions)) != len(versions):
        raise ValueError("supported_schema_versions must not contain duplicates")
    for version in versions:
        if version not in EFFECT_EGRESS_SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported configured effect egress schema_version: {version!r}")
    return versions


def _validate_expected_schema_version(
    expected_schema_version: EffectEgressSchemaVersion | None,
    *,
    supported_schema_versions: tuple[EffectEgressSchemaVersion, ...],
) -> EffectEgressSchemaVersion | None:
    """Validate optional empty-stream version context supplied by a caller."""
    if expected_schema_version is None:
        return None
    if expected_schema_version not in supported_schema_versions:
        raise ValueError("expected_schema_version must be included in supported_schema_versions")
    return expected_schema_version


def _validate_max_frame_bytes(max_frame_bytes: int) -> int:
    """Validate a frame-size bound shared by writers and readers."""
    return _validate_positive_int(max_frame_bytes, name="max_frame_bytes")


def _validate_max_total_bytes(max_total_bytes: int) -> int:
    """Validate a collector-wide byte budget."""
    return _validate_positive_int(max_total_bytes, name="max_total_bytes")


def _validate_max_records(max_records: int) -> int:
    """Validate a collector-wide complete-record budget."""
    return _validate_positive_int(max_records, name="max_records")


def _validate_positive_int(value: int, *, name: str) -> int:
    """Validate one positive integer limit while rejecting bools explicitly."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} expected int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _read_binary_chunk(chunk: object) -> bytes:
    """Keep binary-stream type failures consistent across read paths."""
    if not isinstance(chunk, bytes):
        raise TypeError(f"read_effect_egress expected binary stream, got {type(chunk).__name__}")
    return chunk


def _stream_has_more_input(fh: BinaryIO) -> bool:
    """Use one bounded lookahead byte to distinguish exact EOF from overflow."""
    return bool(_read_binary_chunk(fh.read(1)))
