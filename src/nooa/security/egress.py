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
from dataclasses import dataclass
from typing import BinaryIO, Literal, Never

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic_core import PydanticSerializationError

from nooa.security.effects import EffectRecord

EFFECT_EGRESS_SCHEMA_VERSION: Literal["nooa-effect-egress-v1"] = "nooa-effect-egress-v1"
# Apply this pattern to the whole token. Prefix or substring matching changes
# unsupported-version classification into a compatibility bug.
EFFECT_EGRESS_SCHEMA_VERSION_PATTERN: str = r"nooa-effect-egress-v[1-9][0-9]*"
EFFECT_EGRESS_SCHEMA_VERSION_PATTERN_MATCH_MODE: Literal["full"] = "full"
EFFECT_EGRESS_FRAME_KEYS: frozenset[str] = frozenset({"schema_version", "sequence", "record"})
EFFECT_EGRESS_RECORD_EVENT_TYPE: Literal["EffectRecord"] = "EffectRecord"
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
MAX_EFFECT_EGRESS_SEQUENCE: int = (1 << 53) - 1
DEFAULT_EFFECT_EGRESS_MAX_FRAME_BYTES: int = 1024 * 1024

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


class EffectEgressSinkFailedError(RuntimeError):
    """Raised when a sink is reused after an uncertain descriptor failure."""


class _EffectEgressFrame(BaseModel):
    """One collector-facing frame written by :class:`FdEffectSink`."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["nooa-effect-egress-v1"]
    sequence: int = Field(ge=0, le=MAX_EFFECT_EGRESS_SEQUENCE, strict=True)
    record: EffectRecord


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


class FdEffectSink:
    """Write framed ``EffectRecord`` copies to a borrowed file descriptor.

    The sink never opens or re-resolves a filesystem path after construction.
    Applications can therefore hand it a descriptor already connected to a
    supervisor-owned pipe, socket, or file and keep path selection outside this
    helper. Each sink instance emits a zero-based monotonic sequence number in
    the frame around each record.

    The descriptor is borrowed, not owned: this class does not close it. A file
    descriptor is also not an integrity boundary by itself. Code that can
    access, close, seek, truncate, or write to the same descriptor can still
    tamper with the stream or forge valid-looking frames. Multiple writers can
    also interleave or restart sequences. Sequence continuity only detects loss
    or reordering in a cooperative single-writer stream, and cannot distinguish
    a clean agent exit from a writer that simply stopped emitting.

    An over-bound record is refused before any bytes are written and does not
    consume a sequence number. The caller sees
    :class:`EffectEgressFrameTooLargeError`; the collector does not see a gap
    for a frame that was never emitted.

    Records that cannot be represented as the exact V1 payload shape, including
    subclass-only fields, event-type drift, non-finite floats, lone surrogates,
    or non-JSON-native metadata values that would be rewritten during
    serialization, are refused with :class:`TypeError` before any bytes are
    written.

    The constructor rejects non-blocking descriptors. If a descriptor write or
    ``fsync`` raises :class:`OSError`, the sink is poisoned and subsequent calls
    raise :class:`EffectEgressSinkFailedError` rather than appending after a
    possibly partial frame. The collector may still see a trailing partial
    frame from the failed call.

    Args:
        fd: Open descriptor supplied by the caller.
        fsync: If True, call :func:`os.fsync` after each frame.
        max_frame_bytes: Maximum encoded bytes per frame, including the
            trailing newline. The same bound should be used by the collector.
    """

    def __init__(
        self,
        fd: int,
        *,
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
        self._fsync = fsync
        self._max_frame_bytes = _validate_max_frame_bytes(max_frame_bytes)
        self._sequence = 0
        self._failed = False
        self._lock = threading.Lock()

    def __call__(self, record: EffectRecord) -> None:
        """Write one framed record to the borrowed descriptor."""
        record = _coerce_v1_effect_record(record)

        with self._lock:
            if self._failed:
                raise EffectEgressSinkFailedError(
                    "FdEffectSink is unusable after a descriptor failure"
                )
            frame = _EffectEgressFrame(
                schema_version=EFFECT_EGRESS_SCHEMA_VERSION,
                sequence=self._sequence,
                record=record,
            )
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
            self._sequence += 1


def _write_all(fd: int, payload: bytes) -> None:
    """Write all bytes or propagate the descriptor error."""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written == 0:
            raise OSError("effect egress descriptor accepted zero bytes")
        view = view[written:]


def _coerce_v1_effect_record(record: EffectRecord) -> EffectRecord:
    """Keep subclass-only fields from disappearing across the V1 envelope."""
    if not isinstance(record, EffectRecord):
        raise TypeError(f"FdEffectSink expected EffectRecord, got {type(record).__name__}")
    try:
        raw_payload = record.model_dump()
        _reject_non_finite_numbers(raw_payload)
        _reject_lone_surrogate_strings(raw_payload)
        _reject_non_json_native_values(raw_payload.get("metadata"))
        payload = record.model_dump(mode="json")
        _reject_non_finite_numbers(payload)
        _reject_lone_surrogate_strings(payload)
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
    same value used by :class:`FdEffectSink`.
    """

    max_frame_bytes = _validate_max_frame_bytes(max_frame_bytes)
    records: list[EffectRecord] = []
    expected_sequence = 0
    first_sequence_error: tuple[int, int] | None = None
    truncated = False
    line_number = 0
    while True:
        line = fh.readline(max_frame_bytes + 1)
        if not isinstance(line, bytes):
            raise TypeError(f"read_effect_egress expected binary stream, got {type(line).__name__}")
        if not line:
            break

        line_number += 1
        if len(line) > max_frame_bytes:
            raise EffectEgressFrameTooLargeError(
                max_frame_bytes,
                line_number=line_number,
            )
        if not line.endswith(b"\n"):
            truncated = True
            break

        frame = _parse_frame(line, line_number)

        if first_sequence_error is None and frame.sequence != expected_sequence:
            first_sequence_error = (expected_sequence, frame.sequence)
        records.append(frame.record)
        expected_sequence = frame.sequence + 1

    return EffectEgressReadResult(
        records=tuple(records),
        first_sequence_error=first_sequence_error,
        truncated=truncated,
    )


def _parse_frame(line: bytes, line_number: int) -> _EffectEgressFrame:
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
        )
        _reject_non_finite_numbers(payload)
        _reject_lone_surrogate_strings(payload)
    except (RecursionError, ValueError) as exc:
        raise ValueError(f"invalid effect egress frame at line {line_number}") from exc

    if isinstance(payload, dict) and "schema_version" in payload:
        schema_version = payload["schema_version"]
        if (
            schema_version != EFFECT_EGRESS_SCHEMA_VERSION
            and isinstance(schema_version, str)
            and _EFFECT_EGRESS_SCHEMA_VERSION_RE.fullmatch(schema_version)
        ):
            raise UnsupportedEffectEgressVersionError(line_number, schema_version)
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


def _reject_non_finite_numbers(payload: object) -> None:
    """Reject decoded values that JSON serializers could silently rewrite."""
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("JSON value contains a non-finite float")
            continue
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        if isinstance(value, list):
            pending.extend(value)


def _reject_lone_surrogate_strings(payload: object) -> None:
    """Reject decoded strings that cannot be represented as UTF-8."""
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                raise ValueError("JSON string contains a lone surrogate")
            continue
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
            continue
        if isinstance(value, list):
            pending.extend(value)


def _reject_non_json_native_values(payload: object) -> None:
    """Reject metadata values that would change type during JSON serialization."""
    pending = [payload]
    while pending:
        value = pending.pop()
        if value is None or isinstance(value, (str, bool, int, float)):
            continue
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("JSON object key is not a string")
            pending.extend(value.values())
            continue
        if isinstance(value, list):
            pending.extend(value)
            continue
        raise ValueError(f"value is not JSON-native: {type(value).__name__}")


def _validate_max_frame_bytes(max_frame_bytes: int) -> int:
    """Validate a frame-size bound shared by writers and readers."""
    if not isinstance(max_frame_bytes, int) or isinstance(max_frame_bytes, bool):
        raise TypeError(f"max_frame_bytes expected int, got {type(max_frame_bytes).__name__}")
    if max_frame_bytes <= 0:
        raise ValueError("max_frame_bytes must be positive")
    return max_frame_bytes
