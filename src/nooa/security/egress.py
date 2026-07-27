# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Descriptor-backed egress for structured security-effect telemetry."""

from __future__ import annotations

import fcntl
import json
import os
import re
import threading
from dataclasses import dataclass
from typing import BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from nooa.security.effects import EffectRecord

_EFFECT_EGRESS_SCHEMA_VERSION: Literal["nooa-effect-egress-v1"] = "nooa-effect-egress-v1"
_EFFECT_EGRESS_SCHEMA_VERSION_RE = re.compile(r"^nooa-effect-egress-v[1-9][0-9]*$")
_DEFAULT_MAX_FRAME_BYTES = 1024 * 1024


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
    sequence: int = Field(ge=0, strict=True)
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
        max_frame_bytes: int = _DEFAULT_MAX_FRAME_BYTES,
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
        if not isinstance(record, EffectRecord):
            raise TypeError(f"FdEffectSink expected EffectRecord, got {type(record).__name__}")

        with self._lock:
            if self._failed:
                raise EffectEgressSinkFailedError(
                    "FdEffectSink is unusable after a descriptor failure"
                )
            frame = _EffectEgressFrame(
                schema_version=_EFFECT_EGRESS_SCHEMA_VERSION,
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


def read_effect_egress(
    fh: BinaryIO,
    *,
    max_frame_bytes: int = _DEFAULT_MAX_FRAME_BYTES,
) -> EffectEgressReadResult:
    """Read complete frames from a binary collector stream.

    The reader consumes the stream from its current position until EOF. A
    trailing unterminated line is treated as a truncated final frame and
    ignored. A malformed newline-terminated frame raises :class:`ValueError`
    because it is not distinguishable from a corrupted or forged frame.
    ``max_frame_bytes`` bounds memory consumed by one newline-delimited frame;
    over-bound input raises :class:`EffectEgressFrameTooLargeError`. Callers
    should set the bound to the same value used by :class:`FdEffectSink`.
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
    try:
        payload = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid effect egress frame at line {line_number}") from exc

    if isinstance(payload, dict) and "schema_version" in payload:
        schema_version = payload["schema_version"]
        if (
            schema_version != _EFFECT_EGRESS_SCHEMA_VERSION
            and isinstance(schema_version, str)
            and _EFFECT_EGRESS_SCHEMA_VERSION_RE.fullmatch(schema_version)
        ):
            raise UnsupportedEffectEgressVersionError(line_number, schema_version)

    try:
        return _EffectEgressFrame.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"invalid effect egress frame at line {line_number}") from exc


def _validate_max_frame_bytes(max_frame_bytes: int) -> int:
    """Validate a frame-size bound shared by writers and readers."""
    if not isinstance(max_frame_bytes, int) or isinstance(max_frame_bytes, bool):
        raise TypeError(f"max_frame_bytes expected int, got {type(max_frame_bytes).__name__}")
    if max_frame_bytes <= 0:
        raise ValueError("max_frame_bytes must be positive")
    return max_frame_bytes
