# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Composable sinks for structured security-effect telemetry."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nooa.context_blocks import EventBase, EventStatus
from nooa.runtime.event_backend import EventBackend
from nooa.security.effects import EffectRecord

if TYPE_CHECKING:
    from nooa.runtime.event_manager import EventManager

EffectSink = Callable[[EffectRecord], None]


class JsonlEffectSink:
    """Append host-side ``EffectRecord`` copies to a JSONL file.

    Each call writes one complete ``EffectRecord.model_dump_json()`` object per
    line. Writes are serialized within this process and the destination parent
    directory is created on construction.

    This sink is only as trustworthy as the process and filesystem path that
    own it. Constructing it inside the victim process or pointing it at a path
    the victim can mutate does not make records tamper-evident. The sink also
    does not scrub secrets; records and inherited ``metadata`` must already be
    sanitized and JSON-serializable.

    Args:
        path: Destination JSONL path.
        fsync: If True, call :func:`os.fsync` after each line is flushed.
    """

    def __init__(self, path: str | Path, *, fsync: bool = False) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fsync = fsync
        self._lock = threading.Lock()

    def __call__(self, record: EffectRecord) -> None:
        """Write one record to the sink."""
        if not isinstance(record, EffectRecord):
            raise TypeError(f"JsonlEffectSink expected EffectRecord, got {type(record).__name__}")

        line = record.model_dump_json() + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            if self._fsync:
                os.fsync(fh.fileno())


class EffectRecordSinkBackend:
    """Mirror ``EffectRecord`` stores to a sink before delegating to a backend.

    The decorator preserves the wrapped :class:`~nooa.runtime.event_backend.EventBackend`
    contract for reads, updates, tag allocation, and lifecycle operations. On
    ``store()``, only :class:`EffectRecord` instances are copied to ``sink``;
    other event types pass straight through.

    The sink runs before the wrapped backend. A sink failure therefore
    propagates before the local backend accepts the record. If the sink succeeds
    and the wrapped backend later fails, the external copy may be ahead of local
    storage; applications that require atomic multi-destination commit need a
    transactional backend outside this helper.

    ``EventManager.add()`` injects ``call_id`` metadata and assigns ``tag``
    before calling ``store()``, so records written through an event manager
    include the same lineage fields seen by the wrapped backend. Direct
    ``backend.store()`` callers remain responsible for preparing the event
    object themselves.
    """

    def __init__(self, backend: EventBackend, sink: EffectSink) -> None:
        self._backend = backend
        self._sink = sink

    def store(self, tag: str, event: EventBase) -> None:
        if isinstance(event, EffectRecord):
            self._sink(event)
        self._backend.store(tag, event)

    def get(self, tag: str) -> EventBase | None:
        return self._backend.get(tag)

    def get_by_id(self, event_id: str) -> EventBase | None:
        return self._backend.get_by_id(event_id)

    def update(self, tag: str, **fields: Any) -> bool:
        return self._backend.update(tag, **fields)

    def remove(self, tag: str) -> bool:
        return self._backend.remove(tag)

    def set_status(self, tag: str, status: EventStatus) -> bool:
        return self._backend.set_status(tag, status)

    def active_tags(self) -> list[str]:
        return self._backend.active_tags()

    def insert_active_tag(self, tag: str, index: int) -> None:
        self._backend.insert_active_tag(tag, index)

    def remove_active_tag(self, tag: str) -> bool:
        return self._backend.remove_active_tag(tag)

    def all_events(self) -> Iterator[EventBase]:
        return self._backend.all_events()

    def find_tag(self, event: EventBase) -> str | None:
        return self._backend.find_tag(event)

    def register_event_type(self, cls: type[EventBase]) -> None:
        self._backend.register_event_type(cls)

    def clear(self) -> None:
        self._backend.clear()

    def allocate_next_tag(self) -> str:
        return self._backend.allocate_next_tag()

    def __len__(self) -> int:
        return len(self._backend)


def install_effect_sink(event_manager: EventManager, sink: EffectSink) -> Callable[[], None]:
    """Wrap an event manager's current backend with ``EffectRecordSinkBackend``.

    The returned callable restores the previous backend only if this wrapper is
    still installed. A later :meth:`~nooa.runtime.event_manager.EventManager.set_backend`
    call replaces the wrapper, so applications that swap storage backends must
    reinstall the sink on the new backend.
    """

    previous_backend = event_manager.get_backend()
    wrapped_backend = EffectRecordSinkBackend(previous_backend, sink)
    event_manager.set_backend(wrapped_backend)

    def uninstall() -> None:
        if event_manager.get_backend() is wrapped_backend:
            event_manager.set_backend(previous_backend)

    return uninstall
