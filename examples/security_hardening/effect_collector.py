# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Out-of-process effect collection for the identity hardening example.

This example keeps process lifecycle outside ``src/nooa``. A supervisor creates
one pipe, starts a collector subprocess with only the read end, and starts a
victim subprocess with only the write end. The collector uses
``read_effect_egress()`` until EOF and returns stream-shape facts separately
from the victim's process exit status.

The split makes bytes already emitted unavailable for readback or truncation by
the victim process. It does not authenticate record contents, prevent a
compromised victim from emitting forged records or stopping cleanly, provide
sandboxing or attestation, or turn stream facts into a detector verdict.

    uv run python -m examples.security_hardening.effect_collector demo
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import fcntl
import os
import subprocess
import sys
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from examples.security_hardening.identity_approval import (
    PROMPT_INJECTION_REQUEST,
    AccessRequest,
    IdentityApprovalAgent,
    IdentityBackend,
    authorized_request_with_token,
    install_identity_grant_defender,
    observe_identity_grant,
)
from nooa.security import (
    EffectEgressReadResult,
    EffectRecord,
    FdEffectSink,
    framework_guard_observer,
    install_agent_call_effect_recorder,
    install_effect_recorder,
    install_effect_sink,
    read_effect_egress,
)

_COLLECTOR_SCHEMA_VERSION: Literal["nooa-effect-collector-example-v1"] = (
    "nooa-effect-collector-example-v1"
)
_VICTIM_SCHEMA_VERSION: Literal["nooa-effect-collector-victim-example-v1"] = (
    "nooa-effect-collector-victim-example-v1"
)
_DEMO_SCHEMA_VERSION: Literal["nooa-effect-collector-demo-v1"] = "nooa-effect-collector-demo-v1"
_VICTIM_FAULTS = ("none", "partial_tail_crash")
_REPO_ROOT = Path(__file__).resolve().parents[2]
VictimFault = Literal["none", "partial_tail_crash"]
_FdIdentity = tuple[int, int, int]


class CollectorSummary(BaseModel):
    """Example-local summary emitted by the collector subprocess."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-effect-collector-example-v1"] = _COLLECTOR_SCHEMA_VERSION
    records: tuple[EffectRecord, ...] = ()
    record_count: int = Field(ge=0)
    first_sequence_error: tuple[int, int] | None = None
    truncated: bool

    @model_validator(mode="after")
    def _validate_summary(self) -> Self:
        if self.record_count != len(self.records):
            raise ValueError("record_count must match records length")
        return self

    @classmethod
    def from_egress(cls, egress: EffectEgressReadResult) -> Self:
        """Build a summary from collector-side egress parsing."""
        return cls(
            records=egress.records,
            record_count=len(egress.records),
            first_sequence_error=egress.first_sequence_error,
            truncated=egress.truncated,
        )


class VictimSummary(BaseModel):
    """Example-local summary emitted by the victim subprocess.

    Every field is victim-controlled. The descriptor probes exist only to pin
    honest harness construction in tests; they are not trusted evidence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-effect-collector-victim-example-v1"] = _VICTIM_SCHEMA_VERSION
    scenario: str = Field(min_length=1)
    decision: Literal["allowed", "denied"]
    decision_source: Literal["backend", "defender"]
    backend_event_count: int = Field(ge=0)
    self_reported_collector_read_endpoint_open: bool | None = None
    self_reported_receipt_read_endpoint_open: bool | None = None
    self_reported_receipt_write_endpoint_open: bool | None = None
    self_reported_approval_request_read_endpoint_open: bool | None = None
    self_reported_approval_response_write_endpoint_open: bool | None = None


class CollectedScenario(BaseModel):
    """Supervisor-side join of victim status and collector stream facts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-effect-collector-demo-v1"] = _DEMO_SCHEMA_VERSION
    victim: VictimSummary | None = None
    collector: CollectorSummary
    victim_returncode: int

    @model_validator(mode="after")
    def _validate_victim_summary(self) -> Self:
        if self.victim_returncode == 0 and self.victim is None:
            raise ValueError("successful victim subprocess must emit a victim summary")
        return self


def collect_fd(fd: int) -> CollectorSummary:
    """Read a borrowed descriptor to EOF and summarize the received frames."""
    with os.fdopen(fd, "rb", closefd=True) as fh:
        return CollectorSummary.from_egress(read_effect_egress(fh))


async def run_victim_to_fd(
    scenario: str,
    fd: int,
    *,
    collector_read_identity: _FdIdentity | None = None,
    receipt_read_identity: _FdIdentity | None = None,
    receipt_write_identity: _FdIdentity | None = None,
    approval_request_read_identity: _FdIdentity | None = None,
    approval_response_write_identity: _FdIdentity | None = None,
    fault: VictimFault = "none",
    emit_guard_effect: bool = False,
) -> VictimSummary:
    """Run one identity scenario with only a write descriptor for egress.

    ``emit_guard_effect`` is an example-local coverage knob: it adds one
    framework guard-shaped record after the identity decision so tests can pin
    observer-label separation across the subprocess boundary.
    """
    request, enforce_approval, defender_enabled = _scenario_config(scenario)
    fault = _validate_victim_fault(fault)
    backend = IdentityBackend(enforce_approval=enforce_approval)
    agent = IdentityApprovalAgent(backend)
    self_reported_collector_read_endpoint_open = (
        _has_fd_identity(collector_read_identity) if collector_read_identity is not None else None
    )
    self_reported_receipt_read_endpoint_open = (
        _has_fd_identity(receipt_read_identity) if receipt_read_identity is not None else None
    )
    self_reported_receipt_write_endpoint_open = (
        _has_fd_identity(receipt_write_identity) if receipt_write_identity is not None else None
    )
    self_reported_approval_request_read_endpoint_open = (
        _has_fd_identity(approval_request_read_identity)
        if approval_request_read_identity is not None
        else None
    )
    self_reported_approval_response_write_endpoint_open = (
        _has_fd_identity(approval_response_write_identity)
        if approval_response_write_identity is not None
        else None
    )

    with ExitStack() as cleanup:
        cleanup.callback(os.close, fd)
        cleanup.callback(install_effect_sink(agent.event_manager, FdEffectSink(fd)))
        cleanup.callback(
            install_agent_call_effect_recorder(
                agent.event_manager,
                observe_identity_grant,
            )
        )
        if defender_enabled:
            cleanup.callback(install_identity_grant_defender(agent.event_manager))
        if emit_guard_effect:
            cleanup.callback(install_effect_recorder(agent.event_manager, framework_guard_observer))
        decision = await agent.handle_request(request)
        if emit_guard_effect:
            await agent.runtime.execute_code("eval('1 + 1')")
        if fault == "partial_tail_crash":
            _write_all(fd, b'{"schema_version":"nooa-effect-egress-v1"')
            raise SystemExit(3)

    return VictimSummary(
        scenario=scenario,
        decision="allowed" if decision.granted else "denied",
        decision_source=decision.source,
        backend_event_count=len(backend.audit_log()),
        self_reported_collector_read_endpoint_open=self_reported_collector_read_endpoint_open,
        self_reported_receipt_read_endpoint_open=self_reported_receipt_read_endpoint_open,
        self_reported_receipt_write_endpoint_open=self_reported_receipt_write_endpoint_open,
        self_reported_approval_request_read_endpoint_open=(
            self_reported_approval_request_read_endpoint_open
        ),
        self_reported_approval_response_write_endpoint_open=(
            self_reported_approval_response_write_endpoint_open
        ),
    )


def run_collected_scenario(
    scenario: str = "vulnerable_attack",
    *,
    victim_fault: VictimFault = "none",
    emit_guard_effect: bool = False,
    timeout: float = 10.0,
) -> CollectedScenario:
    """Run one victim and one collector subprocess over a supervisor-owned pipe."""
    _scenario_config(scenario)
    victim_fault = _validate_victim_fault(victim_fault)
    read_fd, write_fd = os.pipe()
    collector_read_identity = _fd_identity(read_fd)
    collector: subprocess.Popen[str] | None = None
    victim: subprocess.Popen[str] | None = None
    try:
        collector = _spawn_subprocess("collect", "--fd", str(read_fd), pass_fds=(read_fd,))
        victim_args = [
            "victim",
            "--fd",
            str(write_fd),
            "--scenario",
            scenario,
            "--collector-read-device",
            str(collector_read_identity[0]),
            "--collector-read-inode",
            str(collector_read_identity[1]),
            "--collector-read-access-mode",
            str(collector_read_identity[2]),
            "--fault",
            victim_fault,
        ]
        if emit_guard_effect:
            victim_args.append("--emit-guard-effect")
        victim = _spawn_subprocess(*victim_args, pass_fds=(write_fd,))
    except BaseException:
        _terminate_process(victim)
        _terminate_process(collector)
        raise
    finally:
        os.close(read_fd)
        os.close(write_fd)

    try:
        victim_stdout, victim_stderr = victim.communicate(timeout=timeout)
        collector_stdout, collector_stderr = collector.communicate(timeout=timeout)
    except BaseException:
        _terminate_process(victim)
        _terminate_process(collector)
        raise

    if collector.returncode != 0:
        raise RuntimeError(
            "collector subprocess failed with "
            f"returncode={collector.returncode}: {collector_stderr.strip()}"
        )

    victim_summary = (
        VictimSummary.model_validate_json(victim_stdout) if victim.returncode == 0 else None
    )
    return CollectedScenario(
        victim=victim_summary,
        collector=CollectorSummary.model_validate_json(collector_stdout),
        victim_returncode=victim.returncode,
    )


def _spawn_subprocess(*args: str, pass_fds: tuple[int, ...]) -> subprocess.Popen[str]:
    """Launch this module in one role with an explicit inherited descriptor set."""
    return subprocess.Popen(
        [sys.executable, "-m", "examples.security_hardening.effect_collector", *args],
        cwd=_REPO_ROOT,
        pass_fds=pass_fds,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _terminate_process(process: subprocess.Popen[str] | None) -> None:
    """Best-effort teardown for a child that did not finish normally."""
    if process is None or process.poll() is not None:
        return
    process.kill()
    process.wait()


def _write_all(fd: int, payload: bytes) -> None:
    """Write one small example-local fault payload to a borrowed descriptor."""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written == 0:
            raise OSError("collector example descriptor accepted zero bytes")
        view = view[written:]


def _fd_identity(fd: int) -> _FdIdentity:
    """Return enough descriptor identity to distinguish one pipe endpoint."""
    stat = os.fstat(fd)
    access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
    return (stat.st_dev, stat.st_ino, access_mode)


def _has_fd_identity(identity: _FdIdentity) -> bool:
    """Return whether this process holds any descriptor for one endpoint."""
    for fd in _open_fd_numbers():
        try:
            if _fd_identity(fd) == identity:
                return True
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
    return False


def _open_fd_numbers() -> tuple[int, ...]:
    """List currently open descriptor numbers without depending on one platform."""
    for fd_dir in (Path("/proc/self/fd"), Path("/dev/fd")):
        try:
            return tuple(int(name) for name in os.listdir(fd_dir) if name.isdigit())
        except OSError:
            continue

    max_fd = min(int(os.sysconf("SC_OPEN_MAX")), 4096)
    return tuple(range(max_fd))


def _fd_identity_from_args(args: argparse.Namespace, prefix: str) -> _FdIdentity | None:
    """Parse one optional descriptor endpoint identity from CLI args."""
    values = (
        getattr(args, f"{prefix}_device"),
        getattr(args, f"{prefix}_inode"),
        getattr(args, f"{prefix}_access_mode"),
    )
    if values == (None, None, None):
        return None
    if any(value is None for value in values):
        raise ValueError(f"{prefix.replace('_', ' ')} identity requires device, inode, and access mode")
    return cast(_FdIdentity, values)


def _collector_read_identity_from_args(args: argparse.Namespace) -> _FdIdentity | None:
    """Parse the optional collector-read endpoint identity from CLI args."""
    return _fd_identity_from_args(args, "collector_read")


def _receipt_read_identity_from_args(args: argparse.Namespace) -> _FdIdentity | None:
    """Parse the optional receipt-read endpoint identity from CLI args."""
    return _fd_identity_from_args(args, "receipt_read")


def _receipt_write_identity_from_args(args: argparse.Namespace) -> _FdIdentity | None:
    """Parse the optional receipt-write endpoint identity from CLI args."""
    return _fd_identity_from_args(args, "receipt_write")


def _approval_request_read_identity_from_args(args: argparse.Namespace) -> _FdIdentity | None:
    """Parse the optional approval-request-read endpoint identity from CLI args."""
    return _fd_identity_from_args(args, "approval_request_read")


def _approval_response_write_identity_from_args(args: argparse.Namespace) -> _FdIdentity | None:
    """Parse the optional approval-response-write endpoint identity from CLI args."""
    return _fd_identity_from_args(args, "approval_response_write")


def _validate_victim_fault(fault: str) -> VictimFault:
    """Validate one example-local victim fault mode."""
    if fault == "none" or fault == "partial_tail_crash":
        return cast(VictimFault, fault)
    raise ValueError(f"unknown identity collector victim fault: {fault}")


def _scenario_config(scenario: str) -> tuple[AccessRequest, bool, bool]:
    """Return the existing demo's request, backend policy, and defender mode."""
    configs = {
        "vulnerable_attack": (PROMPT_INJECTION_REQUEST, False, False),
        "defender_only_attack": (PROMPT_INJECTION_REQUEST, False, True),
        "hardened_attack": (PROMPT_INJECTION_REQUEST, True, False),
        "hardened_authorized": (authorized_request_with_token(), True, False),
    }
    try:
        return configs[scenario]
    except KeyError as exc:
        raise ValueError(f"unknown identity collector scenario: {scenario}") from exc


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect", help="Read effect frames from one fd.")
    collect_parser.add_argument("--fd", type=int, required=True)

    victim_parser = subparsers.add_parser("victim", help="Run one identity victim scenario.")
    victim_parser.add_argument("--fd", type=int, required=True)
    victim_parser.add_argument("--scenario", default="vulnerable_attack")
    victim_parser.add_argument("--collector-read-device", type=int)
    victim_parser.add_argument("--collector-read-inode", type=int)
    victim_parser.add_argument("--collector-read-access-mode", type=int)
    victim_parser.add_argument("--receipt-read-device", type=int)
    victim_parser.add_argument("--receipt-read-inode", type=int)
    victim_parser.add_argument("--receipt-read-access-mode", type=int)
    victim_parser.add_argument("--receipt-write-device", type=int)
    victim_parser.add_argument("--receipt-write-inode", type=int)
    victim_parser.add_argument("--receipt-write-access-mode", type=int)
    victim_parser.add_argument("--approval-request-read-device", type=int)
    victim_parser.add_argument("--approval-request-read-inode", type=int)
    victim_parser.add_argument("--approval-request-read-access-mode", type=int)
    victim_parser.add_argument("--approval-response-write-device", type=int)
    victim_parser.add_argument("--approval-response-write-inode", type=int)
    victim_parser.add_argument("--approval-response-write-access-mode", type=int)
    victim_parser.add_argument("--fault", choices=_VICTIM_FAULTS, default="none")
    victim_parser.add_argument("--emit-guard-effect", action="store_true")

    demo_parser = subparsers.add_parser("demo", help="Run the supervisor/victim/collector demo.")
    demo_parser.add_argument("--scenario", default="vulnerable_attack")
    demo_parser.add_argument("--victim-fault", choices=_VICTIM_FAULTS, default="none")
    demo_parser.add_argument("--emit-guard-effect", action="store_true")
    demo_parser.add_argument("--timeout", type=float, default=10.0)

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run one collector role, victim role, or the combined demo."""
    args = _parse_args(argv)
    if args.command == "collect":
        print(collect_fd(args.fd).model_dump_json())
        return 0
    if args.command == "victim":
        print(
            asyncio.run(
                run_victim_to_fd(
                    args.scenario,
                    args.fd,
                    collector_read_identity=_collector_read_identity_from_args(args),
                    receipt_read_identity=_receipt_read_identity_from_args(args),
                    receipt_write_identity=_receipt_write_identity_from_args(args),
                    approval_request_read_identity=_approval_request_read_identity_from_args(args),
                    approval_response_write_identity=_approval_response_write_identity_from_args(
                        args
                    ),
                    fault=args.fault,
                    emit_guard_effect=args.emit_guard_effect,
                )
            ).model_dump_json()
        )
        return 0

    result = run_collected_scenario(
        args.scenario,
        victim_fault=args.victim_fault,
        emit_guard_effect=args.emit_guard_effect,
        timeout=args.timeout,
    )
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
