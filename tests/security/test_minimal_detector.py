# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the minimal out-of-process detector recipe."""

from __future__ import annotations

import ast
import fcntl
import os
from pathlib import Path

import nooa.security as security
from examples.security_hardening import minimal_detector

MODULE_PATH = Path(minimal_detector.__file__)


def test_minimal_detector_scores_clean_v2_stream() -> None:
    report = minimal_detector.run_demo()

    assert report["schema_version"] == "nooa-minimal-detector-example-v1"
    assert report["victim_returncode"] == 0
    assert report["detector_returncode"] == 0
    assert report["scored"] is True
    assert report["effect_egress_completeness_signals"] == []
    assert report["refusal_reason"] is None
    assert len(report["findings"]) == 1
    assert report["findings"][0]["finding_type"] == "data.export.allowed"


def test_minimal_detector_refuses_missing_stream_end() -> None:
    report = minimal_detector.run_demo(victim_fault="exit_between_frames")

    assert report["victim_returncode"] == 3
    assert report["detector_returncode"] == 0
    assert report["scored"] is False
    assert report["effect_egress_completeness_signals"] == ["missing_stream_end"]
    assert report["refusal_reason"] == "effect egress completeness gate did not pass"
    assert report["findings"] == []


def test_minimal_detector_withholds_each_pipe_peer_from_the_other_child(
    monkeypatch,
) -> None:
    captured: list[tuple[str, tuple[int, ...], tuple[int, ...]]] = []
    original_spawn = minimal_detector._spawn_subprocess

    def capture_spawn(*args: str, pass_fds: tuple[int, ...]):
        access_modes = tuple(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE for fd in pass_fds)
        captured.append((args[0], pass_fds, access_modes))
        return original_spawn(*args, pass_fds=pass_fds)

    monkeypatch.setattr(minimal_detector, "_spawn_subprocess", capture_spawn)

    minimal_detector.run_demo()

    assert [role for role, _fds, _modes in captured] == ["detector", "victim"]
    assert len(captured[0][1]) == 1
    assert len(captured[1][1]) == 1
    assert captured[0][1][0] != captured[1][1][0]
    assert captured[0][2] == (os.O_RDONLY,)
    assert captured[1][2] == (os.O_WRONLY,)


def test_minimal_detector_imports_only_public_security_exports() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "nooa.security"
        for alias in node.names
    }

    assert imported_names
    assert imported_names <= set(security.__all__)
