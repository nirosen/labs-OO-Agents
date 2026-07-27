# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared example constants for the identity hardening flow."""

from __future__ import annotations

EFFECT_TYPE = "identity.grant_access"
RECEIPT_TYPE = "identity.approval"
FINDING_TYPE = "identity.grant_without_approval"
_APPROVAL_TOKEN_PREFIX = "approval-token-42"


def derive_approval_token(request_id: str, *, run_id: str = "") -> str:
    """Derive one deterministic demo token for a request and optional run scope."""
    if run_id:
        return f"{_APPROVAL_TOKEN_PREFIX}:{request_id}:{run_id}"
    return _APPROVAL_TOKEN_PREFIX
