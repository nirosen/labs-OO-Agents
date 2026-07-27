# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the example-only approval authority."""

from __future__ import annotations

from io import BytesIO

import pytest
from pydantic import ValidationError

from examples.security_hardening.approval_authority import (
    ApprovalRequestDocument,
    ApprovalResponseDocument,
    AuthorityInputTooLargeError,
    AuthorityReceiptDocument,
    approval_token_for_request,
    approval_tokens_by_request_id,
    read_approval_request_document,
    read_approval_response_document,
)
from examples.security_hardening.identity_approval import (
    AUTHORIZED_REQUEST,
    IdentityBackend,
    authorized_request_with_token,
)
from nooa.security import SecurityReceipt


def test_authorized_request_fixture_requires_explicit_token_helper() -> None:
    assert AUTHORIZED_REQUEST.approval_token is None
    assert authorized_request_with_token().approval_token == "approval-token-42"


def test_approval_token_for_request_requires_full_allowlist_match() -> None:
    assert (
        approval_token_for_request(
            "req-approved",
            principal="oncall-engineer",
            resource="prod-db",
        )
        == "approval-token-42"
    )
    assert (
        approval_token_for_request(
            "req-approved",
            principal="contractor",
            resource="prod-db",
        )
        is None
    )
    assert approval_token_for_request("req-attack") is None


def test_run_scoped_authority_token_is_required_by_run_scoped_backend() -> None:
    backend = IdentityBackend(
        enforce_approval=True,
        approved_tokens=approval_tokens_by_request_id(run_id="run-1"),
    )

    stale_local_request = authorized_request_with_token()
    authority_request = authorized_request_with_token(run_id="run-1")

    assert stale_local_request.approval_token == "approval-token-42"
    assert authority_request.approval_token != stale_local_request.approval_token
    assert backend.grant_access(stale_local_request).granted is False
    assert backend.grant_access(authority_request).granted is True


def test_authority_models_are_strict_and_count_receipts() -> None:
    response = ApprovalResponseDocument(
        request_id="req-approved",
        approved=True,
        approval_token="approval-token-42",
    )

    assert response.schema_version == "nooa-approval-authority-response-example-v1"

    with pytest.raises(ValidationError, match="requires approval_token"):
        ApprovalResponseDocument(request_id="req-approved", approved=True)
    with pytest.raises(ValidationError, match="cannot carry approval_token"):
        ApprovalResponseDocument(
            request_id="req-attack",
            approved=False,
            approval_token="forged",
        )
    with pytest.raises(ValidationError, match="issued_token_count must match receipts length"):
        AuthorityReceiptDocument(issued_token_count=1)
    with pytest.raises(ValidationError, match="authority receipts must use receipt_source"):
        AuthorityReceiptDocument(
            issued_token_count=1,
            receipts=(
                SecurityReceipt(
                    receipt_id="receipt-1",
                    receipt_type="identity.approval",
                    source="victim",
                ),
            ),
        )


def test_authority_request_and_response_readers_are_bounded() -> None:
    request = ApprovalRequestDocument(
        request_id="req-approved",
        principal="oncall-engineer",
        resource="prod-db",
    )
    response = ApprovalResponseDocument(
        request_id="req-approved",
        approved=True,
        approval_token="approval-token-42",
    )
    request_payload = request.model_dump_json().encode("utf-8")
    response_payload = response.model_dump_json().encode("utf-8")

    assert read_approval_request_document(BytesIO(request_payload)) == request
    assert read_approval_response_document(BytesIO(response_payload)) == response

    with pytest.raises(AuthorityInputTooLargeError) as exc_info:
        read_approval_request_document(
            BytesIO(request_payload),
            max_document_bytes=len(request_payload) - 1,
        )

    assert exc_info.value.max_document_bytes == len(request_payload) - 1
