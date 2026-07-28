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
    AuthoritySummary,
    _transport_receipts_for_fault,
    _validate_authority_receipt_bundle,
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
from nooa.security import ReceiptBundle, SecurityReceipt


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


def test_authority_models_are_strict_and_summary_counts_receipts() -> None:
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
    with pytest.raises(ValidationError, match="issued_token_count must match receipt_count"):
        AuthoritySummary(
            request_count=1,
            issued_token_count=1,
            receipt_count=0,
        )


def test_authority_receipt_bundle_keeps_receipt_source_aligned() -> None:
    bundle = ReceiptBundle(
        receipt_source="approval-authority",
        declared_receipt_count=1,
        receipts=(
            SecurityReceipt(
                receipt_id="receipt-1",
                receipt_type="identity.approval",
                source="victim",
            ),
        ),
    )

    with pytest.raises(ValueError, match="authority receipts must use receipt_source"):
        _validate_authority_receipt_bundle(bundle)


def test_duplicate_receipt_id_fault_duplicates_one_transport_copy_only() -> None:
    receipt = SecurityReceipt(
        receipt_id="receipt-1",
        receipt_type="identity.approval",
        source="approval-authority",
    )

    transported = _transport_receipts_for_fault((receipt,), fault="duplicate_receipt_id")

    assert transported == (receipt, receipt)
    assert transported[0] is not transported[1]
    with pytest.raises(
        ValueError,
        match="duplicate_receipt_id requires at least one authority receipt",
    ):
        _transport_receipts_for_fault((), fault="duplicate_receipt_id")


def test_mislabel_receipt_source_fault_rewrites_one_transport_copy_only() -> None:
    receipt = SecurityReceipt(
        receipt_id="receipt-1",
        receipt_type="identity.approval",
        source="approval-authority",
    )

    transported = _transport_receipts_for_fault((receipt,), fault="mislabel_receipt_source")

    assert transported[0].receipt_id == receipt.receipt_id
    assert transported[0].source == "approval-authority/mislabel"
    assert transported[0] is not receipt
    assert receipt.source == "approval-authority"
    with pytest.raises(
        ValueError,
        match="mislabel_receipt_source requires at least one authority receipt",
    ):
        _transport_receipts_for_fault((), fault="mislabel_receipt_source")


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
