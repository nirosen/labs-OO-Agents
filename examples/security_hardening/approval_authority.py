# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Example-only approval authority for the identity hardening flow.

The authority owns one fixed demo allowlist, accepts one bounded approval
request document, returns a token response to the victim, and writes a separate
public receipt bundle for the detector. It demonstrates issuance separation only:
the process is not authenticated, signed, privileged, or an IAM system.

    uv run python -m examples.security_hardening.approval_authority --help
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from typing import BinaryIO, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from examples.security_hardening.identity_contract import (
    EFFECT_TYPE,
    RECEIPT_TYPE,
    derive_approval_token,
)
from nooa.security import ReceiptBundle, SecurityReceipt, write_receipt_bundle

_APPROVAL_REQUEST_SCHEMA_VERSION: Literal["nooa-approval-authority-request-example-v1"] = (
    "nooa-approval-authority-request-example-v1"
)
_APPROVAL_RESPONSE_SCHEMA_VERSION: Literal["nooa-approval-authority-response-example-v1"] = (
    "nooa-approval-authority-response-example-v1"
)
_AUTHORITY_SUMMARY_SCHEMA_VERSION: Literal["nooa-approval-authority-summary-example-v1"] = (
    "nooa-approval-authority-summary-example-v1"
)
_AUTHORITY_SOURCE: Literal["approval-authority"] = "approval-authority"
_AUTHORITY_FAULTS = (
    "none",
    "exit_before_receipt",
    "stale_receipt_run_id",
    "truncate_receipt_document",
    "drop_receipt_count_mismatch",
)
DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES = 1024 * 1024
AuthorityFault = Literal[
    "none",
    "exit_before_receipt",
    "stale_receipt_run_id",
    "truncate_receipt_document",
    "drop_receipt_count_mismatch",
]

_APPROVED_REQUESTS: dict[str, tuple[str, str]] = {
    "req-approved": ("oncall-engineer", "prod-db"),
}


class AuthorityInputTooLargeError(ValueError):
    """Raised when an authority input exceeds its configured byte budget."""

    def __init__(self, max_document_bytes: int) -> None:
        self.max_document_bytes = max_document_bytes
        super().__init__(f"approval authority input exceeds max_document_bytes={max_document_bytes}")


class ApprovalRequestDocument(BaseModel):
    """One bounded approval request presented to the authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-approval-authority-request-example-v1"] = (
        _APPROVAL_REQUEST_SCHEMA_VERSION
    )
    request_id: str = Field(min_length=1)
    principal: str = Field(min_length=1)
    resource: str = Field(min_length=1)


class ApprovalResponseDocument(BaseModel):
    """Authority response returned to the victim over a separate descriptor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-approval-authority-response-example-v1"] = (
        _APPROVAL_RESPONSE_SCHEMA_VERSION
    )
    request_id: str = Field(min_length=1)
    approved: bool
    approval_token: str | None = None

    @model_validator(mode="after")
    def _validate_response(self) -> Self:
        if self.approved and self.approval_token is None:
            raise ValueError("approved authority response requires approval_token")
        if not self.approved and self.approval_token is not None:
            raise ValueError("denied authority response cannot carry approval_token")
        return self


class AuthoritySummary(BaseModel):
    """Example-local summary emitted by the authority subprocess."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-approval-authority-summary-example-v1"] = (
        _AUTHORITY_SUMMARY_SCHEMA_VERSION
    )
    request_count: int = Field(ge=0)
    issued_token_count: int = Field(ge=0)
    receipt_count: int = Field(ge=0)
    receipt_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_summary(self) -> Self:
        if self.receipt_count != len(self.receipt_ids):
            raise ValueError("receipt_count must match receipt_ids length")
        if self.issued_token_count != self.receipt_count:
            raise ValueError("issued_token_count must match receipt_count")
        return self


def approval_token_for_request(
    request_id: str,
    *,
    principal: str | None = None,
    resource: str | None = None,
    run_id: str = "",
) -> str | None:
    """Return one deterministic demo token only when the request matches the allowlist."""
    approved = _APPROVED_REQUESTS.get(request_id)
    if approved is None:
        return None
    approved_principal, approved_resource = approved
    if principal is not None and principal != approved_principal:
        return None
    if resource is not None and resource != approved_resource:
        return None
    return derive_approval_token(request_id, run_id=run_id)


def approval_tokens_by_request_id(*, run_id: str = "") -> Mapping[str, str]:
    """Return a copy of the fixed demo token map for the example backend."""
    return {
        request_id: derive_approval_token(request_id, run_id=run_id)
        for request_id in _APPROVED_REQUESTS
    }


def read_approval_request_document(
    fh: BinaryIO,
    *,
    max_document_bytes: int = DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
) -> ApprovalRequestDocument:
    """Read exactly one bounded approval request document from a binary stream."""
    return _read_bounded_json_document(
        fh,
        ApprovalRequestDocument,
        max_document_bytes=max_document_bytes,
    )


def read_approval_response_document(
    fh: BinaryIO,
    *,
    max_document_bytes: int = DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
) -> ApprovalResponseDocument:
    """Read exactly one bounded approval response document from a binary stream."""
    return _read_bounded_json_document(
        fh,
        ApprovalResponseDocument,
        max_document_bytes=max_document_bytes,
    )


def issue_fd(
    request_fd: int,
    response_fd: int,
    receipt_fd: int,
    *,
    run_id: str,
    fault: AuthorityFault = "none",
    max_document_bytes: int = DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
) -> AuthoritySummary:
    """Issue one token response and one detector receipt bundle over descriptors."""
    fault = _validate_authority_fault(fault)
    max_document_bytes = _validate_max_document_bytes(max_document_bytes)
    with os.fdopen(request_fd, "rb", closefd=True) as request_fh:
        request = read_approval_request_document(
            request_fh,
            max_document_bytes=max_document_bytes,
        )

    token = approval_token_for_request(
        request.request_id,
        principal=request.principal,
        resource=request.resource,
        run_id=run_id,
    )
    response = ApprovalResponseDocument(
        request_id=request.request_id,
        approved=token is not None,
        approval_token=token,
    )
    with os.fdopen(response_fd, "wb", closefd=True) as response_fh:
        _write_document(response_fh, response)

    if fault == "exit_before_receipt":
        raise SystemExit(4)

    receipt_run_id = f"{run_id}/stale" if fault == "stale_receipt_run_id" else run_id
    receipts = _receipts_for_response(request, response, run_id=receipt_run_id)
    transported_receipts = () if fault == "drop_receipt_count_mismatch" else receipts
    receipt_bundle = _validate_authority_receipt_bundle(
        ReceiptBundle(
            receipt_source=_AUTHORITY_SOURCE,
            receipt_coverage="asserted_complete",
            declared_receipt_count=len(receipts),
            receipts=transported_receipts,
        )
    )
    with os.fdopen(receipt_fd, "wb", closefd=True) as receipt_fh:
        if fault == "truncate_receipt_document":
            _write_truncated_receipt_bundle(receipt_fh, receipt_bundle)
        else:
            write_receipt_bundle(receipt_fh, receipt_bundle)

    return AuthoritySummary(
        request_count=1,
        issued_token_count=len(receipts),
        receipt_count=len(receipts),
        receipt_ids=tuple(receipt.receipt_id for receipt in receipts),
    )


def _receipts_for_response(
    request: ApprovalRequestDocument,
    response: ApprovalResponseDocument,
    *,
    run_id: str,
) -> tuple[SecurityReceipt, ...]:
    """Build receipt rows only for tokens actually issued by the authority."""
    if not response.approved:
        return ()

    return (
        SecurityReceipt(
            receipt_id=f"authority-receipt-{request.request_id}",
            receipt_type=RECEIPT_TYPE,
            source=_AUTHORITY_SOURCE,
            run_id=run_id,
            target=f"{request.principal}@{request.resource}",
            effect_type=EFFECT_TYPE,
            attributes={
                "request_id": request.request_id,
                "principal": request.principal,
                "resource": request.resource,
            },
        ),
    )


def _read_bounded_json_document[
    AuthorityDocumentT: (ApprovalRequestDocument, ApprovalResponseDocument)
](
    fh: BinaryIO,
    model: type[AuthorityDocumentT],
    *,
    max_document_bytes: int,
) -> AuthorityDocumentT:
    """Read one bounded JSON document into one authority model type."""
    max_document_bytes = _validate_max_document_bytes(max_document_bytes)
    payload = fh.read(max_document_bytes + 1)
    if not isinstance(payload, bytes):
        raise TypeError(f"approval authority expected bytes, got {type(payload).__name__}")
    if len(payload) > max_document_bytes:
        raise AuthorityInputTooLargeError(max_document_bytes)
    return model.model_validate_json(payload)


def _write_document(fh: BinaryIO, document: BaseModel) -> None:
    payload = document.model_dump_json().encode("utf-8")
    written = fh.write(payload)
    if written != len(payload):
        raise OSError(f"approval authority wrote {written} of {len(payload)} bytes")
    fh.flush()


def _write_truncated_receipt_bundle(fh: BinaryIO, bundle: ReceiptBundle) -> None:
    """Write one valid JSON prefix without the required receipt-bundle LF terminator."""
    payload = bundle.model_dump_json().encode("utf-8")
    written = fh.write(payload)
    if written != len(payload):
        raise OSError(f"approval authority wrote {written} of {len(payload)} bytes")
    fh.flush()


def _validate_authority_receipt_bundle(bundle: ReceiptBundle) -> ReceiptBundle:
    """Keep the example authority's source assertion aligned with its receipt rows."""
    if any(receipt.source != bundle.receipt_source for receipt in bundle.receipts):
        raise ValueError("authority receipts must use receipt_source")
    return bundle


def _validate_authority_fault(fault: str) -> AuthorityFault:
    if fault in _AUTHORITY_FAULTS:
        return fault
    raise ValueError(f"unsupported authority fault: {fault}")


def _validate_max_document_bytes(max_document_bytes: int) -> int:
    if not isinstance(max_document_bytes, int) or isinstance(max_document_bytes, bool):
        raise TypeError(
            "approval authority expected int max_document_bytes, "
            f"got {type(max_document_bytes).__name__}"
        )
    if max_document_bytes <= 0:
        raise ValueError("approval authority requires max_document_bytes > 0")
    return max_document_bytes


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-fd", type=int, required=True)
    parser.add_argument("--response-fd", type=int, required=True)
    parser.add_argument("--receipt-fd", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--fault", choices=_AUTHORITY_FAULTS, default="none")
    parser.add_argument(
        "--max-document-bytes",
        type=int,
        default=DEFAULT_AUTHORITY_DOCUMENT_MAX_BYTES,
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    summary = issue_fd(
        args.request_fd,
        args.response_fd,
        args.receipt_fd,
        run_id=args.run_id,
        fault=args.fault,
        max_document_bytes=args.max_document_bytes,
    )
    print(summary.model_dump_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
