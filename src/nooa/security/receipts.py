# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security receipt transport and opt-in run-scope helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

ReceiptScopeSignal = Literal["missing_run_id", "run_id_mismatch"]
# Tuple order is public because ReceiptScopeError.reasons preserves it.
RECEIPT_SCOPE_SIGNALS: tuple[ReceiptScopeSignal, ...] = (
    "missing_run_id",
    "run_id_mismatch",
)


class SecurityReceipt(BaseModel):
    """Transport schema for backend receipts intended for out-of-band collection.

    A ``SecurityReceipt`` is a transport schema for application-supplied
    backend truth. The type does not authenticate its source, establish where
    collection happened, or make data constructed inside the victim process
    trustworthy. Construct receipts only from an out-of-band collector or
    separately trusted sink; do not emit them from an observer or generated
    code.

    Fields are intentionally generic so applications can preserve stable
    receipt identity, provenance, and optional run scope without standardizing
    policy or scorer semantics into NOOA. ``run_id`` is application-assigned;
    NOOA does not mint it, verify it, or infer that equal values establish
    trusted provenance. ``target`` and ``effect_type`` mirror
    :class:`~nooa.security.effects.EffectRecord` only for application-defined
    correlation; NOOA does not join receipts to effect records or guarantee
    that a backend knows runtime lineage fields such as ``generation_id`` or
    ``tool_call_id``. Field bindings are frozen for transport stability, but
    nested ``attributes`` values remain ordinary Python containers and are not
    a tamper-resistance boundary. ``attributes`` must contain sanitized JSON
    values only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-receipt-v1"] = Field(
        default="nooa-receipt-v1",
        description="Receipt wire-format discriminator.",
    )
    receipt_id: str = Field(
        min_length=1,
        description="Stable receipt identifier assigned by the source system.",
    )
    receipt_type: str = Field(
        min_length=1,
        description="Application-defined receipt category, e.g. 'payment.accepted'.",
    )
    source: str = Field(
        min_length=1,
        description="Sanitized identifier for the out-of-band source that issued the receipt.",
    )
    run_id: str = Field(
        default="",
        description="Application-assigned run or assessment scope for grouping related receipts.",
    )
    target: str = Field(
        default="",
        description="Sanitized target identifier for the receipt, if any.",
    )
    effect_type: str = Field(
        default="",
        description="Effect category this receipt corroborates, if known.",
    )
    issued_at: str = Field(
        default="",
        description="Serialized source-issued timestamp, if available.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined receipt details.",
    )


@dataclass(frozen=True)
class ReceiptScopeValidation:
    """Run-scope diagnostics for one materialized receipt bundle.

    This result preserves the input order in ``receipts`` and reports only
    collector-visible ``run_id`` inconsistencies against one caller-selected
    ``expected_run_id``. It does not authenticate receipt sources, verify
    coverage, inspect application attributes, enforce receipt-id uniqueness,
    correlate receipts to effects, or prove backend truth.

    A clean empty result means only that none of the supplied receipts
    contradicted the requested run scope. It does not prove that no receipts
    exist or that collection was complete.

    Direct construction only asserts these diagnostic fields; it does not
    perform the check that :func:`validate_receipt_scope` performs.
    """

    receipts: tuple[SecurityReceipt, ...]
    expected_run_id: str
    missing_run_id_receipt_ids: tuple[str, ...] = ()
    mismatched_run_id_receipt_ids: tuple[str, ...] = ()


class ReceiptScopeError(RuntimeError):
    """Raised when supplied receipts do not fit one expected run scope.

    This error reports only diagnostics visible in a
    :class:`ReceiptScopeValidation`. It does not establish receipt
    authenticity, coverage, or semantic correctness.
    """

    def __init__(self, validation: ReceiptScopeValidation) -> None:
        if not isinstance(validation, ReceiptScopeValidation):
            raise TypeError(
                "ReceiptScopeError expected ReceiptScopeValidation, "
                f"got {type(validation).__name__}"
            )
        reasons = receipt_scope_signals(validation)
        if not reasons:
            raise ValueError("ReceiptScopeError requires at least one scope signal")
        self.expected_run_id = validation.expected_run_id
        self.missing_run_id_receipt_ids = validation.missing_run_id_receipt_ids
        self.mismatched_run_id_receipt_ids = validation.mismatched_run_id_receipt_ids
        self.reasons = reasons
        super().__init__(
            "receipt bundle does not match expected run scope: "
            f"expected_run_id={validation.expected_run_id!r}, "
            f"missing_run_id_receipt_ids={validation.missing_run_id_receipt_ids!r}, "
            f"mismatched_run_id_receipt_ids={validation.mismatched_run_id_receipt_ids!r}"
        )


def receipt_scope_signals(validation: ReceiptScopeValidation) -> tuple[ReceiptScopeSignal, ...]:
    """Return canonical run-scope diagnostics for one receipt bundle."""
    if not isinstance(validation, ReceiptScopeValidation):
        raise TypeError(
            "receipt_scope_signals expected ReceiptScopeValidation, "
            f"got {type(validation).__name__}"
        )
    signals: list[ReceiptScopeSignal] = []
    if validation.missing_run_id_receipt_ids:
        signals.append("missing_run_id")
    if validation.mismatched_run_id_receipt_ids:
        signals.append("run_id_mismatch")
    return tuple(signals)


def validate_receipt_scope(
    receipts: Iterable[SecurityReceipt],
    *,
    expected_run_id: str,
) -> ReceiptScopeValidation:
    """Materialize receipts and report run-scope inconsistencies.

    ``receipts`` is consumed once, preserved in input order, and stored as the
    tuple returned by :func:`require_valid_receipt_scope` when no scope signal
    is present. ``expected_run_id`` must be a non-empty caller-selected scope;
    this helper does not mint or authenticate it.

    The helper checks only that each supplied receipt carries a non-empty
    ``run_id`` equal to ``expected_run_id``. It does not verify source identity,
    receipt coverage, receipt-id uniqueness, receipt-to-effect joins, or
    application-specific receipt semantics.
    """
    if not isinstance(expected_run_id, str):
        raise TypeError(
            "validate_receipt_scope expected str expected_run_id, "
            f"got {type(expected_run_id).__name__}"
        )
    if not expected_run_id:
        raise ValueError("validate_receipt_scope requires non-empty expected_run_id")
    if isinstance(receipts, (str, bytes, bytearray)) or not isinstance(receipts, Iterable):
        raise TypeError(
            "validate_receipt_scope expected iterable of SecurityReceipt, "
            f"got {type(receipts).__name__}"
        )

    materialized = tuple(receipts)
    for index, receipt in enumerate(materialized):
        if not isinstance(receipt, SecurityReceipt):
            raise TypeError(
                "validate_receipt_scope expected SecurityReceipt at "
                f"index {index}, got {type(receipt).__name__}"
            )

    return ReceiptScopeValidation(
        receipts=materialized,
        expected_run_id=expected_run_id,
        missing_run_id_receipt_ids=tuple(
            receipt.receipt_id for receipt in materialized if not receipt.run_id
        ),
        mismatched_run_id_receipt_ids=tuple(
            receipt.receipt_id
            for receipt in materialized
            if receipt.run_id and receipt.run_id != expected_run_id
        ),
    )


def require_valid_receipt_scope(
    validation: ReceiptScopeValidation,
) -> tuple[SecurityReceipt, ...]:
    """Return supplied receipts or fail closed on visible run-scope drift."""
    if not isinstance(validation, ReceiptScopeValidation):
        raise TypeError(
            "require_valid_receipt_scope expected ReceiptScopeValidation, "
            f"got {type(validation).__name__}"
        )
    if receipt_scope_signals(validation):
        raise ReceiptScopeError(validation)
    return validation.receipts
