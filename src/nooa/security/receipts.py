# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security receipt transport schema."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue


class SecurityReceipt(BaseModel):
    """Transport schema for backend receipts intended for out-of-band collection.

    A ``SecurityReceipt`` is a transport schema for application-supplied
    backend truth. The type does not authenticate its source, establish where
    collection happened, or make data constructed inside the victim process
    trustworthy. Construct receipts only from an out-of-band collector or
    separately trusted sink; do not emit them from an observer or generated
    code.

    Fields are intentionally generic so applications can preserve stable
    receipt identity and provenance without standardizing policy or scorer
    semantics into NOOA. ``target`` and ``effect_type`` mirror
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
