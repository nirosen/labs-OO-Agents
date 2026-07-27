# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Security finding transport schema."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue

EvidenceRef = Annotated[str, Field(min_length=1)]


class SecurityFinding(BaseModel):
    """Transport schema for detector or scorer findings.

    A ``SecurityFinding`` is a portable record shape, not a detector, policy
    engine, or trust boundary. It does not authenticate ``producer``, verify
    that ``evidence_refs`` exist, or make data constructed inside a victim
    process trustworthy. A finding is only as trustworthy as the execution and
    collection boundary that produced it.

    ``run_id`` is application-assigned scope for grouping findings from one
    run or assessment; NOOA does not mint it, verify it, or infer that equal
    values establish trusted provenance. ``evidence_refs`` are opaque
    identifiers so applications can point at ``EffectRecord.id``,
    ``SecurityReceipt.receipt_id``, SIEM records, or other evidence without
    making NOOA own the join semantics. The schema
    intentionally does not standardize severity, verdict, or enforcement
    action; those remain application policy. Field bindings are frozen for
    transport stability, but nested ``attributes`` values remain ordinary
    Python containers and are not a tamper-resistance boundary.

    ``attributes`` must contain sanitized JSON values only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-finding-v1"] = Field(
        default="nooa-finding-v1",
        description="Finding wire-format discriminator.",
    )
    finding_id: str = Field(
        min_length=1,
        description="Stable finding identifier assigned by the producer.",
    )
    finding_type: str = Field(
        min_length=1,
        description="Application-defined finding category, e.g. 'prompt_injection.suspected'.",
    )
    producer: str = Field(
        min_length=1,
        description="Sanitized identifier for the detector, scorer, or policy producer.",
    )
    run_id: str = Field(
        default="",
        description="Application-assigned run or assessment scope for grouping related findings.",
    )
    target: str = Field(
        default="",
        description="Sanitized target identifier for the finding, if any.",
    )
    evidence_refs: tuple[EvidenceRef, ...] = Field(
        default_factory=tuple,
        description="Opaque identifiers for evidence that supports this finding.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined finding details.",
    )
