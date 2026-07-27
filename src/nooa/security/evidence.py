# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Detector-facing security evidence transport."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from nooa.security.effects import EffectRecord
from nooa.security.egress import (
    EFFECT_EGRESS_COMPLETENESS_SIGNALS,
    EffectEgressCompletenessSignal,
    EffectEgressIncompleteError,
    EffectEgressReadResult,
    effect_egress_completeness_signals,
    require_complete_effect_egress,
)
from nooa.security.receipts import SecurityReceipt

ReceiptCoverage = Literal["asserted_complete", "partial", "unknown"]


class DetectorInput(BaseModel):
    """Transport schema for detector-facing effect and receipt evidence.

    A ``DetectorInput`` is a portable bundle shape, not a detector, policy
    engine, verdict, or trust boundary. It does not authenticate effects,
    receipts, ``receipt_source``, or itself. Constructing one inside a victim
    process does not make its contents trustworthy.

    ``effect_egress_completeness_signals`` preserves only diagnostics already
    visible to :func:`~nooa.security.read_effect_egress`.
    ``effect_egress_completeness_gate_passed=True`` means only that
    :func:`~nooa.security.require_complete_effect_egress` saw no sequence
    discontinuity or trailing partial frame in the bytes it received; it does
    not prove that a writer emitted every effect. Direct construction can still
    only assert that field; it cannot make the assertion trustworthy.
    ``receipt_source`` and ``receipt_coverage`` are caller-supplied assertions
    for downstream policy. NOOA does not inspect the source, verify coverage,
    verify that receipts belong to ``run_id``, join receipts to effects, or
    infer that equal ``run_id`` values establish trusted provenance.

    Field bindings are frozen for transport stability, but nested effect,
    receipt, and ``attributes`` values remain ordinary Python containers and
    are not a tamper-resistance boundary. ``attributes`` must contain
    sanitized JSON values only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["nooa-detector-input-v1"] = Field(
        default="nooa-detector-input-v1",
        description="Detector input wire-format discriminator.",
    )
    input_id: str = Field(
        min_length=1,
        description="Stable detector-input identifier assigned by the producer.",
    )
    run_id: str = Field(
        default="",
        description="Application-assigned run or assessment scope for this detector input.",
    )
    effects: tuple[EffectRecord, ...] = Field(
        default_factory=tuple,
        description="Collector-facing effect copies supplied to downstream policy.",
    )
    effect_egress_completeness_signals: tuple[EffectEgressCompletenessSignal, ...] = Field(
        default_factory=tuple,
        description="Reader-visible egress diagnostics in canonical public order.",
    )
    effect_egress_completeness_gate_passed: bool = Field(
        default=False,
        description="Whether the public completeness gate was asserted to have passed.",
    )
    receipts: tuple[SecurityReceipt, ...] = Field(
        default_factory=tuple,
        description="Application-supplied backend receipt copies supplied to downstream policy.",
    )
    receipt_source: str = Field(
        default="",
        description="Sanitized identifier for the asserted receipt collection source, if any.",
    )
    receipt_coverage: ReceiptCoverage = Field(
        default="unknown",
        description="Caller assertion about the supplied receipt collection coverage.",
    )
    attributes: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Sanitized application-defined detector-input details.",
    )

    @model_validator(mode="after")
    def _validate_completeness_signal_order(self) -> Self:
        canonical = tuple(
            signal
            for signal in EFFECT_EGRESS_COMPLETENESS_SIGNALS
            if signal in self.effect_egress_completeness_signals
        )
        if self.effect_egress_completeness_signals != canonical:
            raise ValueError(
                "effect_egress_completeness_signals must use canonical unique order"
            )
        if (
            self.effect_egress_completeness_gate_passed
            and self.effect_egress_completeness_signals
        ):
            raise ValueError(
                "effect_egress_completeness_gate_passed cannot be true when "
                "effect_egress_completeness_signals is non-empty"
            )
        return self


def detector_input_from_egress(
    egress: EffectEgressReadResult,
    *,
    input_id: str,
    run_id: str = "",
    receipts: Sequence[SecurityReceipt] = (),
    receipt_source: str = "",
    receipt_coverage: ReceiptCoverage = "unknown",
    attributes: Mapping[str, JsonValue] | None = None,
    require_complete: bool = True,
) -> DetectorInput:
    """Build one detector input from collector-facing egress.

    By default this preserves the existing fail-closed handoff:
    :func:`~nooa.security.require_complete_effect_egress` raises
    :class:`~nooa.security.EffectEgressIncompleteError` when the read result
    carries a sequence discontinuity or truncated trailing frame. Set
    ``require_complete=False`` only when the downstream detector must receive
    those reader-visible diagnostics and decide its own policy.

    Malformed frames, unsupported versions, and collector budget refusals are
    raised by :func:`~nooa.security.read_effect_egress` before this helper can
    construct a bundle.
    """

    if not isinstance(egress, EffectEgressReadResult):
        raise TypeError(
            "detector_input_from_egress expected EffectEgressReadResult, "
            f"got {type(egress).__name__}"
        )
    if not isinstance(require_complete, bool):
        raise TypeError(
            "detector_input_from_egress expected bool require_complete, "
            f"got {type(require_complete).__name__}"
        )

    completeness_signals = effect_egress_completeness_signals(egress)
    try:
        effects = require_complete_effect_egress(egress)
    except EffectEgressIncompleteError:
        if require_complete:
            raise
        effects = egress.records

    return DetectorInput(
        input_id=input_id,
        run_id=run_id,
        effects=effects,
        effect_egress_completeness_signals=completeness_signals,
        effect_egress_completeness_gate_passed=not completeness_signals,
        receipts=tuple(receipts),
        receipt_source=receipt_source,
        receipt_coverage=receipt_coverage,
        attributes=dict(attributes or {}),
    )
