# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared example-local detector policy errors."""

from typing import Literal

ReceiptAdmissionRefusal = Literal[
    "duplicate_receipt_id",
    "receipt_source_mismatch",
    "scope_drift",
]


class UnscoreableDetectorInputError(ValueError):
    """Raised when one example detector policy refuses an input bundle."""

    def __init__(
        self,
        message: str,
        *,
        receipt_admission_refusal: ReceiptAdmissionRefusal | None = None,
    ) -> None:
        super().__init__(message)
        self.receipt_admission_refusal: ReceiptAdmissionRefusal | None = (
            receipt_admission_refusal
        )
