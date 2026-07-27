# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared example-local detector policy errors."""


class UnscoreableDetectorInputError(ValueError):
    """Raised when one example detector policy refuses an input bundle."""
