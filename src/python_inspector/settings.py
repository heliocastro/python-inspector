#!/usr/bin/env python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/python-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Reference: https://docs.pydantic.dev/latest/concepts/pydantic_settings/


class TraceLevel(int, Enum):
    TRACE = 1
    TRACE_DEEP = 2
    TRACE_ULTRA_DEEP = 3


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="PYTHON_INSPECTOR_",
        case_sensitive=True,
        extra="allow",
    )
    DEFAULT_PYTHON_VERSION: str = "38"
    INDEX_URL: str = "https://pypi.org/simple"
    EXTRA_INDEX_URLS: list[str] | None = None
    TRACE: TraceLevel | None = None
    CACHE_THIRDPARTY_DIR: Path = Path.home() / ".cache/python_inspector"
