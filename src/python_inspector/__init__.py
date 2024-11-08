#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/scancode-toolkit for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from __future__ import annotations

import logging as __logging
import os
from typing import Any

from rich.logging import RichHandler

from python_inspector.core.settings import Settings


class CustomRichHandler(RichHandler):
    def emit(self, record: __logging.LogRecord) -> None:
        record.msg = f"[wheat1]({record.funcName})[/wheat1]\n{record.msg}"
        super().emit(record)


# Create custom trace level
TRACE = 5
__logging.addLevelName(TRACE, "TRACE")

# Setup the main logger message
__logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        CustomRichHandler(
            markup=True,
            rich_tracebacks=True,
        )
        if "PYTHON_INSPECTOR_DEBUG" in os.environ or "PYTHON_INSPECTOR_TRACE" in os.environ
        else RichHandler(markup=True, show_path=False),
    ],
)


def trace(self: Any, message: str, *args: Any, **kwargs: Any) -> None:
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


# Global logger
logging = __logging.getLogger("rich")

# Initialize global settings
settings = Settings()
