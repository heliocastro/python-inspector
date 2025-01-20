# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/python-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from __future__ import annotations

from typing import TYPE_CHECKING

import importlib_metadata as metadata

if TYPE_CHECKING:
    from collections.abc import Callable


# The metadata.version that we import for Python 3.7 is untyped, work around
# that.
version: Callable[[str], str] = metadata.version

try:
    __version__ = version("otto")
except metadata.PackageNotFoundError:
    # We are running from a git checkout, so we don't have metada
    from pathlib import Path

    import toml

    pyproject = toml.loads((Path(__file__).parent.parent.parent / "pyproject.toml").read_text())
    __version__ = pyproject["project"]["version"]
