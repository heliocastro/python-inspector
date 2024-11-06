# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

import re
from typing import Any

from packvers.version import LegacyVersion, Version, parse
from pydantic import BaseModel, Field


class NameVer(BaseModel):
    name: str = Field(description="Python package name, lowercase and normalized.")
    version: str = Field(description="Python package version string.")

    @property
    def normalized_name(self) -> str:
        return NameVer.normalize_name(self.name)

    @staticmethod
    def normalize_name(name: str) -> str:
        """
        Return a normalized package name per PEP503, and copied from
        https://www.python.org/dev/peps/pep-0503/#id4
        """
        return name and re.sub(r"[-_.]+", "-", name).lower() or name

    def sortable_name_version(self) -> tuple[str, LegacyVersion | Version]:
        """
        Return a tuple of values to sort by name, then version.
        This method is a suitable to use as key for sorting NameVer instances.
        """
        return self.normalized_name, parse(self.version)

    @classmethod
    def sorted(cls, namevers: Any) -> Any:
        return sorted(namevers or [], key=cls.sortable_name_version)
