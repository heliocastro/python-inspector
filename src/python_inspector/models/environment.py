# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

from packvers.tags import Tag
from pydantic import BaseModel, Field

from python_inspector.utils_pip_compatibility_tags import get_supported

"""
- An Environment is a combination of a Python version and operating system
    (e.g., platfiorm and ABI tags.) and is represented by the "tags" it supports.
"""


class Environment(BaseModel):
    """
    An Environment describes a target installation environment with its
    supported Python version, ABI, platform, implementation and related
    attributes.

    We can use these to pass as `pip download` options and force fetching only
    the subset of packages that match these Environment constraints as opposed
    to the current running Python interpreter constraints.
    """

    ABIS_BY_PYTHON_VERSION: dict[str, list[str]] = {
        "27": ["cp27", "cp27m"],
        "36": ["cp36", "cp36m", "abi3"],
        "37": ["cp37", "cp37m", "abi3"],
        "38": ["cp38", "cp38m", "abi3"],
        "39": ["cp39", "cp39m", "abi3"],
        "310": ["cp310", "cp310m", "abi3"],
        "311": ["cp311", "cp311m", "abi3"],
        "312": ["cp312", "cp312m", "abi3"],
    }

    PLATFORMS_BY_OS: dict[str, list[str]] = {
        "linux": [
            "linux_x86_64",
            "manylinux1_x86_64",
            "manylinux2010_x86_64",
            "manylinux2014_x86_64",
        ],
        "macos": [
            "macosx_10_6_intel",
            "macosx_10_6_x86_64",
            "macosx_10_9_intel",
            "macosx_10_9_x86_64",
            "macosx_10_10_intel",
            "macosx_10_10_x86_64",
            "macosx_10_11_intel",
            "macosx_10_11_x86_64",
            "macosx_10_12_intel",
            "macosx_10_12_x86_64",
            "macosx_10_13_intel",
            "macosx_10_13_x86_64",
            "macosx_10_14_intel",
            "macosx_10_14_x86_64",
            "macosx_10_15_intel",
            "macosx_10_15_x86_64",
            "macosx_11_0_x86_64",
            "macosx_11_intel",
            "macosx_11_0_x86_64",
            "macosx_11_intel",
            "macosx_10_9_universal2",
            "macosx_10_10_universal2",
            "macosx_10_11_universal2",
            "macosx_10_12_universal2",
            "macosx_10_13_universal2",
            "macosx_10_14_universal2",
            "macosx_10_15_universal2",
            "macosx_11_0_universal2",
            # 'macosx_11_0_arm64',
        ],
        "windows": [
            "win_amd64",
        ],
    }

    python_version: str = Field(
        default="",
        description="Python version supported by this environment.",
    )

    operating_system: str = Field(
        default="",
        description="operating system supported by this environment.",
    )

    implementation: str = Field(
        default="",
        description="Python implementation supported by this environment.",
    )

    abis: list[str] = Field(
        default_factory=list,
        description="List of ABI tags supported by this environment.",
    )

    platforms: list[str] = Field(
        default_factory=list,
        description="List of platform tags supported by this environment.",
    )

    @classmethod
    def from_pyver_and_os(cls, python_version: str, operating_system: str) -> Environment:
        if "." in python_version:
            python_version = "".join(python_version.split("."))

        return cls(
            python_version=python_version,
            implementation="cp",
            abis=cls.ABIS_BY_PYTHON_VERSION[python_version],
            platforms=cls.PLATFORMS_BY_OS[operating_system],
            operating_system=operating_system,
        )

    def get_pip_cli_options(self) -> list[str]:
        """
        Return a list of pip download command line options for this environment.
        """
        options = [
            "--python-version",
            self.python_version,
            "--implementation",
            self.implementation,
        ]
        for abi in self.abis:
            options.extend(["--abi", abi])

        for platform in self.platforms:
            options.extend(["--platform", platform])

        return options

    def tags(self) -> set[Tag]:
        """
        Return a set of all the PEP425 tags supported by this environment.
        """
        return set(
            get_supported(
                version=self.python_version or None,
                impl=self.implementation or None,
                platforms=self.platforms or None,
                abis=self.abis or None,
            ),
        )
