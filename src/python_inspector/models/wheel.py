# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/scancode-toolkit for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from __future__ import annotations

import re
from pathlib import Path

from packvers.tags import Tag
from pydantic import Field

from python_inspector import settings
from python_inspector.models.distribution import Distribution, InvalidDistributionFilenameError
from python_inspector.core.settings import TraceLevel

"""
- A Wheel binary Distribution can have Python/Platform/OS tags it supports and
    was built for and these tags can be matched to an Environment.

The Wheel models code is partially derived from the mit-licensed pip and the
Distribution/Wheel/Sdist design has been heavily inspired by the packaging-
dists library https://github.com/uranusjr/packaging-dists by Tzu-ping Chung
"""

"""
Wheel downloader

- parse requirement file
- create a TODO queue of requirements to process
- done: create an empty map of processed binary requirements as {package name: (list of versions/tags}


- while we have package reqs in TODO queue, process one requirement:
    - for each PyPI simple index:
        - fetch through cache the PyPI simple index for this package
        - for each environment:
            - find a wheel matching pinned requirement in this index
            - if file exist locally, continue
            - fetch the wheel for env
                - IF pure, break, no more needed for env
            - collect requirement deps from wheel metadata and add to queue
    - if fetched, break, otherwise display error message


"""


class Wheel(Distribution):
    """
    Represents a wheel file.

    Copied and heavily modified from pip-20.3.1 copied from pip-20.3.1
    pip/_internal/models/wheel.py

    name: wheel
    version: 20.3.1
    download_url: https://github.com/pypa/pip/blob/20.3.1/src/pip/_internal/models/wheel.py
    copyright: Copyright (c) 2008-2020 The pip developers (see AUTHORS.txt file)
    license_expression: mit
    notes: copied from pip-20.3.1 pip/_internal/models/wheel.py

    Copyright (c) 2008-2020 The pip developers (see AUTHORS.txt file)

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    """

    get_wheel_from_filename = re.compile(
        r"""^(?P<namever>(?P<name>.+?)-(?P<ver>.*?))
        ((-(?P<build>\d[^-]*?))?-(?P<pyvers>.+?)-(?P<abis>.+?)-(?P<plats>.+?)
        \.whl)$""",
        re.VERBOSE,
    ).match

    build: str = Field(
        default="",
        description="Python wheel build.",
    )

    python_versions: list[str] = Field(
        default_factory=list,
        description="List of wheel Python version tags.",
    )

    abis: list[str] = Field(
        default_factory=list,
        description="List of wheel ABI tags.",
    )

    platforms: list[str] = Field(
        default_factory=list,
        description="List of wheel platform tags.",
    )

    tags: set[Tag] = Field(
        default_factory=set,
        description="Set of all tags for this wheel.",
    )

    @classmethod
    def from_filename(cls, filename: str) -> Wheel:
        """
        Return a wheel object built from a filename.
        Raise an exception if this is not a valid wheel filename
        """
        filename = Path(filename).as_posix()
        wheel_info = cls.get_wheel_from_filename(filename)
        if not wheel_info:
            raise InvalidDistributionFilenameError(filename)

        name = wheel_info.group("name").replace("_", "-")
        # we'll assume "_" means "-" due to wheel naming scheme
        # (https://github.com/pypa/pip/issues/1150)
        version = wheel_info.group("ver").replace("_", "-")
        build = wheel_info.group("build")
        python_versions = wheel_info.group("pyvers").split(".")
        abis = wheel_info.group("abis").split(".")
        platforms = wheel_info.group("plats").split(".")

        # All the tag combinations from this file
        tags = {Tag(x, y, z) for x in python_versions for y in abis for z in platforms}

        return cls(
            filename=filename,
            type="pypi",
            name=name,
            version=version,
            build=build,
            python_versions=python_versions,
            abis=abis,
            platforms=platforms,
            tags=tags,
        )

    def is_supported_by_tags(self, tags: set[Tag]) -> bool:
        """
        Return True is this wheel is compatible with one of a list of PEP 425 tags.
        """
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print()
            print("is_supported_by_tags: tags:", tags)
            print("self.tags:", self.tags)
        return not self.tags.isdisjoint(tags)

    def to_filename(self) -> str:
        """
        Return a wheel filename reconstructed from its fields (that may not be
        the same as the original filename.)
        """
        build = f"-{self.build}" if self.build else ""
        pyvers = ".".join(self.python_versions)
        abis = ".".join(self.abis)
        plats = ".".join(self.platforms)
        return f"{self.name}-{self.version}{build}-{pyvers}-{abis}-{plats}.whl"

    def is_pure(self) -> bool:
        """
        Return True if wheel `filename` is for a "pure" wheel e.g. a wheel that
        runs on all Pythons 3 and all OSes.

        For example::

        >>> Wheel.from_filename('aboutcode_toolkit-5.1.0-py2.py3-none-any.whl').is_pure()
        True
        >>> Wheel.from_filename('beautifulsoup4-4.7.1-py3-none-any.whl').is_pure()
        True
        >>> Wheel.from_filename('beautifulsoup4-4.7.1-py2-none-any.whl').is_pure()
        False
        >>> Wheel.from_filename('bitarray-0.8.1-cp36-cp36m-win_amd64.whl').is_pure()
        False
        >>> Wheel.from_filename('extractcode_7z-16.5-py2.py3-none-macosx_10_13_intel.whl').is_pure()
        False
        >>> Wheel.from_filename('future-0.16.0-cp36-none-any.whl').is_pure()
        False
        >>> Wheel.from_filename('foo-4.7.1-py3-none-macosx_10_13_intel.whl').is_pure()
        False
        >>> Wheel.from_filename('future-0.16.0-py3-cp36m-any.whl').is_pure()
        False
        """
        return "py3" in self.python_versions and "none" in self.abis and "any" in self.platforms
