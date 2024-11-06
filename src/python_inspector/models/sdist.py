# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

from pathlib import Path

from pydantic import Field

from python_inspector.models.distribution import Distribution, InvalidDistributionFilenameError

EXTENSIONS_SDIST = (
    ".tar.gz",
    ".zip",
    ".tar.xz",
)
EXTENSIONS = EXTENSIONS_SDIST + (".whl",)


class Sdist(Distribution):
    extension: str = Field(
        default="",
        description="File extension, including leading dot.",
    )

    @classmethod
    def from_filename(cls, filename: str) -> Sdist:
        """
        Return a Sdist object built from a filename.
        Raise an exception if this is not a valid sdist filename
        """
        filename = Path(filename).as_posix()
        name_ver_ext = get_sdist_name_ver_ext(filename)
        if not name_ver_ext:
            raise InvalidDistributionFilenameError(filename)

        name, version, extension = name_ver_ext

        return cls(
            type="pypi",
            name=name,
            version=version,
            extension=extension,
            filename=filename,
        )

    def to_filename(self) -> str:
        """
        Return an sdist filename reconstructed from its fields (that may not be
        the same as the original filename.)
        """
        return f"{self.name}-{self.version}.{self.extension}"


def get_sdist_name_ver_ext(filename: str) -> tuple[str, str, str] | None:
    """
    Return a (name, version, extension) if filename is a valid sdist name.
    Return False otherwise.

    Note that some legacy binary builds have weird names. In particular some
    older sdists do not use PEP440 compliant versions and/or mix tags, os and
    arch names in tarball names and versions:

    >>> assert get_sdist_name_ver_ext("intbitset-1.3.tar.gz")
    >>> assert not get_sdist_name_ver_ext("intbitset-1.3.linux-x86_64.tar.gz")
    >>> assert get_sdist_name_ver_ext("intbitset-1.4a.tar.gz")
    >>> assert get_sdist_name_ver_ext("intbitset-1.4a.zip")
    >>> assert not get_sdist_name_ver_ext("intbitset-2.0.linux-x86_64.tar.gz")
    >>> assert get_sdist_name_ver_ext("intbitset-2.0.tar.gz")
    >>> assert not get_sdist_name_ver_ext("intbitset-2.1-1.src.rpm")
    >>> assert not get_sdist_name_ver_ext("intbitset-2.1-1.x86_64.rpm")
    >>> assert not get_sdist_name_ver_ext("intbitset-2.1.linux-x86_64.tar.gz")
    >>> assert not get_sdist_name_ver_ext("cffi-1.2.0-1.tar.gz")
    >>> assert not get_sdist_name_ver_ext("html5lib-1.0-reupload.tar.gz")
    >>> assert not get_sdist_name_ver_ext("selenium-2.0-dev-9429.tar.gz")
    >>> assert not get_sdist_name_ver_ext("testfixtures-1.8.0dev-r4464.tar.gz")
    """
    name_ver = None
    extension = None

    for ext in EXTENSIONS_SDIST:
        if filename.endswith(ext):
            name_ver, extension, _ = filename.rpartition(ext)
            break

    if not extension or not name_ver:
        return None

    name, _, version = name_ver.rpartition("-")

    if not name or not version:
        return None

    # weird version
    if any(
        w in version
        for w in (
            "x86_64",
            "i386",
        )
    ):
        return None

    # all char versions
    if version.isalpha():
        return None

    # non-pep 440 version
    if "-" in version:
        return None

    # single version
    if version.isdigit() and len(version) == 1:
        return None

    # r1 version
    if len(version) == 2 and version[0] == "r" and version[1].isdigit():
        return None

    # dotless version (but calver is OK)
    if "." not in version and len(version) < 3:
        return None

    # version with dashes selenium-2.0-dev-9429.tar.gz
    if name.endswith(("dev",)) and "." not in version:
        return None
    # version pre or post, old legacy
    if version.startswith(("beta", "rc", "pre", "post", "final")):
        return None

    return name, version, extension
