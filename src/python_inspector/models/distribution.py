# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

import email
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Type  # noqa: UP035

import packageurl
from commoncode import fileutils
from commoncode.hash import multi_checksums
from pydantic import Field
from requests.auth import HTTPBasicAuth

from python_inspector import settings
from python_inspector.models import Cache, Link, NameVer
from python_inspector.models.pypisimplerepository import PypiSimpleRepository, get_default_repo
from python_inspector.models.sdist import Sdist
from python_inspector.models.wheel import Wheel
from python_inspector.core.settings import TraceLevel

"""
- A Distribution (either a Wheel or Sdist) is identified by and created from its
    filename as well as its name and version.
    A Distribution is fetched from a Repository.
"""


class InvalidDistributionFilenameError(Exception):
    pass


class DistributionNotFoundError(Exception):
    pass


class Distribution(NameVer):
    """
    A Distribution is either either a Wheel or Sdist and is identified by and
    created from its filename as well as its name and version. A Distribution is
    fetched from a PyPIRepository.
    """

    # field names that can be updated from another Distribution or mapping
    updatable_fields = [
        "license_expression",
        "copyright",
        "description",
        "homepage_url",
        "primary_language",
        "notice_text",
        "extra_data",
    ]

    filename: str = Field(
        default="",
        description="File name.",
    )

    path_or_url: str = Field(
        default="",
        description="Path or URL",
    )

    sha256: str = Field(
        default="",
        description="SHA256 checksum.",
    )

    sha: str = Field(
        default="",
        description="SHA1 checksum.",
    )

    md5: int = Field(
        default=0,
        description="MD5 checksum.",
    )

    type: str = Field(
        default="pypi",
        description="Package type",
    )

    namespace: str = Field(
        default="",
        description="Package URL namespace",
    )

    qualifiers: dict[str, Any] = Field(
        default_factory=dict,
        description="Package URL qualifiers",
    )

    subpath: str = Field(
        default="",
        description="Package URL subpath",
    )

    size: str = Field(
        default="",
        description="Size in bytes.",
    )

    primary_language: str = Field(
        default="Python",
        description="Primary Programming language.",
    )

    description: str = Field(
        default="",
        description="Description.",
    )

    homepage_url: str = Field(
        default="",
        description="Homepage URL",
    )

    notes: str = Field(
        default="",
        description="Notes.",
    )

    copyright: str = Field(
        default="",
        description="Copyright.",
    )

    license_expression: str = Field(
        default="",
        description="License expression",
    )

    licenses: list[str] = Field(
        default_factory=list,
        description="List of license mappings.",
    )

    notice_text: str = Field(
        default="",
        description="Notice text",
    )

    extra_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Extra data",
    )

    credentials: HTTPBasicAuth | None = Field(
        default=None,
    )

    python_requires: str = Field(
        default="",
        description="Python 'specifier' required by this distribution.",
    )

    @property
    def package_url(self) -> str:
        """
        Return a Package URL string of self.
        """
        return str(
            packageurl.PackageURL(
                type=self.type,
                namespace=self.namespace,
                name=self.name,
                version=self.version,
                subpath=self.subpath,
                qualifiers=self.qualifiers,
            ),
        )

    @property
    def download_url(self) -> str | None:
        return self.get_best_download_url()

    def get_best_download_url(self, repos: tuple[PypiSimpleRepository] | None = None) -> str:
        """
        Return the best download URL for this distribution where best means this
        is the first URL found for this distribution found in the list of
        ``repos``.

        If none is found, return a synthetic PyPI remote URL.
        """

        if not repos:
            repos = get_default_repo()

        for repo in repos:
            package = repo.get_package_version(name=self.name, version=self.version)
            if not package:
                if settings.TRACE == TraceLevel.TRACE:
                    print(f"     get_best_download_url: {self.name}=={self.version} " f"not found in {repo.index_url}")
                continue
            pypi_url = package.get_url_for_filename(self.filename)
            if pypi_url:
                return pypi_url
            else:
                if settings.TRACE == TraceLevel.TRACE:
                    print(f"     get_best_download_url: {self.filename} not found in {repo.index_url}")
        return ""

    def download(
        self,
        verbose: bool = False,
        echo_func: Callable[[str], None] | None = None,
    ) -> str:
        """
        Download this distribution into `dest_dir` directory.
        Return the fetched filename.
        """
        if not self.filename:
            raise ValueError("No valid filename found !")
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(
                f"Fetching distribution of {self.name}=={self.version}:",
                self.filename,
            )

        as_text: bool = False

        content = Cache().get(
            path_or_url=self.path_or_url,
            credentials=self.credentials,
            as_text=as_text,
            verbose=verbose,
            echo_func=echo_func,
        )
        output = settings.CACHE_THIRDPARTY_DIR / self.filename
        wmode = "w" if as_text else "wb"
        with output.open(wmode) as fo:
            fo.write(content)

        return self.filename

    @classmethod
    def from_link(cls, link: Link) -> Sdist | Wheel:
        """
        Return a distribution built from the data found in the filename of a
        ``path_or_url`` string. Raise an exception if this is not a valid
        filename.
        """
        requires_python = link.python_requires
        path_or_url = link.url
        dist: Sdist | Wheel = cls.from_filename(Path(path_or_url).name)
        dist.path_or_url = path_or_url
        dist.python_requires = requires_python
        return dist

    @classmethod
    def get_dist_class(cls, filename: str) -> Type[Sdist] | Type[Wheel]:  # noqa: UP006
        if filename.endswith(".whl"):
            return Wheel
        elif filename.endswith(
            (
                ".zip",
                ".tar.gz",
            ),
        ):
            return Sdist
        raise InvalidDistributionFilenameError(filename)

    @classmethod
    def from_filename(cls, filename: str) -> Sdist | Wheel:
        """
        Return a distribution built from the data found in a `filename` string.
        Raise an exception if this is not a valid filename
        """
        clazz: type[Wheel | Sdist] = cls.get_dist_class(filename)
        return clazz.from_filename(filename)

    def to_dict(self) -> dict[str, Any]:
        """
        Return a mapping data from this distribution.
        """
        return {k: v for k, v in self.model_dump().items() if v}

    def get_checksums(self) -> Any:
        """
        Return a mapping of computed checksums for this dist filename is
        `dest_dir`.
        """
        dist_loc: Path = settings.CACHE_THIRDPARTY_DIR / self.filename
        if dist_loc.exists():
            return multi_checksums(dist_loc.as_posix(), checksum_names=("md5", "sha1", "sha256"))
        else:
            return {}

    def set_checksums(self) -> bool | None:
        """
        Update self with checksums computed for this dist filename is `dest_dir`.
        """
        return self.update(self.get_checksums(), overwrite=True)

    def validate_checksums(self) -> bool:
        """
        Return True if all checksums that have a value in this dist match
        checksums computed for this dist filename is `dest_dir`.
        """
        real_checksums = self.get_checksums()
        for csk in ("md5", "sha1", "sha256"):
            csv = getattr(self, csk)
            rcv = real_checksums.get(csk)
            if csv and rcv and csv != rcv:
                return False
        return True

    def extract_pkginfo(self) -> str | None:
        """
        Return the text of the first PKG-INFO or METADATA file found in the
        archive of this Distribution in `dest_dir`. Return None if not found.
        """

        fn = self.filename
        if fn.endswith(".whl"):
            fmt = "zip"
        elif fn.endswith(".tar.gz"):
            fmt = "gztar"
        else:
            fmt = None

        dist: Path = settings.CACHE_THIRDPARTY_DIR / fn
        with tempfile.TemporaryDirectory(prefix=f"pypi-tmp-extract-{fn}") as td:
            shutil.unpack_archive(filename=dist, extract_dir=td, format=fmt)
            # NOTE: we only care about the first one found in the dist
            # which may not be 100% right
            for pi in fileutils.resource_iter(location=td, with_dirs=False):
                if pi.endswith(
                    (
                        "PKG-INFO",
                        "METADATA",
                    ),
                ):
                    with Path(pi).open() as fp:
                        return fp.read()
        return None

    def load_pkginfo_data(self) -> bool | None:
        """
        Update self with data loaded from the PKG-INFO file found in the
        archive of this Distribution in `dest_dir`.
        """
        pkginfo_text = self.extract_pkginfo()
        if not pkginfo_text:
            print(f"!!!!PKG-INFO/METADATA not found in {self.filename}")
            return None
        raw_data = email.message_from_string(pkginfo_text)

        classifiers = raw_data.get_all("Classifier") or []

        declared_license = [raw_data["License"]] + [c for c in classifiers if c.startswith("License")]
        other_classifiers = [c for c in classifiers if not c.startswith("License")]

        holder = raw_data["Author"]
        holder_contact = raw_data["Author-email"]
        copyright_statement = f"Copyright (c) {holder} <{holder_contact}>"

        pkginfo_data = {
            "name": raw_data["Name"],
            "declared_license": declared_license,
            "version": raw_data["Version"],
            "description": raw_data["Summary"],
            "homepage_url": raw_data["Home-page"],
            "copyright": copyright_statement,
            "holder": holder,
            "holder_contact": holder_contact,
            "keywords": raw_data["Keywords"],
            "classifiers": other_classifiers,
        }

        return self.update(pkginfo_data, keep_extra=True)

    def update_from_other_dist(self, dist: Sdist | Wheel) -> bool:
        """
        Update self using data from another dist
        """
        return self.update(dist.get_updatable_data())

    def get_updatable_data(self, data: dict[str, Any] | None = None) -> dict[str, Any]:
        data = data or self.model_dump()
        return {k: v for k, v in data.items() if v and k in self.updatable_fields}

    def update(self, data: dict[str, Any], overwrite: bool = False, keep_extra: bool = True) -> bool:
        """
        Update self with a mapping of `data`. Keep unknown data as extra_data if
        `keep_extra` is True. If `overwrite` is True, overwrite self with `data`
        Return True if any data was updated, False otherwise. Raise an exception
        if there are key data conflicts.
        """
        package_url = data.get("package_url")
        if package_url:
            purl_from_data = packageurl.PackageURL.from_string(package_url)
            purl_from_self = packageurl.PackageURL.from_string(self.package_url)
            if purl_from_data != purl_from_self:
                print(f"Invalid dist update attempt, no same same purl with dist: " f"{self} using data {data}.")
                return False

        data.pop("about_resource", None)
        dl = data.pop("download_url", None)
        if dl:
            data["path_or_url"] = dl

        updated = False
        extra = {}
        for k, v in data.items():
            if isinstance(v, str):
                v = v.strip()
            if not v:
                continue

            if hasattr(self, k):
                value = getattr(self, k, None)
                if not value or (overwrite and value != v):
                    try:
                        setattr(self, k, v)
                    except Exception as e:
                        raise Exception(f"{self}, {k}, {v}") from e
                    updated = True

            elif keep_extra:
                # note that we always overwrite extra
                extra[k] = v
                updated = True

        self.extra_data.update(extra)

        return updated
