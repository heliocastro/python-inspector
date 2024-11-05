#!/usr/bin/env python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from __future__ import annotations

import email
import hashlib
import itertools
import os
import re
import shutil
import tempfile
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import quote_plus, unquote, urlparse, urlunparse

import attr
import packageurl
import requests
from bs4 import BeautifulSoup
from commoncode import fileutils
from commoncode.hash import multi_checksums
from packvers import tags as packaging_tags
from packvers import version as packaging_version
from packvers.specifiers import SpecifierSet
from requests.auth import HTTPBasicAuth
from tenacity import retry, stop_after_attempt, wait_fixed

from python_inspector import settings, utils_pip_compatibility_tags
from python_inspector.settings import TraceLevel

"""
Utilities to manage Python thirparty libraries source, binaries and metadata in
requirements and remote repositories.


Approach
--------

The processing is organized around these key objects:

- A PyPiPackage represents a PyPI package with its name, version and metadata.
  It contains the downloadable Distribution objects for that version:

  - one Sdist source Distribution
  - a list of Wheel binary Distribution(s)

- A Distribution (either a Wheel or Sdist) is identified by and created from its
  filename as well as its name and version.
  A Distribution is fetched from a Repository.

- A Wheel binary Distribution can have Python/Platform/OS tags it supports and
  was built for and these tags can be matched to an Environment.

- An Environment is a combination of a Python version and operating system
  (e.g., platfiorm and ABI tags.) and is represented by the "tags" it supports.

- A PypiSimpleRepository is a PyPI "simple" index where a HTML page is listing
  package name links. Each such link points to an HTML page listing URLs to all
  wheels and sdsist of all versions of this package.

PypiSimpleRepository and Packages are related through packages name, version and
filenames.

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

# Supported environments
PYTHON_VERSIONS = "27", "36", "37", "38", "39", "310", "311", "312"

PYTHON_DOT_VERSIONS_BY_VER = {
    "27": "2.7",
    "36": "3.6",
    "37": "3.7",
    "38": "3.8",
    "39": "3.9",
    "310": "3.10",
    "311": "3.11",
    "312": "3.12",
}

valid_python_versions = list(PYTHON_DOT_VERSIONS_BY_VER.keys())
valid_python_versions.extend([dot_ver for pyver, dot_ver in PYTHON_DOT_VERSIONS_BY_VER.items()])


def get_python_dot_version(version: str) -> str:
    """
    Return a dot version from a plain, non-dot version.
    """
    return PYTHON_DOT_VERSIONS_BY_VER[version]


ABIS_BY_PYTHON_VERSION = {
    "27": ["cp27", "cp27m"],
    "36": ["cp36", "cp36m", "abi3"],
    "37": ["cp37", "cp37m", "abi3"],
    "38": ["cp38", "cp38m", "abi3"],
    "39": ["cp39", "cp39m", "abi3"],
    "310": ["cp310", "cp310m", "abi3"],
    "311": ["cp311", "cp311m", "abi3"],
    "312": ["cp312", "cp312m", "abi3"],
}

PLATFORMS_BY_OS = {
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


PYPI_INDEX_URLS = settings.INDEX_URL

################################################################################

EXTENSIONS_SDIST = (
    ".tar.gz",
    ".zip",
    ".tar.xz",
)
EXTENSIONS = EXTENSIONS_SDIST + (".whl",)

collect_urls = re.compile('href="([^"]+)"').findall

################################################################################
# Fetch wheels and sources locally
################################################################################


class DistributionNotFound(Exception):  # noqa: N818
    pass


def download_wheel(
    name: str,
    version: str,
    environment: str,
    repos: tuple[str] = tuple(),
    verbose: bool = False,
    echo_func: Callable[[str], None] | None = None,
    python_version: str = settings.DEFAULT_PYTHON_VERSION,
) -> list[str]:
    """
    Download the wheels binary distribution(s) of package ``name`` and
    ``version`` matching the ``environment`` Environment constraints into the
    ``dest_dir`` directory. Return a list of fetched_wheel_filenames, possibly
    empty.

    Use the first PyPI simple repository from a list of ``repos`` that contains this wheel.
    """
    if settings.TRACE == TraceLevel.TRACE:
        print(f"  download_wheel: {name}=={version} for envt: {environment}")

    if not repos:
        repos = DEFAULT_PYPI_REPOS

    fetched_wheel_filenames: list[str] = []
    for repo in repos:
        supported_and_valid_wheels = get_supported_and_valid_wheels(repo, name, version, environment, python_version)
        if not supported_and_valid_wheels:
            if settings.TRACE == TraceLevel.TRACE_DEEP:
                print(f"    download_wheel: No supported and valid wheel for {name}=={version}: {environment} ")
            continue
        for wheel in supported_and_valid_wheels:
            fetched_wheel_filename = wheel.download(
                verbose=verbose,
                echo_func=echo_func,
            )
            fetched_wheel_filenames.append(fetched_wheel_filename)

        if fetched_wheel_filenames:
            # do not futher fetch from other repos if we find in first, typically PyPI
            break
    return fetched_wheel_filenames


def get_valid_sdist(
    repo: PypiSimpleRepository,
    name: str,
    version: str,
    python_version: str = settings.DEFAULT_PYTHON_VERSION,
) -> None | PypiPackage:
    package = repo.get_package_version(name=name, version=version)
    if not package:
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(print(f"    get_valid_sdist: No package in {repo.index_url} for {name}=={version}"))
        return None

    if not isinstance(package, PypiPackage):
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"    get_valid_sdist: No sdist for {name}=={version}")
        return None
    sdist = package.sdist
    if not valid_python_version(python_requires=sdist.python_requires, python_version=python_version):
        return None
    if settings.TRACE == TraceLevel.TRACE_DEEP:
        print(f"    get_valid_sdist: Getting sdist from index (or cache): {sdist.download_url}")
    return sdist


def get_supported_and_valid_wheels(
    repo,
    name,
    version,
    environment,
    python_version=settings.DEFAULT_PYTHON_VERSION,
) -> list:
    """
    Return a list of wheels matching the ``environment`` Environment constraints.
    """
    package = repo.get_package_version(name=name, version=version)
    if not package:
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"    get_supported_and_valid_wheels: No package in {repo.index_url} for {name}=={version}")
        return []
    supported_wheels = list(package.get_supported_wheels(environment=environment))
    if not supported_wheels:
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"    get_supported_and_valid_wheels: No supported wheel for {name}=={version}: {environment}")
        return []
    wheels = []
    for wheel in supported_wheels:
        if not valid_python_version(python_requires=wheel.python_requires, python_version=python_version):
            continue
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(
                f"""    get_supported_and_valid_wheels: Getting wheel from index (or cache):
                {wheel.download_url}""",
            )
        wheels.append(wheel)
    return wheels


def valid_python_version(python_version, python_requires):
    """
    Return True if ``python_version`` is in the ``python_requires``.
    """
    if not python_requires:
        return True
    return python_version in SpecifierSet(python_requires)


def download_sdist(
    name: str,
    version: str,
    dest_dir: Path = settings.CACHE_THIRDPARTY_DIR,
    repos: tuple = tuple(),
    verbose: bool = False,
    echo_func: Callable[[str], None] | None = None,
    python_version: str = settings.DEFAULT_PYTHON_VERSION,
) -> None:
    """
    Download the sdist source distribution of package ``name`` and ``version``
    into the ``dest_dir`` directory. Return a fetched filename or None.

    Use the first PyPI simple repository from a list of ``repos`` that contains
    this sdist.
    """
    if settings.TRACE == TraceLevel.TRACE_DEEP:
        print(f"  download_sdist: {name}=={version}")

    if not repos:
        repos = DEFAULT_PYPI_REPOS

    fetched_sdist_filename = None

    for repo in repos:
        sdist = get_valid_sdist(repo, name, version, python_version=python_version)
        if not sdist:
            if settings.TRACE == TraceLevel.TRACE_DEEP:
                print(f"    download_sdist: No valid sdist for {name}=={version}")
            continue
        fetched_sdist_filename = sdist.download(
            dest_dir=dest_dir,
            verbose=verbose,
            echo_func=echo_func,
        )

        if fetched_sdist_filename:
            # do not futher fetch from other repos if we find in first, typically PyPI
            break

    return fetched_sdist_filename


################################################################################
#
# Core models
#
################################################################################


@attr.attributes
class NameVer:
    name = attr.ib(
        type=str,
        metadata=dict(help="Python package name, lowercase and normalized."),
    )

    version = attr.ib(
        type=str,
        metadata=dict(help="Python package version string."),
    )

    @property
    def normalized_name(self):
        return NameVer.normalize_name(self.name)

    @staticmethod
    def normalize_name(name):
        """
        Return a normalized package name per PEP503, and copied from
        https://www.python.org/dev/peps/pep-0503/#id4
        """
        return name and re.sub(r"[-_.]+", "-", name).lower() or name

    def sortable_name_version(self):
        """
        Return a tuple of values to sort by name, then version.
        This method is a suitable to use as key for sorting NameVer instances.
        """
        return self.normalized_name, packaging_version.parse(self.version)

    @classmethod
    def sorted(cls, namevers):
        return sorted(namevers or [], key=cls.sortable_name_version)


class Link(NamedTuple):
    """
    A link to a sdist/wheel on PyPI.
    """

    url: str
    python_requires: str


@attr.attributes
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

    filename: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "File name."},
    )

    path_or_url: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Path or URL"},
    )

    sha256: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "SHA256 checksum."},
    )

    sha: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "SHA1 checksum."},
    )

    md5: int = attr.ib(
        repr=False,
        default=0,
        metadata={"help": "MD5 checksum."},
    )

    type: str = attr.ib(
        repr=False,
        default="pypi",
        metadata={"help": "Package type"},
    )

    namespace: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Package URL namespace"},
    )

    qualifiers: dict = attr.ib(
        repr=False,
        default=attr.Factory(dict),
        metadata={"help": "Package URL qualifiers"},
    )

    subpath: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Package URL subpath"},
    )

    size: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Size in bytes."},
    )

    primary_language: str = attr.ib(
        repr=False,
        default="Python",
        metadata={"help": "Primary Programming language."},
    )

    description: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Description."},
    )

    homepage_url: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Homepage URL"},
    )

    notes: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Notes."},
    )

    copyright: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Copyright."},
    )

    license_expression: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "License expression"},
    )

    licenses: list[str] = attr.ib(
        repr=False,
        default=attr.Factory(list),
        metadata={"help": "List of license mappings."},
    )

    notice_text: str = attr.ib(
        repr=False,
        default="",
        metadata={"help": "Notice text"},
    )

    extra_data: dict = attr.ib(
        repr=False,
        default=attr.Factory(dict),
        metadata={"help": "Extra data"},
    )

    credentials: HTTPBasicAuth | None = attr.ib(
        default=None,
    )

    python_requires: str = attr.ib(
        default="",
        metadata={"help": "Python 'specifier' required by this distribution."},
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

    def get_best_download_url(self, repos: tuple = tuple()) -> str:
        """
        Return the best download URL for this distribution where best means this
        is the first URL found for this distribution found in the list of
        ``repos``.

        If none is found, return a synthetic PyPI remote URL.
        """

        if not repos:
            repos = DEFAULT_PYPI_REPOS

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

        # FIXME:
        fetch_and_save(
            path_or_url=self.path_or_url,
            credentials=self.credentials,
            filename=self.filename,
            as_text=False,
            verbose=verbose,
            echo_func=echo_func,
            dest_dir=settings.CACHE_THIRDPARTY_DIR.as_posix(),
        )
        return self.filename

    @classmethod
    def from_link(cls, link: Link):
        """
        Return a distribution built from the data found in the filename of a
        ``path_or_url`` string. Raise an exception if this is not a valid
        filename.
        """
        requires_python = link.python_requires
        path_or_url = link.url
        filename = os.path.basename(path_or_url.strip("/"))
        dist = cls.from_filename(filename)
        dist.path_or_url = path_or_url
        dist.python_requires = requires_python
        return dist

    @classmethod
    def get_dist_class(cls, filename):
        if filename.endswith(".whl"):
            return Wheel
        elif filename.endswith(
            (
                ".zip",
                ".tar.gz",
            ),
        ):
            return Sdist
        raise InvalidDistributionFilename(filename)

    @classmethod
    def from_filename(cls, filename):
        """
        Return a distribution built from the data found in a `filename` string.
        Raise an exception if this is not a valid filename
        """
        clazz = cls.get_dist_class(filename)
        return clazz.from_filename(filename)

    def to_dict(self):
        """
        Return a mapping data from this distribution.
        """
        return {k: v for k, v in attr.asdict(self).items() if v}

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
                    with open(pi) as fi:
                        return fi.read()
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

    def update_from_other_dist(self, dist):
        """
        Update self using data from another dist
        """
        return self.update(dist.get_updatable_data())

    def get_updatable_data(self, data=None):
        data = data or self.to_dict()
        return {k: v for k, v in data.items() if v and k in self.updatable_fields}

    def update(self, data, overwrite=False, keep_extra=True):
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
                return

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


class InvalidDistributionFilename(Exception):  # noqa: N818
    pass


def get_sdist_name_ver_ext(filename):
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
        return False

    name, _, version = name_ver.rpartition("-")

    if not name or not version:
        return False

    # weird version
    if any(
        w in version
        for w in (
            "x86_64",
            "i386",
        )
    ):
        return False

    # all char versions
    if version.isalpha():
        return False

    # non-pep 440 version
    if "-" in version:
        return False

    # single version
    if version.isdigit() and len(version) == 1:
        return False

    # r1 version
    if len(version) == 2 and version[0] == "r" and version[1].isdigit():
        return False

    # dotless version (but calver is OK)
    if "." not in version and len(version) < 3:
        return False

    # version with dashes selenium-2.0-dev-9429.tar.gz
    if name.endswith(("dev",)) and "." not in version:
        return False
    # version pre or post, old legacy
    if version.startswith(("beta", "rc", "pre", "post", "final")):
        return False

    return name, version, extension


def get_filename(filename):
    """
    Return a filename from a ``filename`` path or name string. Unquote as needed.
    """
    filename = filename.strip("/")
    filename = os.path.basename(filename)
    return unquote(filename)


@attr.attributes
class Sdist(Distribution):
    extension: str = attr.ib(
        repr=False,
        default="",
        metadata=dict(help="File extension, including leading dot."),
    )

    @classmethod
    def from_filename(cls, filename):
        """
        Return a Sdist object built from a filename.
        Raise an exception if this is not a valid sdist filename
        """
        filename = get_filename(filename)
        name_ver_ext = get_sdist_name_ver_ext(filename)
        if not name_ver_ext:
            raise InvalidDistributionFilename(filename)

        name, version, extension = name_ver_ext

        return cls(
            type="pypi",
            name=name,
            version=version,
            extension=extension,
            filename=filename,
        )

    def to_filename(self):
        """
        Return an sdist filename reconstructed from its fields (that may not be
        the same as the original filename.)
        """
        return f"{self.name}-{self.version}.{self.extension}"


@attr.attributes
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

    build: str = attr.ib(
        default="",
        metadata={"help": "Python wheel build."},
    )

    python_versions: list[str] = attr.ib(
        default=attr.Factory(list),
        metadata={"help": "List of wheel Python version tags."},
    )

    abis: list[str] = attr.ib(
        default=attr.Factory(list),
        metadata={"help": "List of wheel ABI tags."},
    )

    platforms: list[str] = attr.ib(
        default=attr.Factory(list),
        metadata={"help": "List of wheel platform tags."},
    )

    tags: set = attr.ib(
        repr=False,
        default=attr.Factory(set),
        metadata={"help": "Set of all tags for this wheel."},
    )

    @classmethod
    def from_filename(cls, filename: str) -> Wheel:
        """
        Return a wheel object built from a filename.
        Raise an exception if this is not a valid wheel filename
        """
        filename = get_filename(filename)
        wheel_info = cls.get_wheel_from_filename(filename)
        if not wheel_info:
            raise InvalidDistributionFilename(filename)

        name = wheel_info.group("name").replace("_", "-")
        # we'll assume "_" means "-" due to wheel naming scheme
        # (https://github.com/pypa/pip/issues/1150)
        version = wheel_info.group("ver").replace("_", "-")
        build = wheel_info.group("build")
        python_versions = wheel_info.group("pyvers").split(".")
        abis = wheel_info.group("abis").split(".")
        platforms = wheel_info.group("plats").split(".")

        # All the tag combinations from this file
        tags = {packaging_tags.Tag(x, y, z) for x in python_versions for y in abis for z in platforms}

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

    def is_supported_by_tags(self, tags: dict[str, None]) -> bool:
        """
        Return True is this wheel is compatible with one of a list of PEP 425 tags.
        """
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print()
            print("is_supported_by_tags: tags:", tags)
            print("self.tags:", self.tags)
        return not self.tags.isdisjoint(tags)

    def to_filename(self):
        """
        Return a wheel filename reconstructed from its fields (that may not be
        the same as the original filename.)
        """
        build = f"-{self.build}" if self.build else ""
        pyvers = ".".join(self.python_versions)
        abis = ".".join(self.abis)
        plats = ".".join(self.platforms)
        return f"{self.name}-{self.version}{build}-{pyvers}-{abis}-{plats}.whl"

    def is_pure(self):
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


def is_pure_wheel(filename: str) -> bool:
    try:
        return Wheel.from_filename(filename).is_pure()
    except Exception:
        return False


@attr.attributes
class PypiPackage(NameVer):
    """
    A Python package contains one or more wheels and one source distribution
    from a repository.
    """

    sdist: Sdist = attr.ib(
        repr=False,
        default=None,
        metadata={"help": "Sdist source distribution for this package."},
    )

    wheels: list[Wheel] = attr.ib(
        repr=False,
        default=attr.Factory(list),
        metadata={"help": "List of Wheel for this package"},
    )

    def get_supported_wheels(self, environment: Environment) -> str:
        """
        Yield all the Wheel of this package supported and compatible with the
        Environment `environment`.
        """
        envt_tags = environment.tags()
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print("get_supported_wheels: envt_tags:", envt_tags)
        for wheel in self.wheels:
            if wheel.is_supported_by_tags(envt_tags):
                yield wheel

    @classmethod
    def package_from_dists(cls, dists: list[Sdist | Wheel]) -> PypiPackage | None:
        """
        Return a new PypiPackage built from an iterable of Wheels and Sdist
        objects all for the same package name and version.

        For example:
        >>> w1 = Wheel(name='bitarray', version='0.8.1', build='',
        ...    python_versions=['cp36'], abis=['cp36m'],
        ...    platforms=['linux_x86_64'])
        >>> w2 = Wheel(name='bitarray', version='0.8.1', build='',
        ...    python_versions=['cp36'], abis=['cp36m'],
        ...    platforms=['macosx_10_9_x86_64', 'macosx_10_10_x86_64'])
        >>> sd = Sdist(name='bitarray', version='0.8.1')
        >>> package = PypiPackage.package_from_dists(dists=[w1, w2, sd])
        >>> assert package.name == 'bitarray'
        >>> assert package.version == '0.8.1'
        >>> assert package.sdist == sd
        >>> assert package.wheels == [w1, w2]
        """
        dists = list(dists)
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print(f"package_from_dists: {dists}")
        if not dists:
            return None

        reference_dist = dists[0]
        normalized_name = reference_dist.normalized_name
        version = reference_dist.version

        package = PypiPackage(name=normalized_name, version=version)

        for dist in dists:
            if dist.normalized_name != normalized_name:
                if settings.TRACE == TraceLevel.TRACE:
                    print(f"  Skipping inconsistent dist name: expected {normalized_name} got {dist}")
                continue
            elif dist.version != version:
                dv = packaging_version.parse(dist.version)
                v = packaging_version.parse(version)
                if dv != v:
                    if settings.TRACE == TraceLevel.TRACE:
                        print(f"  Skipping inconsistent dist version: expected {version} got {dist}")
                    continue

            if isinstance(dist, Sdist):
                package.sdist = dist

            elif isinstance(dist, Wheel):
                package.wheels.append(dist)

            else:
                raise Exception(f"Unknown distribution type: {dist}")

        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print(f"package_from_dists: {package}")

        return package

    @classmethod
    def packages_from_links(cls, links: list[Link]):
        """
        Yield PypiPackages built from a list of paths or URLs.
        These are sorted by name and then by version from oldest to newest.
        """
        dists = PypiPackage.dists_from_links(links)
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print("packages_from_many_paths_or_urls: dists:", dists)

        dists = NameVer.sorted(dists)

        for _projver, dists_of_package in itertools.groupby(
            dists,
            key=NameVer.sortable_name_version,
        ):
            package = PypiPackage.package_from_dists(dists_of_package)
            if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
                print("packages_from_many_paths_or_urls", package)
            yield package

    @classmethod
    def dists_from_links(cls, links: list[Link]):
        """
        Return a list of Distribution given a list of
        ``paths_or_urls`` to wheels or source distributions.

        Each Distribution receives two extra attributes:
            - the path_or_url it was created from
            - its filename

        For example:
        >>> links =[
        ...     Link(url="/home/foo/bitarray-0.8.1-cp36-cp36m-linux_x86_64.whl", python_requires= ">=3.7"),
        ...     Link(url="bitarray-0.8.1-cp36-cp36m-macosx_10_9_x86_64.macosx_10_10_x86_64.whl",
        ...         python_requires= ">=3.7"),
        ...     Link(url="bitarray-0.8.1-cp36-cp36m-win_amd64.whl",python_requires= ">=3.7"),
        ...     Link(url="https://example.com/bar/bitarray-0.8.1.tar.gz",python_requires= ">=3.7"),
        ...     Link(url="bitarray-0.8.1.tar.gz.ABOUT",python_requires= ">=3.7"),
        ...     Link(url="bit.LICENSE", python_requires=">=3.7")]
        >>> results = list(PypiPackage.dists_from_links(links))
        >>> for r in results:
        ...    print(r.__class__.__name__, r.name, r.version)
        ...    if isinstance(r, Wheel):
        ...       print(" ", ", ".join(r.python_versions), ", ".join(r.platforms))
        Wheel bitarray 0.8.1
          cp36 linux_x86_64
        Wheel bitarray 0.8.1
          cp36 macosx_10_9_x86_64, macosx_10_10_x86_64
        Wheel bitarray 0.8.1
          cp36 win_amd64
        Sdist bitarray 0.8.1
        """
        dists = []
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print("     ###paths_or_urls:", links)
        installable: list[Link] = [link for link in links if link.url.endswith(EXTENSIONS)]
        for link in installable:
            try:
                dist = Distribution.from_link(link=link)
                dists.append(dist)
                if settings.TRACE == TraceLevel.TRACE_DEEP:
                    print(
                        "     ===> dists_from_paths_or_urls:",
                        dist,
                        "\n     ",
                        "with URL:",
                        dist.download_url,
                        "\n     ",
                        "from URL:",
                        link.url,
                    )
            except InvalidDistributionFilename:
                if settings.TRACE == TraceLevel.TRACE_DEEP:
                    print(f"     Skipping invalid distribution from: {link.url}")
                continue
        return dists

    def get_distributions(self):
        """
        Yield all distributions available for this PypiPackage
        """
        if self.sdist:
            yield self.sdist
        for wheel in self.wheels:
            yield wheel

    def get_url_for_filename(self, filename):
        """
        Return the URL for this filename or None.
        """
        for dist in self.get_distributions():
            if dist.filename == filename:
                return dist.path_or_url


@attr.attributes
class Environment:
    """
    An Environment describes a target installation environment with its
    supported Python version, ABI, platform, implementation and related
    attributes.

    We can use these to pass as `pip download` options and force fetching only
    the subset of packages that match these Environment constraints as opposed
    to the current running Python interpreter constraints.
    """

    python_version: str = attr.ib(
        default="",
        metadata={"help": "Python version supported by this environment."},
    )

    operating_system: str = attr.ib(
        default="",
        metadata={"help": "operating system supported by this environment."},
    )

    implementation: str = attr.ib(
        default="cp",
        metadata={"help": "Python implementation supported by this environment."},
        repr=False,
    )

    abis: list = attr.ib(
        default=attr.Factory(list),
        metadata={"help": "List of ABI tags supported by this environment."},
        repr=False,
    )

    platforms: list = attr.ib(
        default=attr.Factory(list),
        metadata={"help": "List of platform tags supported by this environment."},
        repr=False,
    )

    @classmethod
    def from_pyver_and_os(cls, python_version, operating_system):
        if "." in python_version:
            python_version = "".join(python_version.split("."))

        return cls(
            python_version=python_version,
            implementation="cp",
            abis=ABIS_BY_PYTHON_VERSION[python_version],
            platforms=PLATFORMS_BY_OS[operating_system],
            operating_system=operating_system,
        )

    def get_pip_cli_options(self):
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

    def tags(self):
        """
        Return a set of all the PEP425 tags supported by this environment.
        """
        return set(
            utils_pip_compatibility_tags.get_supported(
                version=self.python_version or None,
                impl=self.implementation or None,
                platforms=self.platforms or None,
                abis=self.abis or None,
            ),
        )


################################################################################
#
# PyPI repo and link index for package wheels and sources
#
################################################################################


@attr.attributes
class PypiSimpleRepository:
    """
    A PyPI repository of Python packages: wheels, sdist, etc. like the public
    PyPI simple index. It is populated lazily based on requested packages names.
    """

    index_url: str = attr.ib(
        default=settings.INDEX_URL,
        metadata={"help": "Base PyPI simple URL for this index."},
    )

    # we keep a nested mapping of PypiPackage that has this shape:
    # {name: {version: PypiPackage, version: PypiPackage, etc}
    # the inner versions mapping is sorted by version from oldest to newest

    packages: dict = attr.ib(
        default=attr.Factory(lambda: defaultdict(dict)),
        metadata={
            "help": "Mapping of {name: {version: PypiPackage, version: PypiPackage, etc} available in this repo",
        },
        repr=False,
    )

    fetched_package_normalized_names: set = attr.ib(
        default=attr.Factory(set),
        metadata={"help": "A set of already fetched package normalized names."},
        repr=False,
    )

    use_cached_index: bool = attr.ib(
        default=True,
        metadata={"help": "If True, use any existing on-disk cached PyPI index files. Otherwise, fetch and cache."},
        repr=False,
    )

    credentials: HTTPBasicAuth | None = attr.ib(
        default=None,
        metadata={"help": "Basic authentication"},
    )

    def _get_package_versions_map(
        self,
        name: str,
        verbose: bool = False,
        echo_func: Callable[[str], None] | None = None,
    ) -> dict[str, PypiPackage | None]:
        """
        Return a mapping of all available PypiPackage version for this package name.
        The mapping may be empty. It is ordered by version from oldest to newest
        """
        if not name:
            raise ValueError("Invalid name !")
        normalized_name = NameVer.normalize_name(name)
        versions = self.packages[normalized_name]
        if not versions and normalized_name not in self.fetched_package_normalized_names:
            self.fetched_package_normalized_names.add(normalized_name)
            try:
                links = self.fetch_links(
                    normalized_name=normalized_name,
                    verbose=verbose,
                    echo_func=echo_func,
                )
                # note that this is sorted so the mapping is also sorted
                versions = {package.version: package for package in PypiPackage.packages_from_links(links=links)}
                self.packages[normalized_name] = versions
            except RemoteNotFetchedException as e:
                if settings.TRACE == TraceLevel.TRACE:
                    print(f"failed to fetch package name: {name} from: {self.index_url}:\n{e}")

        if not versions and settings.TRACE == TraceLevel.TRACE:
            print(f"WARNING: package {name} not found in repo: {self.index_url}")

        return versions

    def get_package_versions(
        self,
        name,
        verbose=False,
        echo_func=None,
    ):
        """
        Return a mapping of all available PypiPackage version as{version:
        package} for this package name. The mapping may be empty but not None.
        It is sorted by version from oldest to newest.
        """
        return dict(
            self._get_package_versions_map(
                name=name,
                verbose=verbose,
                echo_func=echo_func,
            ),
        )

    def get_package_version(
        self,
        name,
        version=None,
        verbose=False,
        echo_func=None,
    ):
        """
        Return the PypiPackage with name and version or None.
        Return the latest PypiPackage version if version is None.
        """
        if not version:
            versions = list(
                self._get_package_versions_map(
                    name=name,
                    verbose=verbose,
                    echo_func=echo_func,
                ).values(),
            )
            # return the latest version
            return versions and versions[-1]
        else:
            return self._get_package_versions_map(
                name=name,
                verbose=verbose,
                echo_func=echo_func,
            ).get(version)

    def fetch_links(
        self,
        normalized_name: str,
        verbose: bool = False,
        echo_func: Callable[[str], None] | None = None,
    ) -> list[Link]:
        """
        Return a list of download link URLs found in a PyPI simple index for package
        name using the `index_url` of this repository.
        """
        package_url = f"{self.index_url}/{normalized_name}"
        print(self.use_cached_index)
        exit(1)
        text = CACHE.get(
            path_or_url=package_url,
            credentials=self.credentials,
            as_text=True,
            force=not self.use_cached_index,
            verbose=verbose,
            echo_func=echo_func,
        )
        soup = BeautifulSoup(text, features="html.parser")
        anchor_tags = soup.find_all("a")
        links = []
        for anchor_tag in anchor_tags:
            python_requires = None
            url, _, _sha256 = anchor_tag["href"].partition("#sha256=")
            if "data-requires-python" in anchor_tag.attrs:
                python_requires = anchor_tag.attrs["data-requires-python"]
            # Resolve relative URL
            url = resolve_relative_url(package_url, url)
            links.append(Link(url=url, python_requires=python_requires))
        # TODO: keep sha256
        return links


def resolve_relative_url(package_url: str, url: str) -> str:
    """
    Return the resolved `url` URLstring given a `package_url` base URL string
    of a package.

    For example:
    >>> resolve_relative_url("https://example.com/package", "../path/file.txt")
    'https://example.com/path/file.txt'
    """
    if not url.startswith(("http://", "https://")):
        base_url_parts = urlparse(package_url)
        url_parts = urlparse(url)
        # If the relative URL starts with '..', remove the last directory from the base URL
        if url_parts.path.startswith(".."):
            path = base_url_parts.path.rstrip("/").rsplit("/", 1)[0] + url_parts.path[2:]
        else:
            path = urlunparse(("", "", url_parts.path, url_parts.params, url_parts.query, url_parts.fragment))
        resolved_url_parts = base_url_parts._replace(path=path)
        url = urlunparse(resolved_url_parts)
    return url


PYPI_PUBLIC_REPO = PypiSimpleRepository(index_url=settings.INDEX_URL)
DEFAULT_PYPI_REPOS = (PYPI_PUBLIC_REPO,)
DEFAULT_PYPI_REPOS_BY_URL = {r.index_url: r for r in DEFAULT_PYPI_REPOS}

################################################################################
#
# Basic file and URL-based operations using a persistent file-based Cache
#
################################################################################


class Cache:
    """
    A simple file-based cache based only on a filename presence.
    This is used to avoid impolite fetching from remote locations.
    """

    def __init__(self) -> None:
        Path(settings.CACHE_THIRDPARTY_DIR).mkdir(exist_ok=True)

    def string_to_hash(self, input_string: str) -> str:
        """
        Converts a given input string to its SHA-256 hash representation.

        Args:
            input_string (str): The string to be hashed.

        Returns:
            str: The SHA-256 hash of the input string.
        """
        hash_object = hashlib.sha256()
        hash_object.update(input_string.encode("utf-8"))
        return hash_object.hexdigest()

    def get(
        self,
        credentials: HTTPBasicAuth | None,
        path_or_url: str,
        as_text: bool = True,
        force: bool = False,
        verbose: bool = False,
        echo_func: Callable[[str], None] | None = None,
    ) -> Any:
        """
        Return the content fetched from a ``path_or_url`` through the cache.
        Raise an Exception on errors. Treats the content as text if as_text is
        True otherwise as treat as binary. `path_or_url` can be a path or a URL
        to a file.
        """
        cache_key = self.string_to_hash(quote_plus(path_or_url.strip("/")))
        cached: Path = settings.CACHE_THIRDPARTY_DIR / cache_key

        print(force)

        if force or not cached.exists():
            if settings.TRACE == TraceLevel.TRACE_DEEP:
                print(f"        FILE CACHE MISS: {path_or_url}")
                print(f"        CACHE_KEY: {cache_key}")
                print(f"        CACHED_FILE: {cached}")
                exit(1)
            content = get_file_content(
                path_or_url=path_or_url,
                credentials=credentials,
                as_text=as_text,
                verbose=verbose,
                echo_func=echo_func,
            )
            wmode = "w" if as_text else "wb"
            with cached.open(wmode) as fo:
                fo.write(content)
            return content
        else:
            if settings.TRACE == TraceLevel.TRACE_DEEP:
                print(f"        FILE CACHE HIT: {path_or_url}")
            return get_local_file_content(path=cached, as_text=as_text)


CACHE = Cache()


def get_file_content(
    path_or_url: str,
    credentials: HTTPBasicAuth | None,
    as_text: bool = True,
    verbose: bool = False,
    echo_func: Callable[[str], None] | None = None,
) -> Any:
    """
    Fetch and return the content at `path_or_url` from either a local path or a
    remote URL. Return the content as bytes is `as_text` is False.
    """
    if path_or_url.startswith("https://"):
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"Fetching: {path_or_url}")
        try:
            _headers, content = get_remote_file_content(
                url=path_or_url,
                credentials=credentials,
                as_text=as_text,
                verbose=verbose,
                echo_func=echo_func,
            )
        except requests.exceptions.RequestException as exc:
            print("All retry attempts failed:", exc)

        return content

    elif path_or_url.startswith("file://") or (path_or_url.startswith("/") and Path(path_or_url).exists()):
        return get_local_file_content(path=Path(path_or_url), as_text=as_text)

    else:
        raise ValueError(f"Unsupported URL scheme: {path_or_url}")


def get_local_file_content(path: Path, as_text: bool = True) -> Any:
    """
    Return the content at `url` as text. Return the content as bytes is
    `as_text` is False.
    """

    mode = "r" if as_text else "rb"
    with path.open(mode) as fo:
        return fo.read()


class RemoteNotFetchedException(Exception):  # noqa: N818
    pass


@retry(stop=stop_after_attempt(3), wait=wait_fixed(3))  # 5 retries with a 3-second delay
def get_remote_file_content(
    url: str,
    credentials: HTTPBasicAuth | None = None,
    as_text: bool = True,
    headers_only: bool = False,
    headers: dict[str, str] | None = None,
    verbose: bool = False,
    echo_func: Callable[[str], None] | None = None,
) -> Any:
    """
    Fetch and return a tuple of (headers, content) at `url`. Return content as a
    text string if `as_text` is True. Otherwise return the content as bytes.

    If `header_only` is True, return only (headers, None). Headers is a mapping
    of HTTP headers.
    Retries multiple times to fetch if there is a HTTP 429 throttling response
    and this with an increasing delay.
    """
    headers = headers or {}
    # using a GET with stream=True ensure we get the the final header from
    # several redirects and that we can ignore content there. A HEAD request may
    # not get us this last header
    if verbose:
        if not echo_func:
            echo_func = print
        echo_func(f"DOWNLOADING: {url}")

    stream = requests.get(url, allow_redirects=True, stream=True, headers=headers, auth=credentials, timeout=120)

    with stream as response:
        if headers_only:
            return response.headers, None

        return response.headers, response.text if as_text else response.content


def fetch_and_save(
    path_or_url: str,
    dest_dir: str,
    filename: str,
    credentials: HTTPBasicAuth | None,
    as_text: bool = True,
    verbose: bool = False,
    echo_func: Callable[[str], None] | None = None,
) -> Any:
    """
    Fetch content at ``path_or_url`` URL or path and save this to
    ``dest_dir/filername``. Return the fetched content. Raise an Exception on
    errors. Treats the content as text if as_text is True otherwise as treat as
    binary.
    """
    content = CACHE.get(
        path_or_url=path_or_url,
        credentials=credentials,
        as_text=as_text,
        verbose=verbose,
        echo_func=echo_func,
    )
    output = Path(dest_dir) / filename
    wmode = "w" if as_text else "wb"
    with output.open(wmode) as fo:
        fo.write(content)
    return content
