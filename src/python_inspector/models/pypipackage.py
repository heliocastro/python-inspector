# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

import itertools
from collections.abc import Generator

from packvers import version as packaging_version
from packvers.tags import Tag
from pydantic import Field

from python_inspector import settings
from python_inspector.models import Environment, Link, NameVer
from python_inspector.models.distribution import Distribution, InvalidDistributionFilenameError
from python_inspector.models.sdist import EXTENSIONS, Sdist
from python_inspector.models.wheel import Wheel
from python_inspector.settings import TraceLevel

"""
- A PyPiPackage represents a PyPI package with its name, version and metadata.
"""


class PypiPackage(NameVer):
    """
    A Python package contains one or more wheels and one source distribution
    from a repository.
    """

    sdist: Sdist | None = Field(
        default=None,
        description="Sdist source distribution for this package.",
    )
    wheels: list[Wheel] = Field(
        default_factory=list,
        description="List of Wheel for this package",
    )

    def get_supported_wheels(self, environment: Environment) -> Generator[Wheel, None, None]:
        """
        Yield all the Wheel of this package supported and compatible with the
        Environment `environment`.
        """
        envt_tags: set[Tag] = environment.tags()
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print("get_supported_wheels: envt_tags:", envt_tags)
        for wheel in self.wheels:
            if wheel.is_supported_by_tags(envt_tags):
                yield wheel

    @classmethod
    def package_from_dists(cls, dists: list[Sdist | Wheel]) -> PypiPackage:
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
        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print(f"package_from_dists: {dists}")

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
                raise ValueError(f"Unknown distribution type: {dist}")

        if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
            print(f"package_from_dists: {package}")

        return package

    @classmethod
    def packages_from_links(cls, links: list[Link]) -> Generator[PypiPackage, None, None]:
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
            package = PypiPackage.package_from_dists(list(dists_of_package))
            if settings.TRACE == TraceLevel.TRACE_ULTRA_DEEP:
                print("packages_from_many_paths_or_urls", package)
            yield package

    @classmethod
    def dists_from_links(cls, links: list[Link]) -> list[Sdist | Wheel]:
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
        dists: list[Sdist | Wheel] = []
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
            except InvalidDistributionFilenameError:
                if settings.TRACE == TraceLevel.TRACE_DEEP:
                    print(f"     Skipping invalid distribution from: {link.url}")
                continue
        return dists

    def get_distributions(self) -> Generator[Sdist | Wheel, None, None]:
        """
        Yield all distributions available for this PypiPackage
        """
        if self.sdist:
            yield self.sdist
        yield from self.wheels

    def get_url_for_filename(self, filename: str) -> str | None:
        """
        Return the URL for this filename or None.
        """
        for dist in self.get_distributions():
            if dist.filename == filename:
                return dist.path_or_url
        return None
