# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

from pydantic import BaseModel


class PypiSimpleRepository(BaseModel):
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
