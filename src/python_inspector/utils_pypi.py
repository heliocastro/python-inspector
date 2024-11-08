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

import re
from collections.abc import Callable
from pathlib import Path

from packvers.specifiers import SpecifierSet

from python_inspector import settings
from python_inspector.core.settings import TraceLevel
from python_inspector.models import Environment
from python_inspector.models.pypipackage import PypiPackage
from python_inspector.models.pypisimplerepository import PypiSimpleRepository, get_default_repo
from python_inspector.models.sdist import Sdist
from python_inspector.models.wheel import Wheel

"""
Utilities to manage Python thirparty libraries source, binaries and metadata in
requirements and remote repositories.
"""


collect_urls = re.compile('href="([^"]+)"').findall


def download_wheel(
    name: str,
    version: str,
    environment: Environment,
    repos: tuple[PypiSimpleRepository],
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
        repos = get_default_repo()

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
) -> Sdist | None:
    package = repo.get_package_version(name=name, version=version)
    if not package or not isinstance(package, PypiPackage):
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"    get_valid_sdist: No package in {repo.index_url} for {name}=={version}")
        return None

    sdist = package.sdist

    if not sdist:
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"    get_valid_sdist: No sdist for {name}=={version}")
        return None
    if not valid_python_version(python_requires=sdist.python_requires, python_version=python_version):
        return None
    if settings.TRACE == TraceLevel.TRACE_DEEP:
        print(f"    get_valid_sdist: Getting sdist from index (or cache): {sdist.download_url}")
    return sdist


def get_supported_and_valid_wheels(
    repo: PypiSimpleRepository,
    name: str,
    version: str,
    environment: Environment,
    python_version: str = settings.DEFAULT_PYTHON_VERSION,
) -> list[Wheel]:
    """
    Return a list of wheels matching the ``environment`` Environment constraints.
    """
    package = repo.get_package_version(name=name, version=version)
    if not package:
        if settings.TRACE == TraceLevel.TRACE_DEEP:
            print(f"    get_supported_and_valid_wheels: No package in {repo.index_url} for {name}=={version}")
        return []
    supported_wheels = package.get_supported_wheels(environment=environment)
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


def valid_python_version(python_version: str, python_requires: str) -> bool:
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
    repos: tuple[PypiSimpleRepository] = (),
    verbose: bool = False,
    echo_func: Callable[[str], None] | None = None,
    python_version: str = settings.DEFAULT_PYTHON_VERSION,
) -> str | None:
    """
    Download the sdist source distribution of package ``name`` and ``version``
    into the ``dest_dir`` directory. Return a fetched filename or None.

    Use the first PyPI simple repository from a list of ``repos`` that contains
    this sdist.
    """
    if settings.TRACE == TraceLevel.TRACE_DEEP:
        print(f"  download_sdist: {name}=={version}")

    if not repos:
        repos = get_default_repo()

    fetched_sdist_filename: str | None = None

    for repo in repos:
        sdist: Sdist | None = get_valid_sdist(repo, name, version, python_version=python_version)
        if not sdist:
            if settings.TRACE == TraceLevel.TRACE_DEEP:
                print(f"    download_sdist: No valid sdist for {name}=={version}")
            continue
        fetched_sdist_filename = sdist.download(
            verbose=verbose,
            echo_func=echo_func,
        )

        if fetched_sdist_filename:
            # do not futher fetch from other repos if we find in first, typically PyPI
            break

    return fetched_sdist_filename


def is_pure_wheel(filename: str) -> bool:
    try:
        return Wheel.from_filename(filename).is_pure()
    except Exception:
        return False
