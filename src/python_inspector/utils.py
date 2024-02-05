#!/usr/bin/env python
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/python-inspector for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import ParseResult, urlparse

import requests


def get_netrc_auth(url, netrc) -> tuple[Any | None, Any | None]:
    """
    Return login and password if url is in netrc
    else return login and password as None
    """
    parsed_url: ParseResult = urlparse(url)
    url_auth = netrc.authenticators(parsed_url.netloc)

    if url_auth:
        return (url_auth[0], url_auth[2])

    return (None, None)


def contain_string(string: str, files: list[str]) -> bool:
    """
    Return True if the ``string`` is contained in any of the ``files`` list of file paths.
    """
    for file in files:
        fp = Path(file)
        if fp.exists():
            with fp.open(encoding="utf-8") as f:
                # TODO also consider other file names
                if string in f.read():
                    return True
    return False


def write_output_in_file(output, location):
    """
    Write headers, requirements and resolved_dependencies as JSON to ``json_output``.
    Return the output data.
    """
    json.dump(output, location, indent=2)
    return output


class Candidate(NamedTuple):
    """
    A candidate is a package that can be installed.
    """

    name: str
    version: str
    extras: str


def get_response(url: str) -> Any:
    """
    Return a mapping of the JSON response from fetching ``url``
    or None if the ``url`` cannot be fetched..
    """
    resp = requests.get(url, timeout=3600)
    if resp.status_code == 200:
        return resp.json()


def remove_test_data_dir_variable_prefix(path, placeholder="<file>"):
    """
    Return a clean path, removing variable test path prefix or using a ``placeholder``.
    Used for testing to ensure that results are stable across runs.
    """
    path = path.replace("\\", "/")
    if "tests/data/" in path:
        _junk, test_dir, cleaned = path.partition("tests/data/")
        cleaned = f"{test_dir}{cleaned}"
        return cleaned.replace("\\", "/")
    else:
        return placeholder
