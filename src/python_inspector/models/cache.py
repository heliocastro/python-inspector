# Copyright (c) nexB Inc. and others. All rights reserved.
# ScanCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 AND MIT
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/skeleton for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

import requests
from pydantic import BaseModel
from requests.auth import HTTPBasicAuth
from tenacity import retry, stop_after_attempt, wait_fixed

from python_inspector import settings
from python_inspector.core.settings import TraceLevel


class Cache(BaseModel):
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
            content = self.get_file_content(
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
            return self.get_local_file_content(path=cached, as_text=as_text)

    def get_file_content(
        self,
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
                _headers, content = self.get_remote_file_content(
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
            return self.get_local_file_content(path=Path(path_or_url), as_text=as_text)

        else:
            raise ValueError(f"Unsupported URL scheme: {path_or_url}")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(3))  # 5 retries with a 3-second delay
    def get_remote_file_content(
        self,
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

    def get_local_file_content(
        self,
        path: Path,
        as_text: bool = True,
    ) -> Any:
        """
        Return the content at `url` as text. Return the content as bytes is
        `as_text` is False.
        """

        mode = "r" if as_text else "rb"
        with path.open(mode) as fo:
            return fo.read()
