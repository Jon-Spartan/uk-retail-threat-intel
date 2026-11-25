"""Bounded public feed downloads with explicitly scoped HTTPS redirects."""

import json
import time
from urllib.parse import urljoin, urlsplit

import requests

from public_urls import validated_http_url


MAX_BODY = 5 * 1024 * 1024
REDIRECT_ALIASES = {"feeds.feedburner.com": {"securityweek.com", "www.securityweek.com"}}


class FeedError(ValueError):
    """A source returned an unusable response."""


class FeedSession(requests.Session):
    # Requests normally prepares the next redirect even with allow_redirects=False.
    # Skipping preparation keeps unneeded redirect response bodies unread.
    def resolve_redirects(self, *args, **kwargs):
        return iter(())


def download_source(url, params=None, limit=MAX_BODY, headers=None):
    if not validated_http_url(url) or urlsplit(url).scheme != "https" or urlsplit(url).port not in (None, 443):
        raise FeedError("Source URL is invalid.")
    host = urlsplit(url).hostname
    base = host.removeprefix("www.")
    allowed = {base, "www." + base} | REDIRECT_ALIASES.get(host, set())
    deadline = time.monotonic() + 25
    with FeedSession() as session:
        session.trust_env = False
        for _ in range(4):
            if time.monotonic() > deadline:
                raise FeedError("Source exceeded its time limit.")
            with session.get(url, params=params, headers=headers, timeout=(3, 8),
                             allow_redirects=False, stream=True) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    target = urljoin(url, response.headers.get("Location", ""))
                    if (not validated_http_url(target) or urlsplit(target).scheme != "https"
                            or urlsplit(target).hostname not in allowed
                            or urlsplit(target).port not in (None, 443)):
                        raise FeedError("Source redirect is outside the allowed hosts.")
                    url, params = target, None
                    continue
                if response.status_code != 200:
                    raise FeedError("Source HTTP response was unsuccessful.")
                advertised = response.headers.get("Content-Length")
                if advertised is not None and (not advertised.isdecimal() or len(advertised) > 10
                                               or int(advertised) > limit):
                    raise FeedError("Source body exceeds its size limit.")
                payload = bytearray()
                for chunk in response.iter_content(chunk_size=16384):
                    if time.monotonic() > deadline or len(payload) + len(chunk) > limit:
                        raise FeedError("Source exceeded its time or size limit.")
                    payload.extend(chunk)
                if time.monotonic() > deadline:
                    raise FeedError("Source exceeded its time limit.")
                return bytes(payload)
    raise FeedError("Source exceeded its redirect limit.")


def download_json(url, **kwargs):
    return json.loads(download_source(url, **kwargs))
