import re
from urllib.parse import urlsplit


def validated_http_url(value):
    if not isinstance(value, str) or not re.match(r"^https?://", value, re.IGNORECASE):
        return None
    if re.search(r'[\s\x00-\x1f\x7f\\<>"|]', value):
        return None
    try:
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username is not None or parsed.port == 0:
            return None
        if not re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname.encode("idna").decode("ascii")):
            return None
    except (ValueError, UnicodeError):
        return None
    return value
