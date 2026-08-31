"""Paths that must not be public on our own site."""

import posixpath
import re

ALLOWED_DOT_PREFIXES = ("/.well-known",)

DANGEROUS_PATH_PREFIXES = (
    "/server-status",
    "/server-info",
    "/phpinfo",
    "/wp-config.php",
    "/web.config",
    "/id_rsa",
)

_REPEATED_SLASHES = re.compile(r"/{2,}")


def _normalize(path: str) -> str:
    return posixpath.normpath(_REPEATED_SLASHES.sub("/", path)).lower()


def is_dangerous_path(path: str) -> bool:
    if not path:
        return False
    p = _normalize(path)
    segments = [segment for segment in p.split("/") if segment]
    if segments and "/" + segments[0] in ALLOWED_DOT_PREFIXES:
        segments = segments[1:]
    if any(segment.startswith(".") for segment in segments):
        return True
    return any(
        p == prefix or p.startswith((prefix + "/", prefix + "."))
        for prefix in DANGEROUS_PATH_PREFIXES
    )
