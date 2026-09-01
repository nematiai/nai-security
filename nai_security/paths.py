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

# Never a legitimate route on a Django app: editor and backup leftovers, database
# dumps, logs, and the scripting extensions Django does not execute.
DANGEROUS_SUFFIXES = (
    ".bak", ".old", ".orig", ".save", ".swp", ".swo", ".tmp",
    ".sql", ".log", ".pem", ".key", ".sqlite", ".sqlite3", ".db",
    ".php", ".php5", ".phtml", ".asp", ".aspx", ".jsp", ".cgi",
)

# Only suspicious at the site root — a backup someone dropped beside the app. Deeper
# down these are ordinary user downloads.
ROOT_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".gz", ".bz2")

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
    if p.endswith(DANGEROUS_SUFFIXES):
        return True
    if len(segments) == 1 and p.endswith(ROOT_ARCHIVE_SUFFIXES):
        return True
    return any(
        p == prefix or p.startswith((prefix + "/", prefix + "."))
        for prefix in DANGEROUS_PATH_PREFIXES
    )
