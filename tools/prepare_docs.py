#!/usr/bin/env python3
"""Copy wiki/*.md into .docs-build/ for MkDocs (convert [[Wiki]] links)."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIKI = ROOT / "wiki"
OUT = ROOT / ".docs-build"
ASSETS = ROOT / "docs" / "assets"
WIKI_LINK = re.compile(r"\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|([^\]]+))?\]\]")

PAGE_META = {
    "index.md": "Django security package for IP, country, email, and user-agent blocking, GeoIP, rate-limit logging, and django-axes lockout.",
    "Installation.md": "Install nai-security, add middleware after AuthenticationMiddleware, configure GeoIP, and migrate.",
    "Configuration.md": "Django settings for nai-security: GEOIP_PATH, exempt paths, NAI_SECURITY_TRUST_PROXY_HEADERS, and admin SecuritySettings.",
    "Admin-Guide.md": "Manage blocked IPs, countries, emails, user agents, whitelist, login history, and SecuritySettings in Django admin.",
    "Axes-Integration.md": "Use DynamicAxesHandler so django-axes failure limits, cooloff, and attempt expiry are controlled from SecuritySettings.",
    "Whitelisting.md": "Exempt IPs and users from nai-security middleware and django-axes lockout.",
    "Management-Commands.md": "download_geoip and sync_security_lists management commands for nai-security.",
    "Celery-Tasks.md": "Optional Celery beat tasks for auto-block, expired IP cleanup, list sync, and security reports.",
    "Upgrading.md": "Upgrade nai-security: 1.16.0 response header stripping; 1.15.0 deploy checks; 1.14.1 startup-crash fixes; 1.14.0 path blocking (migrations 0006 + 0007); 1.13.0 Django 5.2 floor, requests 2.32.4, celery extra; 1.12.0 proxy-header change.",
}

EXTRA_CSS = """\
.md-typeset h1 {
  font-weight: 650;
  letter-spacing: -0.02em;
}
.md-typeset code {
  font-size: 0.85em;
}
.md-header__button.md-logo img,
.md-header__button.md-logo svg {
  height: 1.8rem;
  width: auto;
}
"""

ROBOTS = """\
User-agent: *
Allow: /

Sitemap: https://nematiai.github.io/nai-security/sitemap.xml
"""

# Google Search Console HTML-file verification. Drop the file Search Console
# issues for THIS property at the repo root; every google*.html there is
# published at the site root, which is where Google looks. Not pinned to one
# name: a token belongs to one property, and a second property needs a second
# file rather than an edit here.
def verification_files() -> list[Path]:
    return sorted(ROOT.glob("google*.html"))


def convert_wiki_links(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        target = match.group(1).strip()
        label = (match.group(2) or target).strip()
        href = "index.md" if target == "Home" else f"{target}.md"
        return f"[{label}]({href})"

    return WIKI_LINK.sub(repl, text)


def _front_matter(filename: str, title: str) -> str:
    description = PAGE_META.get(filename, "nai-security Django documentation.")
    return (
        "---\n"
        f"title: {json.dumps(title, ensure_ascii=True)}\n"
        f"description: {json.dumps(description, ensure_ascii=True)}\n"
        "---\n\n"
    )


def prepare() -> Path:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    for src in sorted(WIKI.glob("*.md")):
        if src.name.startswith("_"):
            continue
        body = convert_wiki_links(src.read_text(encoding="utf-8"))
        dest_name = "index.md" if src.name == "Home.md" else src.name
        first_line = next((ln[2:].strip() for ln in body.splitlines() if ln.startswith("# ")), dest_name[:-3])
        if dest_name == "index.md" and first_line == "NAI Security Wiki":
            body = body.replace("# NAI Security Wiki", "# NAI Security", 1)
            first_line = "NAI Security"
        dest = OUT / dest_name
        dest.write_text(_front_matter(dest_name, first_line) + body, encoding="utf-8", newline="\n")

    (OUT / "robots.txt").write_text(ROBOTS, encoding="utf-8", newline="\n")
    for verify in verification_files():
        shutil.copyfile(verify, OUT / verify.name)
    styles = OUT / "stylesheets"
    styles.mkdir()
    (styles / "extra.css").write_text(EXTRA_CSS, encoding="utf-8", newline="\n")
    if ASSETS.is_dir():
        dest_assets = OUT / "assets"
        dest_assets.mkdir()
        for src in sorted(ASSETS.iterdir()):
            if src.is_file():
                shutil.copyfile(src, dest_assets / src.name)
    return OUT


def main() -> None:
    dest = prepare()
    print(f"Prepared MkDocs sources in {dest}")


if __name__ == "__main__":
    main()
