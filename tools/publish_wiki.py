#!/usr/bin/env python3
"""Publish wiki/*.md pages to GitHub Wiki (nematiai/nai-security.wiki.git).

GitHub only creates the wiki git remote after the first page exists in the UI.
If clone fails, this script prints the one-time init steps.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WIKI_SRC = ROOT / "wiki"
WIKI_REMOTE = "https://github.com/nematiai/nai-security.wiki.git"


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd or ROOT, check=check, text=True, capture_output=True)


def main() -> None:
    if not WIKI_SRC.is_dir():
        raise SystemExit(f"Missing wiki source directory: {WIKI_SRC}")

    pages = sorted(WIKI_SRC.glob("*.md"))
    if not pages:
        raise SystemExit(f"No markdown pages found in {WIKI_SRC}")

    # Ensure gh credentials are available for HTTPS git.
    subprocess.run(["gh", "auth", "setup-git"], check=False)

    tmp = Path(tempfile.mkdtemp(prefix="nai-security-wiki-"))
    try:
        clone = subprocess.run(
            ["git", "clone", WIKI_REMOTE, str(tmp)],
            text=True,
            capture_output=True,
        )
        if clone.returncode != 0:
            print(clone.stderr.strip())
            print(
                "\nWiki git remote does not exist yet.\n"
                "One-time init required:\n"
                "  1) Open https://github.com/nematiai/nai-security/wiki\n"
                "  2) Click 'Create the first page'\n"
                "  3) Title: Home\n"
                "  4) Paste content from wiki/Home.md and Save\n"
                "  5) Re-run: make wiki\n"
            )
            raise SystemExit(2)

        # Replace tracked markdown pages with source of truth from repo wiki/
        for path in tmp.glob("*.md"):
            path.unlink()
        for src in pages:
            shutil.copy2(src, tmp / src.name)

        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=tmp,
            check=True,
            text=True,
            capture_output=True,
        )
        if not status.stdout.strip():
            print("Wiki already up to date.")
            return

        env = os.environ.copy()
        try:
            name = subprocess.check_output(["git", "config", "user.name"], cwd=ROOT, text=True).strip()
            email = subprocess.check_output(["git", "config", "user.email"], cwd=ROOT, text=True).strip()
        except subprocess.CalledProcessError:
            name = subprocess.check_output(["git", "log", "-1", "--format=%an"], cwd=ROOT, text=True).strip()
            email = subprocess.check_output(["git", "log", "-1", "--format=%ae"], cwd=ROOT, text=True).strip()
        env["GIT_AUTHOR_NAME"] = name
        env["GIT_AUTHOR_EMAIL"] = email
        env["GIT_COMMITTER_NAME"] = name
        env["GIT_COMMITTER_EMAIL"] = email

        subprocess.run(
            ["git", "commit", "-m", "docs: update nai-security wiki usage guide"],
            cwd=tmp,
            check=True,
            env=env,
        )
        push = subprocess.run(["git", "push", "origin", "HEAD"], cwd=tmp, text=True, capture_output=True)
        if push.returncode != 0:
            print(push.stdout)
            print(push.stderr)
            raise SystemExit(push.returncode)
        print("Wiki published: https://github.com/nematiai/nai-security/wiki")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)
