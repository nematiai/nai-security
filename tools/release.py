#!/usr/bin/env python3
"""Interactive release helper for nai-security.

Prompts for version and release options, then optionally:
bump versions, run tests, build, git commit/tag/push, upload to PyPI.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "nai_security" / "__init__.py"
README = ROOT / "README.md"
DEP_TESTS = ROOT / "tests" / "test_dependencies.py"
ENV_FILE = ROOT / ".env"
DIST = ROOT / "dist"
VENV_PYTHON = ROOT / ".venv" / "bin" / "python"
VENV_PYTEST = ROOT / ".venv" / "bin" / "pytest"
VENV_TWINE = ROOT / ".venv" / "bin" / "twine"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$")


def python_bin() -> str:
    if VENV_PYTHON.exists():
        return str(VENV_PYTHON)
    return sys.executable


def load_dotenv() -> None:
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    raw = input(f"{prompt}{suffix}: ").strip()
    if not raw and default is not None:
        return default
    return raw


def ask_yes(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = ask(f"{prompt} ({hint})", "y" if default else "n").lower()
    if raw in {"", "y", "yes"}:
        return True
    if raw in {"n", "no"}:
        return False
    print("Please answer y or n.")
    return ask_yes(prompt, default=default)


def run(cmd: list[str], *, env: dict | None = None, check: bool = True) -> int:
    print("+", " ".join(cmd))
    completed = subprocess.run(cmd, cwd=ROOT, env=env)
    if check and completed.returncode != 0:
        raise SystemExit(completed.returncode)
    return completed.returncode


def current_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("Could not find version in pyproject.toml")
    return match.group(1)


def set_version(new_version: str) -> None:
    # pyproject.toml
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    pyproject, n = re.subn(
        r'^version\s*=\s*"[^"]+"',
        f'version = "{new_version}"',
        pyproject,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise SystemExit("Failed to update version in pyproject.toml")
    PYPROJECT.write_text(pyproject, encoding="utf-8", newline="\n")

    # nai_security/__init__.py
    init = INIT.read_text(encoding="utf-8")
    init, n = re.subn(
        r"^__version__\s*=\s*['\"][^'\"]+['\"]",
        f"__version__ = '{new_version}'",
        init,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise SystemExit("Failed to update __version__ in nai_security/__init__.py")
    INIT.write_text(init, encoding="utf-8", newline="\n")

    # dependency contract test hard-coded expectation, if present
    if DEP_TESTS.exists():
        dep = DEP_TESTS.read_text(encoding="utf-8")
        dep2, n = re.subn(
            r'assert project\["version"\] == "[^"]+"',
            f'assert project["version"] == "{new_version}"',
            dep,
            count=1,
        )
        if n == 1:
            DEP_TESTS.write_text(dep2, encoding="utf-8", newline="\n")


def prepend_upgrade_notes(new_version: str, notes: str) -> None:
    readme = README.read_text(encoding="utf-8")
    marker = "## Upgrading to "
    block = (
        f"## Upgrading to {new_version}\n\n"
        f"{notes.rstrip()}\n\n"
    )
    idx = readme.find(marker)
    if idx == -1:
        readme = readme.rstrip() + "\n\n" + block
    else:
        readme = readme[:idx] + block + readme[idx:]
    README.write_text(readme, encoding="utf-8", newline="\n")


def build_artifacts() -> None:
    DIST.mkdir(exist_ok=True)
    # remove prior artifacts for this exact version only if present later via skip
    run(
        [
            python_bin(),
            "-c",
            "from build.__main__ import main; raise SystemExit(main(['--outdir','dist']))",
        ]
    )
    version = current_version()
    artifacts = sorted(DIST.glob(f"nai_security-{version}*"))
    if not artifacts:
        raise SystemExit(f"No dist artifacts found for {version}")
    run([str(VENV_TWINE if VENV_TWINE.exists() else "twine"), "check", *[str(p) for p in artifacts]])


def package_name() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("Could not find package name in pyproject.toml")
    return match.group(1)


def get_pypi_token() -> str:
    load_dotenv()
    token = os.environ.get("PYPI_TOKEN", "").strip()
    if not token:
        raise SystemExit("PYPI_TOKEN missing. Add it to .env")
    if not token.startswith("pypi-"):
        raise SystemExit("PYPI_TOKEN must start with 'pypi-'")
    return token


def verify_pypi_token() -> None:
    """Validate .env PYPI_TOKEN against PyPI upload API before any release work."""
    import requests

    token = get_pypi_token()
    name = package_name()
    print(f"Checking PyPI API token for project '{name}'...")

    # Authenticated probe without uploading a real file.
    # Valid token + incomplete form => HTTP 400.
    # Invalid/wrong-project token => HTTP 403 Invalid API Token.
    response = requests.post(
        "https://upload.pypi.org/legacy/",
        auth=("__token__", token),
        data={
            ":action": "file_upload",
            "protocol_version": "1",
            "name": name,
            "version": "0.0.0+token-check",
            "content": "",
        },
        timeout=30,
    )
    body = response.text or ""
    title = ""
    if "<title>" in body:
        title = body.split("<title>", 1)[1].split("</title>", 1)[0].strip()

    if response.status_code == 403 or "Invalid API Token" in body or "Invalid API Token" in title:
        detail = title or body[:240].replace("\n", " ")
        raise SystemExit(
            "PyPI API token verification FAILED.\n"
            f"HTTP {response.status_code}: {detail}\n"
            "Fix: create a token scoped to this project (or entire account) "
            "and update PYPI_TOKEN in .env"
        )

    if response.status_code >= 500:
        raise SystemExit(
            f"PyPI API token verification FAILED: server error HTTP {response.status_code}"
        )

    # 400 (missing/invalid file) means auth succeeded for this project.
    print(f"PyPI API token OK (auth accepted for '{name}', probe HTTP {response.status_code}).")


def publish_pypi() -> None:
    verify_pypi_token()

    token = get_pypi_token()
    version = current_version()
    artifacts = sorted(DIST.glob(f"nai_security-{version}*"))
    if not artifacts:
        raise SystemExit(f"No dist artifacts for {version}. Run build first.")

    env = os.environ.copy()
    env["TWINE_USERNAME"] = "__token__"
    env["TWINE_PASSWORD"] = token
    twine = str(VENV_TWINE if VENV_TWINE.exists() else "twine")
    run([twine, "upload", "--skip-existing", *[str(p) for p in artifacts]], env=env)


def git_release(new_version: str, message: str) -> None:
    files = [
        "pyproject.toml",
        "nai_security/__init__.py",
        "README.md",
        "tests/test_dependencies.py",
    ]
    existing = [f for f in files if (ROOT / f).exists()]
    run(["git", "add", *existing])
    env = os.environ.copy()
    # Use existing git identity if configured; otherwise fall back to last commit author.
    try:
        name = subprocess.check_output(["git", "config", "user.name"], cwd=ROOT, text=True).strip()
        email = subprocess.check_output(["git", "config", "user.email"], cwd=ROOT, text=True).strip()
    except subprocess.CalledProcessError:
        name = subprocess.check_output(
            ["git", "log", "-1", "--format=%an"], cwd=ROOT, text=True
        ).strip()
        email = subprocess.check_output(
            ["git", "log", "-1", "--format=%ae"], cwd=ROOT, text=True
        ).strip()
    env["GIT_AUTHOR_NAME"] = name
    env["GIT_AUTHOR_EMAIL"] = email
    env["GIT_COMMITTER_NAME"] = name
    env["GIT_COMMITTER_EMAIL"] = email
    run(["git", "commit", "-m", message], env=env)
    tag = f"v{new_version}"
    run(["git", "tag", "-a", tag, "-m", f"Release {new_version}"], env=env)
    if ask_yes("Push commit and tag to origin?", default=True):
        run(["git", "push", "origin", "HEAD"], env=env)
        run(["git", "push", "origin", tag], env=env)


def cmd_bump_only() -> None:
    current = current_version()
    print(f"Current version: {current}")
    new_version = ask("New version (semver X.Y.Z)")
    if not VERSION_RE.match(new_version):
        raise SystemExit(f"Invalid version format: {new_version}")
    if not ask_yes(f"Write version files to {new_version}?", default=True):
        raise SystemExit("Aborted.")
    set_version(new_version)
    print(f"Updated version to {new_version}")


def cmd_release() -> None:
    current = current_version()
    print(f"Current version: {current}")
    print("Release checklist will ask before each major step.\n")

    # Always verify API credentials first when PyPI upload is intended.
    print("--- PyPI API check (first) ---")
    do_pypi = ask_yes("Upload to PyPI in this release?", default=True)
    if do_pypi:
        verify_pypi_token()
    else:
        print("Skipping PyPI token check (no upload requested).")
    print()

    new_version = ask("New version (semver X.Y.Z)", default="")
    if not new_version:
        raise SystemExit("Version is required.")
    if not VERSION_RE.match(new_version):
        raise SystemExit(f"Invalid version format: {new_version}")
    if new_version == current:
        if not ask_yes(f"Version is already {current}. Continue without bump?", default=False):
            raise SystemExit("Aborted.")
        do_bump = False
    else:
        do_bump = ask_yes(f"Update version files to {new_version}?", default=True)

    upgrade_notes = ""
    if ask_yes("Add/update README upgrading notes?", default=True):
        print("Enter upgrade notes. End with an empty line:")
        lines: list[str] = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        upgrade_notes = "\n".join(lines).strip()
        if not upgrade_notes:
            upgrade_notes = "**Dependency / packaging release.**"

    do_tests = ask_yes("Run full pytest suite?", default=True)
    do_build = ask_yes("Build sdist/wheel and twine check?", default=True)
    do_git = ask_yes("Create git commit + tag?", default=True)

    print("\n--- Plan ---")
    print(f"version: {current} -> {new_version}")
    print(f"bump files: {do_bump}")
    print(f"readme notes: {bool(upgrade_notes)}")
    print(f"tests: {do_tests}")
    print(f"build: {do_build}")
    print(f"git: {do_git}")
    print(f"pypi: {do_pypi}")
    if not ask_yes("Proceed?", default=True):
        raise SystemExit("Aborted.")

    if do_bump:
        set_version(new_version)
        print(f"Updated version to {new_version}")
    if upgrade_notes:
        prepend_upgrade_notes(new_version, upgrade_notes)
        print("Updated README upgrading section")

    if do_tests:
        pytest = str(VENV_PYTEST if VENV_PYTEST.exists() else "pytest")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT)
        run([pytest, "-q"], env=env)

    if do_build:
        build_artifacts()

    if do_git:
        msg = ask(
            "Commit message",
            default=f"chore: release {new_version}",
        )
        git_release(new_version, msg)

    if do_pypi:
        # Re-check immediately before upload in case .env changed mid-run.
        verify_pypi_token()
        publish_pypi()
        print(f"Published nai-security=={new_version} to PyPI")

    print("\nDone.")


def main(argv: list[str] | None = None) -> None:
    os.chdir(ROOT)
    load_dotenv()
    args = list(sys.argv[1:] if argv is None else argv)
    cmd = args[0] if args else "release"

    if cmd in {"-h", "--help", "help"}:
        print("Usage: python tools/release.py [check|release|bump|publish|build|version]")
        return
    if cmd == "version":
        print(current_version())
        return
    if cmd == "check":
        verify_pypi_token()
        return
    if cmd == "bump":
        cmd_bump_only()
        return
    if cmd == "build":
        build_artifacts()
        return
    if cmd == "publish":
        # verify_pypi_token() runs inside publish_pypi() first
        publish_pypi()
        return
    if cmd == "release":
        cmd_release()
        return
    raise SystemExit(f"Unknown command: {cmd}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        raise SystemExit(130)
