"""MkDocs hooks. Keep Google's HTML file at the Search Console property path."""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "google4e3f9dd160c3aab0.html"


def place_verify_under_sitemap(site_dir: Path, verify_src: Path = VERIFY) -> Path:
    """Serve google*.html at /sitemap.xml/google*.html.

    Search Console asked for the file under
    https://nematiai.github.io/nai-security/sitemap.xml/ — MkDocs writes
    sitemap.xml as a file, so this replaces that file with a folder, keeps the
    XML at sitemap.xml.gz (already built), and copies the verification file in.
    """
    site_dir = Path(site_dir)
    xml_path = site_dir / "sitemap.xml"
    if xml_path.is_file():
        xml_path.unlink()
    elif xml_path.is_dir():
        shutil.rmtree(xml_path)
    xml_path.mkdir()
    dest = xml_path / verify_src.name
    shutil.copyfile(verify_src, dest)
    return dest


def on_post_build(config) -> None:
    place_verify_under_sitemap(Path(config["site_dir"]))
