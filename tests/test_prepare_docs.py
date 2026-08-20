from pathlib import Path

from tools.prepare_docs import convert_wiki_links, prepare


def test_convert_wiki_links_plain_and_home():
    src = "See [[Installation]] and [[Home]]."
    assert convert_wiki_links(src) == "See [Installation](Installation.md) and [Home](index.md)."


def test_prepare_writes_index_and_robots(tmp_path, monkeypatch):
    import tools.prepare_docs as prep

    wiki = tmp_path / "wiki"
    wiki.mkdir()
    (wiki / "Home.md").write_text("# NAI Security Wiki\n\nGo to [[Installation]].\n", encoding="utf-8")
    (wiki / "Installation.md").write_text("# Installation\n", encoding="utf-8")
    (wiki / "_Sidebar.md").write_text("* [[Home]]\n", encoding="utf-8")
    out = tmp_path / ".docs-build"
    monkeypatch.setattr(prep, "WIKI", wiki)
    monkeypatch.setattr(prep, "OUT", out)

    dest = prepare()
    index = (dest / "index.md").read_text(encoding="utf-8")
    assert "title: \"NAI Security\"" in index
    assert "description:" in index
    assert index.startswith("---\n")
    assert "[Installation](Installation.md)" in index
    assert "# NAI Security\n" in index
    assert not (dest / "_Sidebar.md").exists()
    assert "Sitemap:" in (dest / "robots.txt").read_text(encoding="utf-8")
    assert (dest / "stylesheets" / "extra.css").is_file()
    assert Path(dest / "Installation.md").is_file()
    assert (dest / "assets" / "logo.svg").is_file()
    assert (dest / "assets" / "favicon.ico").is_file()


def test_verification_files_land_at_the_site_root(tmp_path, monkeypatch):
    """Google looks for the token at the property URL, which for a Pages project
    site is the site root — not under sitemap.xml, which must stay a file."""
    import tools.prepare_docs as prep

    root = tmp_path / "repo"
    (root / "wiki").mkdir(parents=True)
    (root / "wiki" / "Home.md").write_text("# NAI Security Wiki\n", encoding="utf-8")
    (root / "googleabc123.html").write_bytes(b"google-site-verification: googleabc123.html")
    out = tmp_path / ".docs-build"
    monkeypatch.setattr(prep, "ROOT", root)
    monkeypatch.setattr(prep, "WIKI", root / "wiki")
    monkeypatch.setattr(prep, "OUT", out)

    dest = prepare()
    assert (dest / "googleabc123.html").read_bytes() == b"google-site-verification: googleabc123.html"
    assert not (dest / "sitemap.xml").exists()


def test_a_second_property_token_needs_no_code_change(tmp_path, monkeypatch):
    import tools.prepare_docs as prep

    root = tmp_path / "repo"
    (root / "wiki").mkdir(parents=True)
    (root / "wiki" / "Home.md").write_text("# NAI Security Wiki\n", encoding="utf-8")
    (root / "googleone.html").write_bytes(b"one")
    (root / "googletwo.html").write_bytes(b"two")
    monkeypatch.setattr(prep, "ROOT", root)
    monkeypatch.setattr(prep, "WIKI", root / "wiki")
    monkeypatch.setattr(prep, "OUT", tmp_path / ".docs-build")

    dest = prepare()
    assert (dest / "googleone.html").is_file() and (dest / "googletwo.html").is_file()


def test_prepare_copies_brand_assets_when_present(tmp_path, monkeypatch):
    import tools.prepare_docs as prep

    root = tmp_path / "repo"
    (root / "wiki").mkdir(parents=True)
    (root / "wiki" / "Home.md").write_text("# NAI Security Wiki\n", encoding="utf-8")
    assets = root / "docs" / "assets"
    assets.mkdir(parents=True)
    (assets / "logo.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'></svg>\n", encoding="utf-8")
    (assets / "favicon.ico").write_bytes(b"\x00\x00\x01\x00")
    monkeypatch.setattr(prep, "ROOT", root)
    monkeypatch.setattr(prep, "WIKI", root / "wiki")
    monkeypatch.setattr(prep, "ASSETS", assets)
    monkeypatch.setattr(prep, "OUT", tmp_path / ".docs-build")

    dest = prepare()
    assert (dest / "assets" / "logo.svg").is_file()
    assert (dest / "assets" / "favicon.ico").read_bytes() == b"\x00\x00\x01\x00"
