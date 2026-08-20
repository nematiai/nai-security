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
    assert (dest / "google4e3f9dd160c3aab0.html").read_bytes() == (
        b"google-site-verification: google4e3f9dd160c3aab0.html"
    )
    assert (dest / "stylesheets" / "extra.css").is_file()
    assert Path(dest / "Installation.md").is_file()


def test_google_verify_file_is_under_sitemap_xml(tmp_path):
    from tools.mkdocs_hooks import place_verify_under_sitemap

    site = tmp_path / "site"
    site.mkdir()
    (site / "sitemap.xml").write_text("<?xml version='1.0'?><urlset/>", encoding="utf-8")
    verify = tmp_path / "google4e3f9dd160c3aab0.html"
    verify.write_bytes(b"google-site-verification: google4e3f9dd160c3aab0.html")

    dest = place_verify_under_sitemap(site, verify)
    assert dest == site / "sitemap.xml" / "google4e3f9dd160c3aab0.html"
    assert dest.read_bytes() == b"google-site-verification: google4e3f9dd160c3aab0.html"
    assert not (site / "sitemap.xml").is_file()
    assert (site / "sitemap.xml").is_dir()
