import pytest
from django.core.cache import cache


def pytest_collection_modifyitems(items):
    """Every test in this package stubs its externals — no live stack exists here."""
    for item in items:
        if not item.get_closest_marker("real"):
            item.add_marker(pytest.mark.mock)


@pytest.fixture(autouse=True)
def clear_cache():
    """TestCase rolls back the database between tests but not the cache.

    SecuritySettings.get_settings() caches the singleton for 300s, so a test that
    mutates it leaks that object into whichever test runs next.
    """
    cache.clear()
    yield
    cache.clear()
