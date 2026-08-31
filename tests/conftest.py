import pytest


def pytest_collection_modifyitems(items):
    """Every test in this package stubs its externals — no live stack exists here."""
    for item in items:
        if not item.get_closest_marker("real"):
            item.add_marker(pytest.mark.mock)
