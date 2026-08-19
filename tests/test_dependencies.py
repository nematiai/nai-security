"""Contract tests for declared runtime dependencies and version floors."""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"


def _load_project() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]


def _installed_version(dist_name: str) -> Version:
    return Version(importlib.metadata.version(dist_name))


def _requirement_satisfied(req_str: str) -> tuple[bool, str]:
    req = Requirement(req_str)
    try:
        installed = _installed_version(req.name)
    except importlib.metadata.PackageNotFoundError:
        return False, f"{req.name} is not installed"
    if req.specifier and installed not in req.specifier:
        return False, f"{req.name}=={installed} does not satisfy {req}"
    return True, f"{req.name}=={installed} satisfies {req}"


class TestPyprojectDependencyPins:
    def test_core_dependencies_are_declared(self):
        project = _load_project()
        names = {Requirement(r).name.lower() for r in project["dependencies"]}
        assert names == {"django", "geoip2", "redis", "requests"}

    def test_requests_is_a_core_dependency(self):
        """Regression: sync_services imports requests at runtime."""
        project = _load_project()
        reqs = [Requirement(r) for r in project["dependencies"]]
        requests_req = next((r for r in reqs if r.name.lower() == "requests"), None)
        assert requests_req is not None
        assert Version("2.28") in requests_req.specifier

    def test_geoip2_major_is_capped(self):
        project = _load_project()
        geo = next(Requirement(r) for r in project["dependencies"] if Requirement(r).name == "geoip2")
        assert Version("5.0") in geo.specifier
        assert Version("6.0") not in geo.specifier

    def test_redis_major_is_capped(self):
        project = _load_project()
        redis_req = next(
            Requirement(r) for r in project["dependencies"] if Requirement(r).name == "redis"
        )
        assert Version("5.0") in redis_req.specifier
        assert Version("9.0") not in redis_req.specifier

    def test_axes_optional_stays_below_9(self):
        project = _load_project()
        axes = Requirement(project["optional-dependencies"]["axes"][0])
        assert axes.name == "django-axes"
        assert Version("8.3.1") in axes.specifier
        assert Version("9.0") not in axes.specifier

    def test_import_export_optional_is_v4(self):
        project = _load_project()
        ie = Requirement(project["optional-dependencies"]["import-export"][0])
        assert Version("4.0") in ie.specifier
        assert Version("5.0") not in ie.specifier

    def test_unfold_floor_raised(self):
        project = _load_project()
        unfold = Requirement(project["optional-dependencies"]["unfold"][0])
        assert Version("0.90") in unfold.specifier
        assert Version("0.10") not in unfold.specifier

    def test_django_61_and_python_314_classifiers(self):
        project = _load_project()
        assert "Framework :: Django :: 6.1" in project["classifiers"]
        assert "Programming Language :: Python :: 3.14" in project["classifiers"]


class TestInstalledDependencyVersions:
    @pytest.mark.parametrize(
        "req_str",
        [
            "django>=4.2",
            "geoip2>=5.0,<6",
            "redis>=5.0,<9",
            "requests>=2.28",
        ],
    )
    def test_core_requirement_installed(self, req_str):
        ok, detail = _requirement_satisfied(req_str)
        assert ok, detail

    @pytest.mark.parametrize(
        "req_str",
        [
            "django-axes>=8.3.1,<9.0",
            "django-import-export>=4.0,<5",
            "django-unfold>=0.90",
        ],
    )
    def test_optional_requirement_installed_in_test_env(self, req_str):
        ok, detail = _requirement_satisfied(req_str)
        assert ok, detail


class TestRuntimeImportContracts:
    def test_requests_importable_for_sync_services(self):
        import requests

        assert hasattr(requests, "get")
        assert Version(requests.__version__) >= Version("2.28")

    def test_geoip2_reader_api_available(self):
        import geoip2.database
        from geoip2.models import Country

        assert hasattr(geoip2.database, "Reader")
        # geoip2 5.x replaced model.raw with to_dict()
        assert callable(getattr(Country, "to_dict", None))

    def test_redis_client_importable(self):
        import redis

        version = Version(getattr(redis, "__version__", importlib.metadata.version("redis")))
        assert version >= Version("5.0")
        assert version < Version("9.0")
        assert hasattr(redis, "Redis")

    def test_package_version_matches_pyproject(self):
        import nai_security

        project = _load_project()
        assert re.fullmatch(r"\d+\.\d+\.\d+", project["version"])
        assert project["version"] == "1.12.0"
        assert nai_security.__version__ == project["version"]
