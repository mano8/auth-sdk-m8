"""Verify the packed wheel and sdist actually contain and export the SDK (§5.1).

Builds real distributions with the project's declared build backend
(hatchling) via ``python -m build --no-isolation`` — no network round-trip to
re-resolve build requirements, since ``hatchling``/``build`` are already dev
dependencies — and proves the built wheel installs into a clean target and
its public surface (including the new fixture-matrix package data) imports
and loads correctly. mypy/ruff/pytest passing against the source tree does
not prove packaging metadata is correct; only building and installing the
real artifact does.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def built_distributions(tmp_path_factory) -> dict[str, Path]:
    out_dir = tmp_path_factory.mktemp("dist")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(out_dir.glob("*.whl"))
    sdists = list(out_dir.glob("*.tar.gz"))
    assert len(wheels) == 1, f"expected exactly one wheel, found {wheels}"
    assert len(sdists) == 1, f"expected exactly one sdist, found {sdists}"
    return {"wheel": wheels[0], "sdist": sdists[0]}


class TestWheelContents:
    def test_wheel_contains_the_fixture_matrix_package_data(
        self, built_distributions: dict[str, Path]
    ) -> None:
        with zipfile.ZipFile(built_distributions["wheel"]) as zf:
            names = zf.namelist()
        assert "auth_sdk_m8/testing/authorization_matrix.json" in names
        assert "auth_sdk_m8/__init__.py" in names
        assert "auth_sdk_m8/authorization.py" in names

    def test_wheel_excludes_the_test_suite(
        self, built_distributions: dict[str, Path]
    ) -> None:
        with zipfile.ZipFile(built_distributions["wheel"]) as zf:
            names = zf.namelist()
        assert not any(name.startswith("tests/") for name in names)


class TestSdistContents:
    def test_sdist_contains_the_fixture_matrix_source_and_generator(
        self, built_distributions: dict[str, Path]
    ) -> None:
        with tarfile.open(built_distributions["sdist"]) as tf:
            names = tf.getnames()
        assert any(
            n.endswith("auth_sdk_m8/testing/authorization_matrix.json") for n in names
        )
        assert any(
            n.endswith("scripts/generate_authorization_fixture_matrix.py")
            for n in names
        )


class TestInstalledWheelImports:
    def test_public_api_and_fixture_matrix_import_from_a_clean_install(
        self, built_distributions: dict[str, Path], tmp_path: Path
    ) -> None:
        install_dir = tmp_path / "site"
        install_dir.mkdir()
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--target",
                str(install_dir),
                str(built_distributions["wheel"]),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        probe = (
            "import sys; "
            f"sys.path.insert(0, {str(install_dir)!r}); "
            "import auth_sdk_m8 as sdk; "
            "assert sdk.has_minimum_role is not None; "
            "matrix = sdk.load_authorization_fixture_matrix(); "
            "assert matrix['schema_version'] == sdk.FIXTURE_MATRIX_SCHEMA_VERSION; "
            "assert len(matrix['role_flag_matrix']) == 10; "
            "assert len(matrix['canonical_jwt_fixtures']['tokens']) == 10; "
            "print('OK')"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe],
            check=True,
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip() == "OK"
