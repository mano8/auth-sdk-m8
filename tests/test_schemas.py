"""Package-level import smoke test."""

import tomllib
from pathlib import Path

import auth_sdk_m8


def test_package_version() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as fh:
        expected_version = tomllib.load(fh)["project"]["version"]

    assert hasattr(auth_sdk_m8, "__version__")
    assert auth_sdk_m8.__version__ == expected_version
