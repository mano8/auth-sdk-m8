"""Package-level import smoke test."""
import auth_sdk_m8


def test_package_version() -> None:
    assert hasattr(auth_sdk_m8, "__version__")
    assert auth_sdk_m8.__version__ == "0.1.0"
