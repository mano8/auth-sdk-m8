"""CI and release-workflow policy tests — findings 11.6, 11.7, 11.8."""

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CI_YAML = WORKFLOWS / "CI.yaml"
PIPY_YML = WORKFLOWS / "PiPy.yml"

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"uses:\s+([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@(\S+))")


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return yaml.safe_load(fh)  # type: ignore[no-any-return]


def _action_refs(path: Path) -> list[tuple[str, str]]:
    """Return (full-ref, sha-candidate) for every action ``uses:`` in a workflow."""
    results: list[tuple[str, str]] = []
    for m in _USES_RE.finditer(path.read_text()):
        full_ref = m.group(1)
        sha_part = m.group(2).split("#")[0].strip()
        results.append((full_ref, sha_part))
    return results


# ── 11.6  PyPI Trusted Publishing — no long-lived API token ─────────────────


def test_pypi_workflow_no_api_token() -> None:
    """PiPy.yml must not reference PYPI_API_TOKEN; OIDC Trusted Publishing only."""
    assert "PYPI_API_TOKEN" not in PIPY_YML.read_text()


def test_pypi_publish_job_has_oidc_permission() -> None:
    """The pypi-publish job must declare id-token: write for OIDC."""
    wf = _load_yaml(PIPY_YML)
    perms = wf["jobs"]["pypi-publish"].get("permissions", {})
    assert perms.get("id-token") == "write"


def test_pypi_publish_job_uses_protected_environment() -> None:
    """The pypi-publish job must target a named protected environment."""
    wf = _load_yaml(PIPY_YML)
    env = wf["jobs"]["pypi-publish"].get("environment")
    assert env is not None, "pypi-publish must declare an environment."
    name = env.get("name") if isinstance(env, dict) else env
    assert name, "pypi-publish environment must have a non-empty name."


# ── 11.7  CI workflow consolidation — one canonical gate ────────────────────


def test_no_duplicate_ci_yml() -> None:
    """ci.yml must not exist — CI.yaml is the single canonical quality gate."""
    assert not (WORKFLOWS / "ci.yml").exists(), (
        "Found duplicate ci.yml; the canonical workflow is CI.yaml."
    )


def test_ci_yaml_has_secret_scan_job() -> None:
    """CI.yaml must contain the gitleaks secret-scan job."""
    wf = _load_yaml(CI_YAML)
    assert "secret-scan" in wf["jobs"], "CI.yaml must include a secret-scan job."


def test_ci_yaml_actions_are_sha_pinned() -> None:
    """Every action reference in CI.yaml must be pinned to a full 40-char commit SHA."""
    refs = _action_refs(CI_YAML)
    assert refs, "No action references found in CI.yaml."
    for full_ref, sha_part in refs:
        assert _SHA_RE.match(sha_part), (
            f"CI.yaml: '{full_ref}' is not SHA-pinned — use a full 40-char commit hash."
        )


def test_pipy_yml_actions_are_sha_pinned() -> None:
    """Every action reference in PiPy.yml must be pinned to a full 40-char commit SHA."""
    refs = _action_refs(PIPY_YML)
    assert refs, "No action references found in PiPy.yml."
    for full_ref, sha_part in refs:
        assert _SHA_RE.match(sha_part), (
            f"PiPy.yml: '{full_ref}' is not SHA-pinned — use a full 40-char commit hash."
        )


# ── 11.8  Locked resolver outputs / package index policy ────────────────────


def test_constraints_all_exists() -> None:
    """constraints-all.txt must exist as the locked all+dev dependency snapshot."""
    assert (REPO_ROOT / "constraints-all.txt").exists()


def test_constraints_all_pins_key_runtime_deps() -> None:
    """constraints-all.txt must pin every key runtime package from pyproject.toml."""
    content = (REPO_ROOT / "constraints-all.txt").read_text().lower()
    required = [
        "pydantic==",
        "fastapi==",
        "pyjwt==",
        "redis==",
        "httpx==",
        "sqlmodel==",
        "cryptography==",
        "prometheus-client==",
    ]
    for pin in required:
        assert pin in content, (
            f"constraints-all.txt is missing a pin for '{pin.rstrip('=')}'. "
            "Re-run pip-compile to regenerate."
        )


def test_constraints_no_custom_index_url() -> None:
    """Constraint files must reference only the public PyPI index."""
    for name in ("constraints.txt", "constraints-all.txt"):
        content = (REPO_ROOT / name).read_text()
        assert "--index-url" not in content, (
            f"{name}: must not contain --index-url (public PyPI only)."
        )
        assert "--extra-index-url" not in content, (
            f"{name}: must not contain --extra-index-url (public PyPI only)."
        )
