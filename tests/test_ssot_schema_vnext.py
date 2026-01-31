"""
Schema tests: manifest.repo_revision, no repo_revision/excerpt_hash in atoms.

- New payload (manifest, refs without repo_revision/excerpt_hash) passes schema.
- ref.repo_revision or ref.excerpt_hash → schema validation fails.
"""

import json
from pathlib import Path

import pytest


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "spec" / "schema" / "reticulum-wire-format.ssot.schema.json"


def _load_yaml(path: Path):
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        pytest.skip("PyYAML required")


def test_new_payload_passes_schema():
    """Payload with manifest.repo_revision and refs without repo_revision/excerpt_hash passes JSON schema."""
    path = FIXTURES_DIR / "ssot_vnext_clean.yaml"
    data = _load_yaml(path)
    assert data is not None
    assert data.get("manifest", {}).get("repo_revision") == "286a78ef8c58ca4503af2b0211b3a2d7e385467c"
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    import jsonschema
    jsonschema.validate(instance=data, schema=schema)


def test_new_payload_rejects_ref_repo_revision():
    """Schema rejects ref.repo_revision (additionalProperties)."""
    path = FIXTURES_DIR / "ssot_vnext_clean.yaml"
    data = _load_yaml(path)
    assert data is not None
    data["atoms"][0]["references"][0]["repo_revision"] = "286a78ef8c58ca4503af2b0211b3a2d7e385467c"
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    import jsonschema
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=data, schema=schema)


def test_new_payload_rejects_ref_excerpt_hash():
    """Schema rejects ref.excerpt_hash (additionalProperties)."""
    path = FIXTURES_DIR / "ssot_vnext_clean.yaml"
    data = _load_yaml(path)
    assert data is not None
    data["atoms"][0]["references"][0]["excerpt_hash"] = "a" * 64
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    import jsonschema
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=data, schema=schema)
