"""
Test runner for SSOT conformance test vectors (plan section 11).
CI runs: pytest -q
Tests MUST fail if required expected fields are missing.
Real assertions: hashable bytes, SHA-256, link_id stability, signalling encode/decode, IFAC round-trip.
"""

import hashlib
from pathlib import Path

import pytest


VECTORS_DIR = Path(__file__).resolve().parent / "vectors"


def _load_yaml(path: Path):
    try:
        import yaml
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        pytest.skip("PyYAML required for vector tests")


def _hashable_part(packet_bytes: bytes, header_type: int) -> bytes:
    """Spec: mask first byte with 0x0f; HEADER_1 raw[2:], HEADER_2 raw[18:]."""
    if len(packet_bytes) < 2:
        return b""
    masked = bytes([packet_bytes[0] & 0x0F])
    if header_type == 2:
        if len(packet_bytes) < 18:
            return b""
        return masked + packet_bytes[18:]
    return masked + packet_bytes[2:]


# --- hashable_part ---


def test_hashable_part_vectors_required_fields():
    """All hashable_part vectors must have expected_hashable_hex and expected_sha256_hex."""
    data = _load_yaml(VECTORS_DIR / "hashable_part.yaml")
    assert data is not None, "hashable_part.yaml missing"
    vectors = data.get("vectors") or []
    assert len(vectors) >= 1, "at least one hashable_part vector required"
    for v in vectors:
        assert v.get("expected_hashable_hex"), f"vector {v.get('name')} missing expected_hashable_hex"
        assert v.get("expected_sha256_hex"), f"vector {v.get('name')} missing expected_sha256_hex"


def test_hashable_part_hashable_bytes_match():
    """Computed hashable part must match expected_hashable_hex."""
    data = _load_yaml(VECTORS_DIR / "hashable_part.yaml")
    if not data:
        pytest.skip("no hashable_part.yaml")
    for v in (data.get("vectors") or []):
        packet_hex = v.get("packet_hex")
        expected_hex = v.get("expected_hashable_hex")
        if not packet_hex or not expected_hex:
            continue
        packet = bytes.fromhex(packet_hex)
        header_type = v.get("header_type", 1)
        computed = _hashable_part(packet, header_type)
        assert computed.hex() == expected_hex, f"hashable bytes mismatch for {v.get('name')}"


def test_hashable_part_sha256_matches():
    """SHA-256 of expected_hashable_hex must equal expected_sha256_hex."""
    data = _load_yaml(VECTORS_DIR / "hashable_part.yaml")
    if not data:
        pytest.skip("no hashable_part.yaml")
    for v in (data.get("vectors") or []):
        expected_hex = v.get("expected_hashable_hex")
        expected_sha = v.get("expected_sha256_hex")
        assert expected_hex, f"vector {v.get('name')} missing expected_hashable_hex"
        assert expected_sha, f"vector {v.get('name')} missing expected_sha256_hex"
        raw = bytes.fromhex(expected_hex)
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == expected_sha, f"SHA-256 mismatch for {v.get('name')}"


# --- ifac_masking ---


def test_ifac_masking_required_fields():
    """All IFAC vectors must have canonical_packet_hex, expected_on_wire_hex, expected_recovered_canonical_hex."""
    data = _load_yaml(VECTORS_DIR / "ifac_masking.yaml")
    assert data is not None
    vectors = data.get("vectors") or []
    assert len(vectors) >= 1
    for v in vectors:
        assert v.get("canonical_packet_hex"), f"vector {v.get('name')} missing canonical_packet_hex"
        assert v.get("expected_on_wire_hex"), f"vector {v.get('name')} missing expected_on_wire_hex"
        assert v.get("expected_recovered_canonical_hex"), f"vector {v.get('name')} missing expected_recovered_canonical_hex"


def test_ifac_masking_recovered_equals_canonical():
    """expected_recovered_canonical_hex must equal canonical_packet_hex (round-trip consistency)."""
    data = _load_yaml(VECTORS_DIR / "ifac_masking.yaml")
    if not data:
        pytest.skip("no ifac_masking.yaml")
    for v in (data.get("vectors") or []):
        canonical = v.get("canonical_packet_hex")
        recovered = v.get("expected_recovered_canonical_hex")
        assert canonical, f"vector {v.get('name')} missing canonical_packet_hex"
        assert recovered, f"vector {v.get('name')} missing expected_recovered_canonical_hex"
        assert recovered == canonical, f"IFAC round-trip: recovered must equal canonical for {v.get('name')}"


# --- link_id_from_linkrequest ---


def test_link_id_required_fields():
    """link_id vectors must have expected_link_id_hex (or hashable_part_hex for stability)."""
    data = _load_yaml(VECTORS_DIR / "link_id_from_linkrequest.yaml")
    assert data is not None
    vectors = data.get("vectors") or []
    assert len(vectors) >= 1
    for v in vectors:
        assert v.get("expected_link_id_hex") or v.get("hashable_part_hex"), f"vector {v.get('name')} missing expected_link_id_hex or hashable_part_hex"


def test_link_id_stability():
    """Link ID must be stable: same hashable part (before signalling strip) -> same link_id."""
    data = _load_yaml(VECTORS_DIR / "link_id_from_linkrequest.yaml")
    if not data:
        pytest.skip("no link_id_from_linkrequest.yaml")
    vectors = [v for v in (data.get("vectors") or []) if v.get("hashable_part_hex") and v.get("expected_link_id_hex")]
    for v in vectors:
        part_hex = (v["hashable_part_hex"] or "").strip()
        expected_id_raw = (v["expected_link_id_hex"] or "").strip()
        if len(expected_id_raw) < 32:
            pytest.fail(
                f"vector {v.get('name')}: expected_link_id_hex must be at least 32 hex chars, got {len(expected_id_raw)}"
            )
        expected_id = expected_id_raw[:32]
        part = bytes.fromhex(part_hex)
        full_hash = hashlib.sha256(part).hexdigest()
        link_id_hex = full_hash[:32]  # first 16 bytes = 32 hex chars
        assert link_id_hex == expected_id, f"link_id mismatch for {v.get('name')}"


# --- signalling_bytes ---


def test_signalling_required_fields():
    """Encode vectors need mtu, mode, expected_bytes_hex; decode vectors need bytes_hex, expected_mtu, expected_mode."""
    data = _load_yaml(VECTORS_DIR / "signalling_bytes.yaml")
    assert data is not None
    vectors = data.get("vectors") or []
    assert len(vectors) >= 1
    for v in vectors:
        if "expected_bytes_hex" in v:
            assert v.get("expected_bytes_hex"), f"vector {v.get('name')} has empty expected_bytes_hex"
        if "bytes_hex" in v and "expected_mtu" in v:
            assert v.get("expected_mtu") is not None, f"vector {v.get('name')} missing expected_mtu"
            assert v.get("expected_mode") is not None, f"vector {v.get('name')} missing expected_mode"


def test_signalling_decode():
    """Decode bytes_hex -> MTU and Mode must match expected_mtu and expected_mode."""
    data = _load_yaml(VECTORS_DIR / "signalling_bytes.yaml")
    if not data:
        pytest.skip("no signalling_bytes.yaml")
    for v in (data.get("vectors") or []):
        if "bytes_hex" not in v or "expected_mtu" not in v or "expected_mode" not in v:
            continue
        raw = bytes.fromhex(v["bytes_hex"])
        assert len(raw) == 3, f"signalling must be 3 bytes for {v.get('name')}"
        byte0, byte1, byte2 = raw[0], raw[1], raw[2]
        mode = (byte0 >> 5) & 0x07
        mtu = ((byte0 & 0x1F) << 16) | (byte1 << 8) | byte2
        assert mtu == v["expected_mtu"], f"MTU decode mismatch for {v.get('name')}"
        assert mode == v["expected_mode"], f"Mode decode mismatch for {v.get('name')}"


def test_signalling_encode():
    """Encode mtu+mode -> 3 bytes must match expected_bytes_hex."""
    data = _load_yaml(VECTORS_DIR / "signalling_bytes.yaml")
    if not data:
        pytest.skip("no signalling_bytes.yaml")
    for v in (data.get("vectors") or []):
        if "mtu" not in v or "mode" not in v or "expected_bytes_hex" not in v:
            continue
        mtu = int(v["mtu"]) & 0x1FFFFF
        mode = int(v["mode"]) & 0x07
        byte0 = (mode << 5) | (mtu >> 16)
        byte1 = (mtu >> 8) & 0xFF
        byte2 = mtu & 0xFF
        encoded = bytes([byte0, byte1, byte2]).hex()
        assert encoded == v["expected_bytes_hex"], f"signalling encode mismatch for {v.get('name')}"
