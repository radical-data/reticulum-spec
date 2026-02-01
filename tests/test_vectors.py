"""
Test runner for SSOT conformance test vectors (plan section 11).
CI runs: pytest -q
Tests MUST fail if required expected fields are missing.
Real assertions: hashable bytes, SHA-256, link_id stability (including strip rule),
signalling encode/decode, IFAC round-trip and on-wire/unmask.
Tests consume only fixtures; no generator or vendor imports.
"""

import hashlib
import hmac
from pathlib import Path

import pytest


VECTORS_DIR = Path(__file__).resolve().parent / "vectors"
REPO_ROOT = Path(__file__).resolve().parent.parent
ECPUBSIZE = 64


def _load_yaml(path: Path):
    """Load YAML with safe loader only. Do not use yaml.load() without Loader= — use safe_load."""
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


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF (extract+expand) with HMAC-SHA256. Spec-aligned for IFAC mask derivation."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _ifac_mask_transform(canonical_raw: bytes, ifac_bytes: bytes, ifac_key: bytes) -> bytes:
    """Spec: (byte0|0x80, byte1) + ifac + raw[2:]; mask = HKDF; XOR mask into [0],[1],[2+ifac_size..)."""
    if len(canonical_raw) < 2:
        raise ValueError("canonical_raw must be at least 2 bytes")
    ifac_size = len(ifac_bytes)
    new_raw = bytes([canonical_raw[0] | 0x80, canonical_raw[1]]) + ifac_bytes + canonical_raw[2:]
    mask = _hkdf_sha256(ikm=ifac_bytes, salt=ifac_key, info=b"", length=len(new_raw))
    out = bytearray(new_raw)
    out[0] = (out[0] ^ mask[0]) | 0x80
    out[1] = out[1] ^ mask[1]
    for i in range(2 + ifac_size, len(out)):
        out[i] ^= mask[i]
    return bytes(out)


def _ifac_unmask_transform(on_wire: bytes, ifac_size: int, ifac_key: bytes) -> bytes:
    """Spec: extract ifac, derive mask, unmask [0],[1],[2+ifac_size..); canonical = (byte0&0x7f, byte1) + raw[2+ifac_size:]."""
    if len(on_wire) <= 2 + ifac_size:
        raise ValueError("on_wire too short")
    if (on_wire[0] & 0x80) != 0x80:
        raise ValueError("IFAC flag not set")
    ifac = on_wire[2 : 2 + ifac_size]
    mask = _hkdf_sha256(ikm=ifac, salt=ifac_key, info=b"", length=len(on_wire))
    raw = bytearray(on_wire)
    raw[0] = (raw[0] ^ mask[0]) & 0x7F
    raw[1] ^= mask[1]
    for i in range(2 + ifac_size, len(raw)):
        raw[i] ^= mask[i]
    return bytes([raw[0], raw[1]]) + bytes(raw[2 + ifac_size :])


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


IFAC_KEY_BYTES = 32  # Vectors use 32-byte ifac_key (mask derivation salt).


def test_ifac_masking_required_fields():
    """All IFAC vectors must have canonical_packet_hex, ifac_bytes_hex, ifac_key_hex, expected_on_wire_hex, expected_recovered_canonical_hex."""
    data = _load_yaml(VECTORS_DIR / "ifac_masking.yaml")
    assert data is not None
    vectors = data.get("vectors") or []
    assert len(vectors) >= 1
    for v in vectors:
        assert v.get("canonical_packet_hex"), f"vector {v.get('name')} missing canonical_packet_hex"
        assert v.get("ifac_bytes_hex"), f"vector {v.get('name')} missing ifac_bytes_hex"
        assert v.get("ifac_key_hex"), f"vector {v.get('name')} missing ifac_key_hex"
        assert v.get("expected_on_wire_hex"), f"vector {v.get('name')} missing expected_on_wire_hex"
        assert v.get("expected_recovered_canonical_hex"), f"vector {v.get('name')} missing expected_recovered_canonical_hex"
        ifac_key_bytes = bytes.fromhex(v["ifac_key_hex"])
        assert len(ifac_key_bytes) == IFAC_KEY_BYTES, (
            f"vector {v.get('name')}: ifac_key_hex must decode to {IFAC_KEY_BYTES} bytes, got {len(ifac_key_bytes)}"
        )
        ifac_bytes = bytes.fromhex(v["ifac_bytes_hex"])
        assert len(ifac_bytes) >= 1, f"vector {v.get('name')}: ifac_bytes_hex must be at least 1 byte"


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


def test_ifac_on_wire_match():
    """Computed on-wire bytes (mask transform) must match expected_on_wire_hex."""
    data = _load_yaml(VECTORS_DIR / "ifac_masking.yaml")
    if not data:
        pytest.skip("no ifac_masking.yaml")
    for v in (data.get("vectors") or []):
        canonical_hex = v.get("canonical_packet_hex")
        ifac_hex = v.get("ifac_bytes_hex")
        key_hex = v.get("ifac_key_hex")
        expected_hex = v.get("expected_on_wire_hex")
        if not all((canonical_hex, ifac_hex, key_hex, expected_hex)):
            continue
        canonical = bytes.fromhex(canonical_hex)
        ifac = bytes.fromhex(ifac_hex)
        key = bytes.fromhex(key_hex)
        on_wire = _ifac_mask_transform(canonical, ifac, key)
        assert on_wire.hex() == expected_hex, f"IFAC on-wire mismatch for {v.get('name')}"


def test_ifac_unmask_match():
    """Computed recovered canonical (unmask transform) must match expected_recovered_canonical_hex."""
    data = _load_yaml(VECTORS_DIR / "ifac_masking.yaml")
    if not data:
        pytest.skip("no ifac_masking.yaml")
    for v in (data.get("vectors") or []):
        on_wire_hex = v.get("expected_on_wire_hex")
        ifac_hex = v.get("ifac_bytes_hex")
        key_hex = v.get("ifac_key_hex")
        expected_recovered = v.get("expected_recovered_canonical_hex")
        if not all((on_wire_hex, ifac_hex, key_hex, expected_recovered)):
            continue
        on_wire = bytes.fromhex(on_wire_hex)
        ifac_size = len(bytes.fromhex(ifac_hex))
        key = bytes.fromhex(key_hex)
        recovered = _ifac_unmask_transform(on_wire, ifac_size, key)
        assert recovered.hex() == expected_recovered, f"IFAC unmask mismatch for {v.get('name')}"


# --- link_id_from_linkrequest ---


def test_link_id_required_fields():
    """link_id vectors must have expected_link_id_hex and (hashable_part_before_strip_hex or hashable_part_hex)."""
    data = _load_yaml(VECTORS_DIR / "link_id_from_linkrequest.yaml")
    assert data is not None
    vectors = data.get("vectors") or []
    assert len(vectors) >= 1
    for v in vectors:
        assert v.get("expected_link_id_hex"), f"vector {v.get('name')} missing expected_link_id_hex"
        part_hex = v.get("hashable_part_before_strip_hex") or v.get("hashable_part_hex")
        assert part_hex, f"vector {v.get('name')} missing hashable_part_before_strip_hex or hashable_part_hex"


def test_link_id_strip_rule():
    """Link ID = first 16 bytes of SHA-256(stripped). When data_len > 64, strip last (data_len - 64) bytes."""
    data = _load_yaml(VECTORS_DIR / "link_id_from_linkrequest.yaml")
    if not data:
        pytest.skip("no link_id_from_linkrequest.yaml")
    for v in (data.get("vectors") or []):
        part_hex = (v.get("hashable_part_before_strip_hex") or v.get("hashable_part_hex") or "").strip()
        expected_id_raw = (v.get("expected_link_id_hex") or "").strip()
        if not part_hex or not expected_id_raw:
            continue
        if len(expected_id_raw) < 32:
            pytest.fail(
                f"vector {v.get('name')}: expected_link_id_hex must be at least 32 hex chars, got {len(expected_id_raw)}"
            )
        expected_id = expected_id_raw[:32]
        part = bytes.fromhex(part_hex)
        data_len = v.get("data_len")
        if data_len is not None:
            assert len(part) == data_len, (
                f"vector {v.get('name')}: data_len must equal len(hashable_part_before_strip): "
                f"data_len={data_len}, len(part)={len(part)}"
            )
        if data_len is not None and data_len > ECPUBSIZE:
            diff = data_len - ECPUBSIZE
            stripped = part[:-diff]
        else:
            stripped = part
        link_id_hex = hashlib.sha256(stripped).digest()[:16].hex()
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
    """Decode bytes_hex -> MTU and Mode must match expected_mtu and expected_mode; re-encode must match original 3 bytes."""
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
        # Re-encode must match original 3 bytes
        re_byte0 = (mode << 5) | (mtu >> 16)
        re_byte1 = (mtu >> 8) & 0xFF
        re_byte2 = mtu & 0xFF
        re_encoded = bytes([re_byte0, re_byte1, re_byte2])
        assert re_encoded == raw, f"signalling re-encode must match bytes_hex for {v.get('name')}"


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
