#!/usr/bin/env python3
"""
generate_vectors.py — Deterministically generate conformance vectors from SSOT.

Design goals:
- Deterministic output (no timestamps; stable ordering; stable YAML formatting).
- Vectors are committed fixtures; generator is the reproducible way to update them.
- Pull key constants from SSOT atoms, so vectors stay aligned with spec changes.

Vectors generated:
- hashable_part.yaml
- signalling_bytes.yaml
- link_id_from_linkrequest.yaml
- ifac_masking.yaml (mask/unmask transform level; IFAC bytes treated as input)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from pathlib import Path
from typing import Any

# -----------------------------
# SSOT loading + atom lookup
# -----------------------------


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        from ruamel.yaml import YAML

        y = YAML(typ="safe")
        with open(path, encoding="utf-8") as f:
            data = y.load(f)
    except ImportError:
        try:
            import yaml

            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except ImportError as e:
            raise SystemExit("PyYAML or ruamel.yaml required. Run: uv sync") from e
    if not isinstance(data, dict):
        raise SystemExit(f"SSOT at {path} is not a YAML mapping")
    return data


def atom_value_number(ssot: dict[str, Any], atom_id: str) -> Any:
    """Return atoms[].value.number for given atom_id. Supports int or string (e.g. IFAC_SALT hex)."""
    for a in ssot.get("atoms") or []:
        if a.get("id") == atom_id:
            v = (a.get("value") or {}).get("number")
            if v is None:
                raise SystemExit(f"Atom {atom_id} has no value.number")
            return v
    raise SystemExit(f"Atom id not found: {atom_id}")


# -----------------------------
# Pure functions matching spec
# -----------------------------


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def truncated_hash_16_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:16]


def hashable_part(packet_bytes: bytes, header_type: int) -> bytes:
    """
    Spec: mask first byte with 0x0F; exclude hops (byte 1).
    HEADER_1: b0 + raw[2:]; HEADER_2: b0 + raw[18:].
    """
    if len(packet_bytes) < 2:
        return b""
    b0 = bytes([packet_bytes[0] & 0x0F])
    if header_type == 2:
        if len(packet_bytes) < 18:
            return b""
        return b0 + packet_bytes[18:]
    return b0 + packet_bytes[2:]


def encode_signalling_bytes(mtu: int, mode: int, mtu_mask: int = 0x1FFFFF) -> bytes:
    """
    3 bytes big-endian: byte0=(mode<<5)|(mtu>>16), byte1=(mtu>>8)&0xFF, byte2=mtu&0xFF.
    mtu masked to 21 bits, mode to 3 bits.
    """
    mtu = mtu & mtu_mask
    mode = mode & 0x07
    byte0 = (mode << 5) | (mtu >> 16)
    byte1 = (mtu >> 8) & 0xFF
    byte2 = mtu & 0xFF
    return bytes([byte0, byte1, byte2])


def decode_signalling_bytes(raw3: bytes, mtu_mask: int = 0x1FFFFF) -> tuple[int, int]:
    if len(raw3) != 3:
        raise ValueError("signalling bytes must be exactly 3 bytes")
    byte0, byte1, byte2 = raw3[0], raw3[1], raw3[2]
    mode = (byte0 >> 5) & 0x07
    mtu = ((byte0 & 0x1F) << 16) | (byte1 << 8) | byte2
    mtu = mtu & mtu_mask
    return mtu, mode


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Minimal HKDF (extract+expand) using HMAC-SHA256. Deterministic."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
        if counter > 255:
            raise ValueError("HKDF counter overflow")
    return out[:length]


def ifac_mask_transform(canonical_raw: bytes, ifac_bytes: bytes, ifac_key: bytes) -> bytes:
    """
    Spec: new_raw = (canonical_raw[0]|0x80, canonical_raw[1]) + ifac + canonical_raw[2:].
    mask = HKDF(length=len(new_raw), ikm=ifac, salt=ifac_key, info=b'').
    XOR mask into bytes [0], [1], and [2+ifac_size..end); leave [2..2+ifac_size) unchanged.
    byte0 after XOR: (xored_byte0 | 0x80).
    """
    if len(canonical_raw) < 2:
        raise ValueError("canonical_raw must be at least 2 bytes")
    ifac_size = len(ifac_bytes)
    new_raw = bytes([canonical_raw[0] | 0x80, canonical_raw[1]]) + ifac_bytes + canonical_raw[2:]
    mask = hkdf_sha256(ikm=ifac_bytes, salt=ifac_key, info=b"", length=len(new_raw))
    out = bytearray(new_raw)
    out[0] = (out[0] ^ mask[0]) | 0x80
    out[1] = out[1] ^ mask[1]
    for i in range(2 + ifac_size, len(out)):
        out[i] ^= mask[i]
    return bytes(out)


def ifac_unmask_transform(on_wire: bytes, ifac_size: int, ifac_key: bytes) -> bytes:
    """
    Inverse of ifac_mask_transform: extract ifac, derive mask, unmask, remove IFAC bytes and clear IFAC bit.
    """
    if len(on_wire) <= 2 + ifac_size:
        raise ValueError("on_wire too short")
    if (on_wire[0] & 0x80) != 0x80:
        raise ValueError("IFAC flag not set")
    ifac = on_wire[2 : 2 + ifac_size]
    mask = hkdf_sha256(ikm=ifac, salt=ifac_key, info=b"", length=len(on_wire))
    raw = bytearray(on_wire)
    raw[0] = (raw[0] ^ mask[0]) & 0x7F
    raw[1] ^= mask[1]
    for i in range(2 + ifac_size, len(raw)):
        raw[i] ^= mask[i]
    canonical = bytes([raw[0], raw[1]]) + bytes(raw[2 + ifac_size :])
    return canonical


# -----------------------------
# YAML writer (stable formatting, quoted hex)
# -----------------------------


def _hex_quoted(s: str) -> Any:
    """Emit hex as single-quoted YAML scalar for parser safety (avoid numeric interpretation, preserve leading zeros)."""
    try:
        from ruamel.yaml.scalarstring import SingleQuotedScalarString

        return SingleQuotedScalarString(s.lower())
    except ImportError:
        return s.lower()


def dump_yaml_stable(obj: dict[str, Any], path: Path) -> None:
    """Stable YAML output: ruamel round-trip, fixed indentation, no key sorting."""
    try:
        from ruamel.yaml import YAML

        y = YAML(typ="rt")
        y.preserve_quotes = True
        y.indent(mapping=2, sequence=4, offset=2)
        y.width = 4096
    except ImportError as e:
        raise SystemExit("ruamel.yaml required for stable dump. Run: uv sync") from e
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        y.dump(obj, f)


# -----------------------------
# Vector generation
# -----------------------------


def gen_hashable_part_vectors() -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []

    # HEADER_1 minimal: 19 bytes, all zeros
    packet_hex = "00" * 19
    packet = bytes.fromhex(packet_hex)
    hp = hashable_part(packet, header_type=1)
    vectors.append(
        {
            "name": "HEADER_1_minimal",
            "description": "Minimal HEADER_1: flags=0, hops=0, dest_hash=16 zeros, context=0. Total 19 bytes.",
            "packet_hex": _hex_quoted(packet_hex),
            "header_type": 1,
            "expected_hashable_hex": _hex_quoted(hp.hex()),
            "expected_sha256_hex": _hex_quoted(sha256_hex(hp)),
        }
    )

    # HEADER_2 minimal: 38 bytes (35 header + 3 payload)
    packet_hex = "40" + "00" * 37
    packet = bytes.fromhex(packet_hex)
    hp = hashable_part(packet, header_type=2)
    vectors.append(
        {
            "name": "HEADER_2_minimal",
            "description": "Minimal HEADER_2: flags=0x40, hops=0, transport_id=16 zeros, dest_hash=16 zeros, context=0; plus 3 bytes payload.",
            "packet_hex": _hex_quoted(packet_hex),
            "header_type": 2,
            "expected_hashable_hex": _hex_quoted(hp.hex()),
            "expected_sha256_hex": _hex_quoted(sha256_hex(hp)),
        }
    )

    # HEADER_1 with upper bits set (IFAC 0x80, header-type 0x40, context 0x20) — low nibble mask 0x0F
    packet_hex = "e0" + "00" * 18  # flags=0xE0, rest zeros
    packet = bytes.fromhex(packet_hex)
    hp = hashable_part(packet, header_type=1)
    vectors.append(
        {
            "name": "HEADER_1_flags_upper_bits",
            "description": "HEADER_1 flags=0xE0 (IFAC|header-type|context); hashable byte0 masked to 0x00.",
            "packet_hex": _hex_quoted(packet_hex),
            "header_type": 1,
            "expected_hashable_hex": _hex_quoted(hp.hex()),
            "expected_sha256_hex": _hex_quoted(sha256_hex(hp)),
        }
    )

    # HEADER_2 with upper bits, zero payload (35 bytes)
    packet_hex = "40" + "00" * 34
    packet = bytes.fromhex(packet_hex)
    hp = hashable_part(packet, header_type=2)
    vectors.append(
        {
            "name": "HEADER_2_zero_payload",
            "description": "HEADER_2 minimal header 35 bytes, no payload.",
            "packet_hex": _hex_quoted(packet_hex),
            "header_type": 2,
            "expected_hashable_hex": _hex_quoted(hp.hex()),
            "expected_sha256_hex": _hex_quoted(sha256_hex(hp)),
        }
    )

    return {"vectors": vectors}


def gen_signalling_vectors(ssot: dict[str, Any]) -> dict[str, Any]:
    mtu_mask = int(atom_value_number(ssot, "RNS.LNK.CONST.MTU_BYTEMASK"))
    mode_mask_val = atom_value_number(ssot, "RNS.LNK.CONST.MODE_BYTEMASK")
    mode_mask = int(mode_mask_val) if isinstance(mode_mask_val, (int, float)) else 0xE0
    link_mtu_size = int(atom_value_number(ssot, "RNS.LNK.CONST.LINK_MTU_SIZE"))
    if link_mtu_size != 3:
        raise SystemExit("SSOT says LINK_MTU_SIZE != 3; generator expects 3-byte signalling")

    vectors: list[dict[str, Any]] = []
    mtu_values = [0, 1, 500, 2047, 65535, mtu_mask]
    mode_values = list(range(8))

    for mtu in mtu_values:
        for mode in mode_values:
            name_safe = f"encode_mtu{mtu}_mode{mode}"
            raw = encode_signalling_bytes(mtu, mode, mtu_mask)
            vectors.append(
                {
                    "name": name_safe,
                    "mtu": mtu,
                    "mode": mode,
                    "expected_bytes_hex": _hex_quoted(raw.hex()),
                }
            )
    for mtu in mtu_values:
        for mode in mode_values:
            raw = encode_signalling_bytes(mtu, mode, mtu_mask)
            name_decode = f"decode_mtu{mtu}_mode{mode}"
            vectors.append(
                {
                    "name": name_decode,
                    "bytes_hex": _hex_quoted(raw.hex()),
                    "expected_mtu": mtu,
                    "expected_mode": mode,
                }
            )

    # Overflow: MTU beyond 21-bit masked to 0x1FFFFF
    overflow_mtu = 0x200000
    raw_overflow = encode_signalling_bytes(overflow_mtu, 0, mtu_mask)
    mtu_decoded, mode_decoded = decode_signalling_bytes(raw_overflow, mtu_mask)
    vectors.append(
        {
            "name": "encode_mtu_overflow_21bit",
            "description": "MTU 0x200000 (22nd bit set) masked to 21 bits; encodes as 0.",
            "mtu": overflow_mtu,
            "mode": 0,
            "expected_bytes_hex": _hex_quoted(raw_overflow.hex()),
        }
    )
    vectors.append(
        {
            "name": "decode_mtu_overflow_21bit",
            "bytes_hex": _hex_quoted(raw_overflow.hex()),
            "expected_mtu": mtu_decoded,
            "expected_mode": mode_decoded,
        }
    )

    return {
        "meta": {
            "mtu_bytemask": mtu_mask,
            "mode_bytemask": mode_mask,
            "link_mtu_size": link_mtu_size,
        },
        "vectors": vectors,
    }


def gen_link_id_vectors(ssot: dict[str, Any]) -> dict[str, Any]:
    ecpubsize = int(atom_value_number(ssot, "RNS.LNK.CONST.ECPUBSIZE"))
    if ecpubsize != 64:
        raise SystemExit("SSOT ECPUBSIZE != 64; generator expects 64 for strip threshold")

    vectors: list[dict[str, Any]] = []
    # Case 1: 64 bytes hashable part, data_len=64 → no strip
    base_64 = bytes.fromhex("00" * 64)
    link_id_hex = truncated_hash_16_bytes(base_64).hex()
    data_len_64 = len(base_64)
    assert data_len_64 == 64
    vectors.append(
        {
            "name": "linkrequest_without_signalling",
            "description": "LINKREQUEST: hashable part 64 bytes; data_len=64, no strip.",
            "hashable_part_before_strip_hex": _hex_quoted(base_64.hex()),
            "data_len": data_len_64,
            "expected_link_id_hex": _hex_quoted(link_id_hex),
        }
    )
    # Case 2: same 64-byte prefix + 3 signalling bytes, data_len=67 → strip last 3
    base_67 = base_64 + bytes.fromhex("aabbcc")
    data_len_67 = len(base_67)
    assert data_len_67 == 67
    stripped = base_67[:64]
    link_id_stripped_hex = truncated_hash_16_bytes(stripped).hex()
    assert link_id_stripped_hex == link_id_hex
    assert data_len_67 == len(base_67), "data_len must equal len(hashable_part_before_strip)"
    vectors.append(
        {
            "name": "linkrequest_with_signalling",
            "description": "Same 64-byte hashable prefix + 3 signalling bytes; data_len=67, strip last 3 → same link_id.",
            "hashable_part_before_strip_hex": _hex_quoted(base_67.hex()),
            "data_len": data_len_67,
            "expected_link_id_hex": _hex_quoted(link_id_stripped_hex),
        }
    )
    # Stability: same expected_link_id_hex for both
    vectors.append(
        {
            "name": "link_id_stability",
            "description": "Stability: identical hashable part after strip → identical link_id.",
            "hashable_part_before_strip_hex": _hex_quoted(base_64.hex()),
            "data_len": data_len_64,
            "expected_link_id_hex": _hex_quoted(link_id_hex),
        }
    )
    return {"vectors": vectors}


IFAC_KEY_BYTES = (
    32  # Vectors use 32-byte ifac_key (mask derivation salt). Spec IFAC key derivation may use 64 for Identity.
)


def gen_ifac_masking_vectors(ssot: dict[str, Any]) -> dict[str, Any]:
    _ = atom_value_number(ssot, "RNS.IFAC.CONST.IFAC_SALT")

    vectors: list[dict[str, Any]] = []

    # Case 1: canonical 19 bytes, ifac 1 byte 0x00, ifac_key all-zero 32 bytes
    canonical = bytes.fromhex("00" * 19)
    ifac = bytes.fromhex("00")
    ifac_key = bytes.fromhex("00" * 32)
    assert len(ifac_key) == IFAC_KEY_BYTES, "ifac_key must be 32 bytes"
    assert len(ifac) == 1
    on_wire = ifac_mask_transform(canonical, ifac, ifac_key)
    recovered = ifac_unmask_transform(on_wire, ifac_size=len(ifac), ifac_key=ifac_key)
    vectors.append(
        {
            "name": "canonical19_ifac1_key0",
            "description": "Canonical 19 bytes; IFAC=0x00; ifac_key=32 zero bytes; mask/unmask round-trip.",
            "canonical_packet_hex": _hex_quoted(canonical.hex()),
            "ifac_bytes_hex": _hex_quoted(ifac.hex()),
            "ifac_key_hex": _hex_quoted(ifac_key.hex()),
            "expected_on_wire_hex": _hex_quoted(on_wire.hex()),
            "expected_recovered_canonical_hex": _hex_quoted(recovered.hex()),
        }
    )

    # Case 2: non-zero canonical, ifac 0xa5, ifac_key 0x11*32
    canonical2 = bytes.fromhex("40" + "01" * 18)
    ifac2 = bytes.fromhex("a5")
    ifac_key2 = bytes.fromhex("11" * 32)
    assert len(ifac_key2) == IFAC_KEY_BYTES
    assert len(ifac2) == 1
    on_wire2 = ifac_mask_transform(canonical2, ifac2, ifac_key2)
    recovered2 = ifac_unmask_transform(on_wire2, ifac_size=len(ifac2), ifac_key=ifac_key2)
    vectors.append(
        {
            "name": "canonical19_ifac1_key11",
            "description": "Non-zero canonical; IFAC=0xa5; ifac_key=0x11*32; transform determinism + round-trip.",
            "canonical_packet_hex": _hex_quoted(canonical2.hex()),
            "ifac_bytes_hex": _hex_quoted(ifac2.hex()),
            "ifac_key_hex": _hex_quoted(ifac_key2.hex()),
            "expected_on_wire_hex": _hex_quoted(on_wire2.hex()),
            "expected_recovered_canonical_hex": _hex_quoted(recovered2.hex()),
        }
    )

    # Case 3: ifac_size 8 bytes, non-zero mask
    canonical3 = bytes.fromhex("00" * 25)
    ifac3 = bytes.fromhex("deadbeefcafebabe")
    ifac_key3 = bytes.fromhex("aa" * 32)
    assert len(ifac_key3) == IFAC_KEY_BYTES
    assert len(ifac3) == 8
    on_wire3 = ifac_mask_transform(canonical3, ifac3, ifac_key3)
    recovered3 = ifac_unmask_transform(on_wire3, ifac_size=len(ifac3), ifac_key=ifac_key3)
    vectors.append(
        {
            "name": "canonical25_ifac8_keyaa",
            "description": "Canonical 25 bytes; IFAC 8 bytes; non-zero ifac_key; round-trip.",
            "canonical_packet_hex": _hex_quoted(canonical3.hex()),
            "ifac_bytes_hex": _hex_quoted(ifac3.hex()),
            "ifac_key_hex": _hex_quoted(ifac_key3.hex()),
            "expected_on_wire_hex": _hex_quoted(on_wire3.hex()),
            "expected_recovered_canonical_hex": _hex_quoted(recovered3.hex()),
        }
    )

    # Case 4: ifac_size 16 bytes
    canonical4 = bytes.fromhex("40" + "00" * 34)
    ifac4 = bytes.fromhex("00" * 15 + "01")
    ifac_key4 = bytes.fromhex("11" * 32)
    assert len(ifac_key4) == IFAC_KEY_BYTES
    assert len(ifac4) == 16
    on_wire4 = ifac_mask_transform(canonical4, ifac4, ifac_key4)
    recovered4 = ifac_unmask_transform(on_wire4, ifac_size=len(ifac4), ifac_key=ifac_key4)
    vectors.append(
        {
            "name": "canonical35_ifac16",
            "description": "HEADER_2-style 35 bytes; IFAC 16 bytes; round-trip.",
            "canonical_packet_hex": _hex_quoted(canonical4.hex()),
            "ifac_bytes_hex": _hex_quoted(ifac4.hex()),
            "ifac_key_hex": _hex_quoted(ifac_key4.hex()),
            "expected_on_wire_hex": _hex_quoted(on_wire4.hex()),
            "expected_recovered_canonical_hex": _hex_quoted(recovered4.hex()),
        }
    )

    return {
        "meta": {
            "hkdf_note": "Mask derivation (RFC 5869): HKDF-Extract(salt=ifac_key, IKM=ifac_bytes); HKDF-Expand(PRK, info=b'', L=len(packet)).",
        },
        "vectors": vectors,
    }


# -----------------------------
# Main
# -----------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate conformance vectors from SSOT.")
    ap.add_argument("--ssot", default="spec/reticulum-wire-format.ssot.yaml", help="Path to SSOT YAML")
    ap.add_argument("--vectors-dir", default="tests/vectors", help="Output directory for vector YAML files")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    ssot_path = repo_root / args.ssot
    vectors_dir = repo_root / args.vectors_dir

    if not ssot_path.is_file():
        print(f"SSOT not found: {ssot_path}", file=sys.stderr)
        return 1

    ssot = load_yaml(ssot_path)
    manifest = ssot.get("manifest") or {}
    source_commit = (manifest.get("repo_revision") or "").strip()
    if not source_commit:
        print("manifest.repo_revision is required.", file=sys.stderr)
        return 1
    hashable = gen_hashable_part_vectors()
    signalling = gen_signalling_vectors(ssot)
    link_id = gen_link_id_vectors(ssot)
    ifac_masking = gen_ifac_masking_vectors(ssot)

    dump_yaml_stable(hashable, vectors_dir / "hashable_part.yaml")
    dump_yaml_stable(signalling, vectors_dir / "signalling_bytes.yaml")
    dump_yaml_stable(link_id, vectors_dir / "link_id_from_linkrequest.yaml")
    dump_yaml_stable(ifac_masking, vectors_dir / "ifac_masking.yaml")

    return 0


if __name__ == "__main__":
    sys.exit(main())
