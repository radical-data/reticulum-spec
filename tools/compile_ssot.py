#!/usr/bin/env python3
"""
compile_ssot.py — Generate human-readable spec from SSOT YAML.

Outputs under spec/generated/ (plan section 10):
- reticulum-wire-format.md (full spec by atom order)
- constants.md (constants table by ID)
- contexts.md (from atoms tagged context, sorted by numeric value)
- layouts.md (byte/bit diagrams)
- traceability.md (every atom ID exactly once)
- manifest.json (required: ssot_version, ssot_content_sha256, source_commit, generated_at; optional generated_files)

Hard rule: No timestamps in generated Markdown; only generated_at in manifest.json.
Same SSOT → byte-identical Markdown (reproducible).
"""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_ssot(path: Path):
    """Load SSOT with ruamel.yaml to preserve ordering when round-tripping."""
    try:
        from ruamel.yaml import YAML
        yaml = YAML()
        yaml.preserve_quotes = True
        with open(path, encoding="utf-8") as f:
            return yaml.load(f)
    except ImportError:
        import yaml
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ssot_path = repo_root / "spec" / "reticulum-wire-format.ssot.yaml"
    out_dir = repo_root / "spec" / "generated"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ssot_path.is_file():
        print(f"SSOT not found: {ssot_path}", file=sys.stderr)
        return 1

    raw_ssot = ssot_path.read_bytes()
    ssot_content_sha256 = hashlib.sha256(raw_ssot).hexdigest()
    data = load_ssot(ssot_path)
    if not data:
        print("SSOT is empty or invalid", file=sys.stderr)
        return 1

    spec_meta = data.get("spec_meta") or {}
    atoms = data.get("atoms") or []
    spec_id = spec_meta.get("spec_id", "reticulum-wire-format")
    ssot_version = spec_meta.get("ssot_version", "0.0.0")
    sot = spec_meta.get("source_of_truth") or {}
    rev = sot.get("revision") or {}
    source_commit = (rev.get("commit") or "").strip()

    # Version bump enforcement: if manifest exists and ssot_version unchanged but content hash changed, fail
    manifest_path = out_dir / "manifest.json"
    if manifest_path.is_file():
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            if manifest.get("ssot_version") == ssot_version and manifest.get("ssot_content_sha256") != ssot_content_sha256:
                print("SSOT changed without version bump; bump ssot_version", file=sys.stderr)
                return 1
        except Exception:
            pass

    # No timestamps in Markdown; only in manifest
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. reticulum-wire-format.md — full spec by atom order
    lines = [f"# {spec_id.replace('-', ' ').title()} (generated from SSOT)", ""]
    for atom in atoms:
        aid = atom.get("id", "")
        kind = atom.get("kind", "")
        normative = atom.get("normative", "")
        statement = atom.get("statement", "")
        lines.append(f"## {aid}")
        lines.append(f"- **Kind:** {kind}")
        if normative:
            lines.append(f"- **Normative:** {normative}")
        lines.append(f"- **Statement:** {statement}")
        refs = atom.get("references") or []
        if refs:
            lines.append("- **References:**")
            for ref in refs:
                fpath = ref.get("file", "")
                sym = ref.get("symbol", "")
                ln = ref.get("lines") or {}
                lines.append(f"  - {fpath} ({sym}) lines {ln.get('start', '?')}-{ln.get('end', '?')}")
        if atom.get("value"):
            lines.append(f"- **Value:** {atom['value']}")
        if atom.get("layout", {}).get("fields"):
            lines.append("- **Layout fields:**")
            for f in atom["layout"]["fields"]:
                lines.append(f"  - {f.get('name')}: offset {f.get('offset')}, length {f.get('length')}")
        if atom.get("algorithm", {}).get("steps"):
            lines.append("- **Steps:**")
            for s in atom["algorithm"]["steps"]:
                lines.append(f"  - {s}")
        lines.append("")
    (out_dir / "reticulum-wire-format.md").write_text("\n".join(lines), encoding="utf-8")

    # 2. constants.md — table by ID
    const_atoms = [a for a in atoms if a.get("kind") == "constant" and "context" not in (a.get("tags") or [])]
    const_atoms.sort(key=lambda a: a.get("id", ""))
    const_lines = ["# Constants (from SSOT)", "", "| ID | Value | Unit | Statement |", "|----|-------|------|-----------|"]
    for a in const_atoms:
        val = a.get("value") or {}
        num = val.get("number", "")
        unit = val.get("unit", "")
        stmt = (a.get("statement") or "")[:80]
        const_lines.append(f"| {a.get('id', '')} | {num} | {unit} | {stmt} |")
    const_lines.append("")
    (out_dir / "constants.md").write_text("\n".join(const_lines), encoding="utf-8")

    # 3. contexts.md — from atoms tagged context, sorted by numeric value
    ctx_atoms = [a for a in atoms if a.get("kind") == "constant" and "context" in (a.get("tags") or [])]
    ctx_atoms.sort(key=lambda a: (a.get("value") or {}).get("number", 0))
    ctx_lines = ["# Packet context byte values (from SSOT)", "", "| Value | Hex | ID | Meaning |", "|-------|-----|----|---------|"]
    for a in ctx_atoms:
        val = a.get("value") or {}
        num = val.get("number", 0)
        hex_val = f"0x{num:02X}" if isinstance(num, int) else str(num)
        ctx_lines.append(f"| {num} | {hex_val} | {a.get('id', '')} | {a.get('statement', '')} |")
    ctx_lines.append("")
    (out_dir / "contexts.md").write_text("\n".join(ctx_lines), encoding="utf-8")

    # 4. layouts.md — byte/bit diagrams
    layout_atoms = [a for a in atoms if a.get("kind") == "layout"]
    layout_lines = ["# Layouts (from SSOT)", ""]
    for a in layout_atoms:
        layout_lines.append(f"## {a.get('id', '')}")
        layout_lines.append(a.get("statement", ""))
        fields = (a.get("layout") or {}).get("fields") or []
        if fields:
            layout_lines.append("| Field | Offset | Length |")
            layout_lines.append("|-------|--------|--------|")
            for f in fields:
                layout_lines.append(f"| {f.get('name')} | {f.get('offset')} | {f.get('length')} |")
        layout_lines.append("")
    (out_dir / "layouts.md").write_text("\n".join(layout_lines), encoding="utf-8")

    # 5. traceability.md — every atom ID exactly once
    trace_lines = ["# Traceability (atoms → references)", ""]
    for atom in atoms:
        aid = atom.get("id", "")
        trace_lines.append(f"## {aid}")
        for ref in (atom.get("references") or []):
            trace_lines.append(f"- {ref.get('file')} `{ref.get('symbol')}` lines {ref.get('lines', {}).get('start')}-{ref.get('lines', {}).get('end')} ({ref.get('role')})")
        trace_lines.append("")
    (out_dir / "traceability.md").write_text("\n".join(trace_lines), encoding="utf-8")

    # 6. manifest.json
    generated_files = {}
    for name in ["reticulum-wire-format.md", "constants.md", "contexts.md", "layouts.md", "traceability.md"]:
        p = out_dir / name
        if p.is_file():
            generated_files[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {
        "ssot_version": ssot_version,
        "ssot_content_sha256": ssot_content_sha256,
        "source_commit": source_commit,
        "generated_at": generated_at,
        "generated_files": generated_files,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
