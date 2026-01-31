#!/usr/bin/env python3
"""
compile_ssot.py — Generate human-readable spec from SSOT YAML.

Outputs under spec/generated/ (plan section 10):
- reticulum-wire-format.md (full spec by atom order)
- constants.md (constants table by ID)
- contexts.md (from atoms tagged context, sorted by numeric value)
- layouts.md (byte/bit diagrams)
- traceability.md (every atom ID exactly once)
- manifest.json (required: ssot_version, ssot_content_sha256, source_commit, generated_at; optional generated_files, excerpts_sha256)

Hard rule: No timestamps in generated Markdown; only generated_at in manifest.json.
Same SSOT → byte-identical Markdown (reproducible).
"""

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Extension -> fenced code block language (GitHub-style)
_EXCERPT_LANG = {".py": "py", ".md": "markdown", ".yaml": "yaml", ".yml": "yaml", ".txt": "text"}


def _lang_for_file(filepath: str) -> str:
    ext = Path(filepath).suffix.lower()
    return _EXCERPT_LANG.get(ext, "text")


def _normalise_excerpt_bytes(content: str, start: int, end: int) -> bytes:
    """Normalise excerpt for digest: \\r\\n -> \\n. start/end 1-indexed inclusive."""
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines(keepends=True)
    if not lines:
        return b""
    lo = max(0, start - 1)
    hi = min(len(lines), end)
    excerpt = "".join(lines[lo:hi])
    return excerpt.encode("utf-8")


def _excerpt_sha256(content: str, start: int, end: int) -> str:
    return hashlib.sha256(_normalise_excerpt_bytes(content, start, end)).hexdigest()


def _read_excerpt_from_content(content: str, start: int, end: int) -> tuple[list[str], int]:
    """From normalised content, return (lines[start:end], first_line_1based)."""
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines()
    n = len(lines)
    lo = max(0, start - 1)
    hi = min(n, end)
    return lines[lo:hi], start


def _read_excerpt(vendor_root: Path, filepath: str, start: int, end: int) -> tuple[list[str], int]:
    """Read lines start..end (1-indexed inclusive) from vendor file. Returns (list of line strings, first_line_1based)."""
    path = vendor_root / filepath
    raw = path.read_text(encoding="utf-8", errors="replace")
    return _read_excerpt_from_content(raw, start, end)


def _format_excerpt_with_line_numbers(lines: list[str], first_line_one_indexed: int) -> str:
    """Prefix each line with NNN: for visual mapping to lines.start/end."""
    return "\n".join(f"{first_line_one_indexed + i}: {line}" for i, line in enumerate(lines))


def _ensure_vendor_pinned(repo_root: Path, expected_commit: str, atoms: list) -> Path | None:
    """
    If atoms is non-empty, require vendor/reticulum-source to exist and HEAD == expected_commit.
    Returns vendor_root Path or None (caller should exit 1 after printing error).
    """
    if not atoms:
        return None
    vendor_root = repo_root / "vendor" / "reticulum-source"
    if not vendor_root.is_dir():
        print("vendor/reticulum-source/ not found; cannot render inline excerpts. Populate vendor and checkout the SSOT commit.", file=sys.stderr)
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(vendor_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("vendor/reticulum-source/ git rev-parse failed; ensure it is a git checkout.", file=sys.stderr)
        return None
    head = (out.stdout or "").strip()
    if head != expected_commit:
        print(
            f"vendor/reticulum-source/ is at {head or '(not a git repo)'}, expected manifest.repo_revision {expected_commit}. Checkout the pinned commit.",
            file=sys.stderr,
        )
        return None
    return vendor_root


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
    manifest = data.get("manifest") or {}
    atoms = data.get("atoms") or []
    spec_id = spec_meta.get("spec_id", "reticulum-wire-format")
    ssot_version = spec_meta.get("ssot_version", "0.0.0")
    source_commit = (manifest.get("repo_revision") or "").strip()
    if not source_commit:
        print("manifest.repo_revision is required.", file=sys.stderr)
        return 1

    # Fail fast if atoms exist but vendor checkout missing or wrong commit (excerpts must be from pinned revision)
    vendor_root = _ensure_vendor_pinned(repo_root, source_commit, atoms)
    if atoms and vendor_root is None:
        return 1

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

    # 1. reticulum-wire-format.md — full spec by atom order (with inline excerpts) + excerpts_sha256 for manifest
    excerpts_sha256 = {}
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
            for ref_idx, ref in enumerate(refs):
                fpath = ref.get("file", "")
                sym = ref.get("symbol", "")
                ln = ref.get("lines") or {}
                start_ln = ln.get("start")
                end_ln = ln.get("end")
                role = ref.get("role", "")
                ref_line = f"  - {fpath} (`{sym}`) lines {start_ln or '?'}–{end_ln or '?'} ({role})"
                lines.append(ref_line)
                if vendor_root and start_ln is not None and end_ln is not None:
                    try:
                        path = vendor_root / fpath
                        content = path.read_text(encoding="utf-8", errors="replace")
                        start_i, end_i = int(start_ln), int(end_ln)
                        all_lines = content.replace("\r\n", "\n").replace("\r", "\n").splitlines()
                        n_lines = len(all_lines)
                        excerpt_lines, first_ln = _read_excerpt_from_content(content, start_i, end_i)
                        excerpt_body = _format_excerpt_with_line_numbers(excerpt_lines, first_ln)
                        lang = _lang_for_file(fpath)
                        summary_label = f"Show code: {fpath}:{start_ln}–{end_ln} — {sym} — {role}"
                        lines.append("    <details>")
                        lines.append(f"      <summary>{summary_label}</summary>")
                        lines.append("")
                        lines.append(f"```{lang}")
                        lines.append(excerpt_body)
                        lines.append("```")
                        lines.append("")
                        lines.append("    </details>")
                        # Optional: ±10 lines context with >> marker on referenced span
                        ctx_start = max(1, start_i - 10)
                        ctx_end = min(n_lines, end_i + 10)
                        ctx_lines = all_lines[ctx_start - 1 : ctx_end]
                        ctx_parts = []
                        for i, line in enumerate(ctx_lines):
                            ln = ctx_start + i
                            marker = ">> " if start_i <= ln <= end_i else "   "
                            ctx_parts.append(f"{marker}{ln}: {line}")
                        lines.append("    <details>")
                        lines.append("      <summary>Show ±10 lines context</summary>")
                        lines.append("")
                        lines.append(f"```{lang}")
                        lines.append("\n".join(ctx_parts))
                        lines.append("```")
                        lines.append("")
                        lines.append("    </details>")
                        excerpts_sha256[f"{aid}#{ref_idx}"] = _excerpt_sha256(content, start_i, end_i)
                    except (ValueError, OSError):
                        pass
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
        stmt = (a.get("statement") or "")
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
            ln = ref.get("lines") or {}
            trace_lines.append(f"- {ref.get('file')} `{ref.get('symbol')}` lines {ln.get('start')}-{ln.get('end')} ({ref.get('role')})")
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
    if excerpts_sha256:
        manifest["excerpts_sha256"] = excerpts_sha256
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
