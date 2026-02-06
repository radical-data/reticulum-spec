#!/usr/bin/env python3
"""
extract_refs.py — Verify and optionally fill reference line ranges from pinned vendor checkout.

Bounded behaviour (plan section 4):
- Must NOT guess arbitrary ranges.
- May only fill lines.start/end if:
  1. Reference has a symbol.
  2. Symbol occurs exactly once in the file.
  3. Deterministic windowing:
     - Constants: single line containing symbol ± 2 lines.
     - Functions/classes: full def/class block (parse with ast for .py files).
- If symbol occurs more than once, MUST fail and require contractor to specify range manually.

Schema vNext: repo_revision lives on manifest only; refs must not have repo_revision or excerpt_hash.
- lines.start and lines.end are 1-indexed, inclusive.
"""

import argparse
import ast
import hashlib
import re
import sys
from pathlib import Path


def normalise_excerpt_bytes(content: str, start: int, end: int) -> bytes:
    """Compute excerpt bytes per plan section 3. start/end 1-indexed inclusive."""
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines(keepends=True)
    if not lines:
        return b""
    # 1-indexed inclusive -> 0-indexed slice [start-1:end]
    lo = max(0, start - 1)
    hi = min(len(lines), end)
    excerpt = "".join(lines[lo:hi])
    return excerpt.encode("utf-8")


def excerpt_hash(content: str, start: int, end: int) -> str:
    """Hex-encoded SHA-256 of excerpt bytes (plan section 3)."""
    raw = normalise_excerpt_bytes(content, start, end)
    return hashlib.sha256(raw).hexdigest()


def find_ast_def_ranges(content: str, symbol: str) -> list[tuple[int, int]]:
    """
    For .py content: find all FunctionDef/ClassDef/AsyncFunctionDef with node.name == symbol.
    Returns list of (start, end) 1-indexed inclusive. Empty if not .py or parse error.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    matches = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol:
                end = node.end_lineno if hasattr(node, "end_lineno") and node.end_lineno else node.lineno
                matches.append((node.lineno, end))
    return matches


def find_assignment_lines(content: str, symbol: str) -> list[int]:
    """
    Find line numbers (1-indexed) where symbol appears in assignment-ish form: ^SYMBOL\\s*=
    (or with leading whitespace). Used for constants when AST has no def match.
    """
    pattern = re.compile(r"^\s*" + re.escape(symbol) + r"\s*=", re.MULTILINE)
    lines = content.splitlines()
    result = []
    for i, line in enumerate(lines):
        if pattern.match(line):
            result.append(i + 1)
    return result


def find_symbol_line_ranges(content: str, symbol: str, filepath: str, kind_hint: str) -> list[tuple[int, int]]:
    """
    Find all (start, end) 1-indexed inclusive ranges where symbol appears (substring in line).
    Returns list of (start_line, end_line) for each occurrence. Used as last resort.
    """
    lines = content.splitlines()
    occurrences = []
    for i, line in enumerate(lines):
        if symbol in line:
            occurrences.append((i + 1, i + 1))  # 1-indexed
    return occurrences


def fill_range_constant(content: str, line_one_indexed: int, window: int = 2) -> tuple[int, int]:
    """Single line containing symbol ± window lines. 1-indexed inclusive (start, end)."""
    lines = content.splitlines()
    n = len(lines)
    lo = max(1, line_one_indexed - window)
    hi = min(n, line_one_indexed + window)
    return (lo, hi)


def fill_range_def_or_class(content: str, filepath: str, symbol: str) -> tuple[int, int] | None:
    """Full def/class block via ast. Returns (start, end) 1-indexed inclusive or None."""
    if not filepath.endswith(".py"):
        return None
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol:
                # ast line numbers are 1-indexed
                start = node.lineno
                end = node.end_lineno if hasattr(node, "end_lineno") and node.end_lineno else node.lineno
                return (start, end)
    return None


def fill_line_range(content: str, filepath: str, symbol: str, kind_hint: str) -> tuple[int, int] | None:
    """
    Deterministic windowing. Returns (start, end) 1-indexed inclusive or None.
    For .py: AST-first (FunctionDef/ClassDef by name), then assignment regex (^SYMBOL\\s*=),
    then substring with uniqueness. Fails (returns None) if ambiguous; caller must exit non-zero.
    """
    if filepath.endswith(".py"):
        # 1. AST-first: locate FunctionDef/ClassDef by exact node.name == symbol
        ast_matches = find_ast_def_ranges(content, symbol)
        if len(ast_matches) == 1:
            return ast_matches[0]
        if len(ast_matches) > 1:
            return None  # ambiguous
        # 2. No AST match: treat as constant, assignment-ish form
        assign_lines = find_assignment_lines(content, symbol)
        if len(assign_lines) == 1:
            return fill_range_constant(content, assign_lines[0], 2)
        if len(assign_lines) > 1:
            return None
        # 3. Fall back to substring; require uniqueness
        occurrences = find_symbol_line_ranges(content, symbol, filepath, kind_hint)
        if len(occurrences) != 1:
            return None
        return fill_range_constant(content, occurrences[0][0], 2)
    # Non-.py: substring with uniqueness
    occurrences = find_symbol_line_ranges(content, symbol, filepath, kind_hint)
    if len(occurrences) == 0 or len(occurrences) > 1:
        return None
    return fill_range_constant(content, occurrences[0][0], 2)


def verify_ref(vendor_root: Path, ref: dict, expected_commit: str) -> tuple[bool, str]:
    """
    Verify one reference: file exists, symbol in range. Schema vNext: no repo_revision/excerpt_hash on ref.
    Returns (ok, error_message).
    """
    filepath = ref.get("file")
    if not filepath:
        return (False, "reference missing 'file'")
    path = vendor_root / filepath
    if not path.is_file():
        return (False, f"file not found under vendor: {filepath}")
    # repo_revision is on manifest only; ref must not override it
    if ref.get("repo_revision") is not None and ref.get("repo_revision") != expected_commit:
        return (False, "repo_revision on ref does not match manifest.repo_revision")
    lines_obj = ref.get("lines")
    if not lines_obj or "start" not in lines_obj or "end" not in lines_obj:
        return (False, "reference missing lines.start/end")
    start, end = int(lines_obj["start"]), int(lines_obj["end"])
    if start > end:
        return (False, f"lines.start ({start}) > lines.end ({end})")
    content = path.read_text(encoding="utf-8", errors="replace")
    symbol = ref.get("symbol", "")
    # Check symbol appears in range
    excerpt_lines = content.replace("\r\n", "\n").splitlines()
    if start < 1 or end > len(excerpt_lines):
        return (False, f"lines [{start},{end}] out of range (file has {len(excerpt_lines)} lines)")
    slice_text = "\n".join(excerpt_lines[start - 1 : end])
    if symbol and symbol not in slice_text:
        return (False, f"symbol '{symbol}' not found in lines [{start},{end}]")
    # Schema vNext: no excerpt_hash on ref
    return (True, "")


def load_ssot(path: Path, for_write: bool = False):
    """Load SSOT. When for_write=True (--fill), MUST use ruamel.yaml for round-trip; fail if not available."""
    if for_write:
        try:
            from ruamel.yaml import YAML

            yaml = YAML()
            yaml.preserve_quotes = True
            with open(path, encoding="utf-8") as f:
                return yaml.load(f), yaml
        except ImportError:
            print("ruamel.yaml required for --fill (SSOT write); run: uv sync", file=sys.stderr)
            sys.exit(1)
    try:
        import yaml

        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f), None
    except ImportError:
        print("PyYAML required; run: uv sync", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify/fill SSOT references from vendor checkout.")
    parser.add_argument("--ssot", default="spec/reticulum-wire-format.ssot.yaml", help="SSOT YAML path")
    parser.add_argument("--vendor", default="vendor/reticulum-source", help="Vendor checkout root")
    parser.add_argument("--fill", action="store_true", help="Fill missing line ranges (when symbol unique)")
    parser.add_argument("--no-write", action="store_true", help="Only verify; do not write SSOT")
    args = parser.parse_args()
    vendor_root = Path(args.vendor)
    if not vendor_root.is_dir():
        print(f"Vendor root not found: {vendor_root}", file=sys.stderr)
        return 1
    ssot_path = Path(args.ssot)
    if not ssot_path.is_file():
        print(f"SSOT not found: {ssot_path}", file=sys.stderr)
        return 1
    data, ruamel_yaml = load_ssot(ssot_path, for_write=args.fill and not args.no_write)
    manifest = data.get("manifest") or {}
    expected_commit = (manifest.get("repo_revision") or "").strip()
    if not expected_commit:
        print("manifest.repo_revision is required; set it to the vendor commit.", file=sys.stderr)
        return 1
    atoms = data.get("atoms") or []
    errors = []
    modified = False
    for atom in atoms:
        refs = atom.get("references") or []
        kind = atom.get("kind", "")
        for ref in refs:
            # Schema vNext: do not write repo_revision or excerpt_hash to refs
            ok, msg = verify_ref(vendor_root, ref, expected_commit)
            if not ok:
                if "lines" in ref and ref.get("lines", {}).get("start"):
                    errors.append(f"{atom.get('id', '?')} ref {ref.get('file')}: {msg}")
                elif args.fill and ref.get("symbol"):
                    # Try fill
                    filepath = ref.get("file")
                    path = vendor_root / filepath
                    content = path.read_text(encoding="utf-8", errors="replace")
                    rng = fill_line_range(content, filepath, ref["symbol"], kind)
                    if rng is None:
                        errors.append(
                            f"{atom.get('id')} ref {filepath}: symbol '{ref['symbol']}' "
                            "occurs 0 or >1 time; specify lines manually."
                        )
                    else:
                        ref["lines"] = {"start": rng[0], "end": rng[1]}
                        # Schema vNext: do not write excerpt_hash
                        modified = True
                else:
                    errors.append(f"{atom.get('id', '?')} ref {ref.get('file')}: {msg}")
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        return 1
    if modified and not args.no_write:
        if ruamel_yaml is None:
            print("ruamel.yaml required to write SSOT; run: uv sync", file=sys.stderr)
            return 1
        with open(ssot_path, "w", encoding="utf-8") as f:
            ruamel_yaml.dump(data, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
