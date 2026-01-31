#!/usr/bin/env python3
"""
validate_ssot.py — Validate SSOT YAML: JSON Schema 2020-12, Spectral, bespoke checks.

Order: Load SSOT → JSON Schema → Spectral → bespoke checks → extract_refs verification.
Manifest.repo_revision is the single source of truth; atoms MUST NOT contain repo_revision or excerpt_hash.
Bespoke checks: ID uniqueness; manifest required; ref must not have repo_revision/excerpt_hash;
file exists under vendor; symbol in file; lines.start <= lines.end; slice contains symbol;
layout offsets monotone; constant sane bounds; version vs manifest.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def normalise_excerpt_bytes(content: str, start: int, end: int) -> bytes:
    """Plan section 3: 1-indexed inclusive; \\n line endings normalised."""
    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.splitlines(keepends=True)
    if not lines:
        return b""
    lo = max(0, start - 1)
    hi = min(len(lines), end)
    excerpt = "".join(lines[lo:hi])
    return excerpt.encode("utf-8")


def excerpt_hash_hex(content: str, start: int, end: int) -> str:
    """Hex-encoded SHA-256 of excerpt bytes."""
    raw = normalise_excerpt_bytes(content, start, end)
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ssot_path = repo_root / "spec" / "reticulum-wire-format.ssot.yaml"
    schema_path = repo_root / "spec" / "schema" / "reticulum-wire-format.ssot.schema.json"
    spectral_rules = repo_root / "spec" / "rules" / "spectral.ssot.yaml"
    vendor_root = repo_root / "vendor" / "reticulum-source"
    generated_dir = repo_root / "spec" / "generated"
    manifest_path = generated_dir / "manifest.json"

    errors = []

    # Load SSOT
    try:
        import yaml
        with open(ssot_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        errors.append(f"Load SSOT: {e}")
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    if not isinstance(data, dict):
        errors.append("SSOT root must be an object with spec_meta and atoms")
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    spec_meta = data.get("spec_meta")
    manifest = data.get("manifest")
    atoms = data.get("atoms")
    if spec_meta is None:
        errors.append("Missing spec_meta")
    if manifest is None:
        errors.append("Missing manifest")
    if atoms is None:
        errors.append("Missing atoms")
    if not isinstance(atoms, list):
        errors.append("atoms must be an array")
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    expected_commit = (manifest.get("repo_revision") or "").strip()
    if not expected_commit:
        errors.append("manifest.repo_revision is required and must be non-empty")
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    # If atoms exist: vendor checkout and pinned commit are mandatory; no skipping
    if atoms and len(atoms) > 0:
        if not vendor_root.is_dir():
            errors.append("vendor/reticulum-source/ is required when atoms exist; populate from spec_meta.source_of_truth (clone URL, checkout revision.commit)")
        if not expected_commit or not expected_commit.strip():
            errors.append("spec_meta.source_of_truth.revision.commit is required when atoms exist; set to pinned vendor commit")

    # 1. JSON Schema
    try:
        import jsonschema
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        jsonschema.validate(instance=data, schema=schema)
    except ImportError:
        errors.append("JSON Schema validation: jsonschema not installed. Run: uv sync")
    except Exception as e:
        errors.append(f"JSON Schema validation: {e}")

    # 1b. Fail fast: reject forbidden fields in references (repo_revision, excerpt_hash)
    for atom in atoms:
        aid = atom.get("id", "?")
        for ref in atom.get("references") or []:
            if ref.get("repo_revision") is not None:
                errors.append(f"ref must not contain repo_revision (use manifest.repo_revision) (atom {aid})")
            if ref.get("excerpt_hash") is not None:
                errors.append(f"ref must not contain excerpt_hash (Schema vNext) (atom {aid})")

    # 2. Spectral
    if spectral_rules.is_file():
        try:
            r = subprocess.run(
                ["npx", "--yes", "@stoplight/spectral-cli@6.11.0", "lint", str(ssot_path), "--ruleset", str(spectral_rules)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=30,
            )
            if r.returncode != 0 and r.stderr:
                errors.append(f"Spectral: {r.stderr.strip()}")
            if r.returncode != 0 and r.stdout:
                errors.append(r.stdout.strip())
        except FileNotFoundError:
            errors.append("Spectral: npx or @stoplight/spectral-cli not found. Install Node (LTS) and run: npx --yes @stoplight/spectral-cli@6.11.0 lint ...")
        except subprocess.TimeoutExpired:
            errors.append("Spectral: timeout")
    else:
        errors.append(f"Spectral ruleset not found: {spectral_rules}")

    # 3. Bespoke checks
    seen_ids = set()
    for atom in atoms:
        aid = atom.get("id")
        if aid:
            if aid in seen_ids:
                errors.append(f"Duplicate atom id: {aid}")
            seen_ids.add(aid)

        refs = atom.get("references") or []
        for ref in refs:
            # repo_revision is on manifest only; ref must not have it (already checked above)
            fpath = ref.get("file")
            if not fpath:
                errors.append(f"ref missing file (atom {aid})")
                continue
            if ".." in fpath:
                errors.append(f"ref file must not contain ..: {fpath} (atom {aid})")
            full_path = vendor_root / fpath
            if not vendor_root.is_dir():
                pass  # already reported above when atoms exist
            elif not full_path.is_file():
                errors.append(f"ref file not found under vendor: {fpath} (atom {aid})")
            else:
                lines_obj = ref.get("lines") or {}
                start = lines_obj.get("start")
                end = lines_obj.get("end")
                if start is not None and end is not None:
                    if start > end:
                        errors.append(f"lines.start > lines.end (atom {aid}, file {fpath})")
                    else:
                        try:
                            content = full_path.read_text(encoding="utf-8", errors="replace")
                            excerpt_lines = content.replace("\r\n", "\n").splitlines()
                            if 1 <= start <= len(excerpt_lines) and 1 <= end <= len(excerpt_lines):
                                slice_text = "\n".join(excerpt_lines[start - 1 : end])
                                symbol = ref.get("symbol", "")
                                if symbol and symbol not in slice_text:
                                    errors.append(f"symbol '{symbol}' not in lines [{start},{end}] (atom {aid}, file {fpath})")
                                # excerpt_hash removed in Schema vNext; no per-ref hash check
                            else:
                                errors.append(f"lines [{start},{end}] out of range (atom {aid}, file {fpath})")
                        except Exception as e:
                            errors.append(f"reading ref file {fpath}: {e}")

        if atom.get("kind") == "layout":
            layout = atom.get("layout") or {}
            fields = layout.get("fields") or []
            prev_end = -1
            for i, f in enumerate(fields):
                offset = f.get("offset", 0)
                length = f.get("length", 0)
                if offset < prev_end:
                    allow = f.get("allow_overlap") and f.get("overlap_with")
                    if not allow:
                        errors.append(f"layout atom {aid} field {f.get('name')} overlaps previous; set allow_overlap and overlap_with if intentional")
                prev_end = offset + length
            for f in fields:
                if f.get("allow_overlap"):
                    ow = f.get("overlap_with")
                    if not ow or not isinstance(ow, list):
                        errors.append(f"layout atom {aid} allow_overlap=true but overlap_with missing or not list")

        if atom.get("kind") == "constant":
            val = atom.get("value") or {}
            num = val.get("number")
            unit = (val.get("unit") or "").lower()
            if num is not None and isinstance(num, (int, float)) and ("byte" in unit or "bit" in unit):
                constraints = atom.get("constraints") or {}
                max_r = val.get("max_reasonable")
                lo = constraints.get("min", 0)
                hi = constraints.get("max") if constraints.get("max") is not None else (max_r if max_r is not None else 10_000)
                if hi is not None and num > hi:
                    errors.append(f"constant atom {aid} value {num} exceeds max {hi} (set constraints or value.max_reasonable to override)")

    # 4. Version bump: manifest required (plan 2b)
    if manifest_path.is_file():
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = json.load(f)
            manifest_ver = manifest.get("ssot_version", "")
            spec_ver = (spec_meta or {}).get("ssot_version", "")
            if spec_ver != manifest_ver:
                errors.append(f"spec_meta.ssot_version ({spec_ver}) != manifest.ssot_version ({manifest_ver}); bump ssot_version and recompile")
            # Content hash: compare SSOT file hash to manifest
            raw_ssot = ssot_path.read_bytes()
            ssot_sha = hashlib.sha256(raw_ssot).hexdigest()
            manifest_sha = manifest.get("ssot_content_sha256", "")
            if manifest_sha and ssot_sha != manifest_sha:
                errors.append("SSOT content changed but manifest.ssot_content_sha256 not updated; run compile_ssot.py and commit generated files")
        except Exception as e:
            errors.append(f"manifest read: {e}")
    else:
        # Manifest required when we have atoms; with empty atoms allow missing until first compile
        if atoms and len(atoms) > 0:
            errors.append("spec/generated/manifest.json required; run tools/compile_ssot.py first")

    # 5. extract_refs verification (when vendor and atoms exist)
    if vendor_root.is_dir() and atoms and expected_commit and expected_commit.strip():
        extract_refs = repo_root / "tools" / "extract_refs.py"
        if extract_refs.is_file():
            try:
                r = subprocess.run(
                    [sys.executable, str(extract_refs), "--ssot", str(ssot_path), "--vendor", str(vendor_root), "--no-write"],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if r.returncode != 0 and r.stderr:
                    errors.append(f"extract_refs: {r.stderr.strip()}")
            except Exception as e:
                errors.append(f"extract_refs: {e}")

    for e in errors:
        print(e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
