# Schema vNext: Container / Atom Contract

This document describes the leaner SSOT schema (vNext): a single top-level container for shared metadata and atoms that contain only per-atom data. No duplicated provenance or per-atom hashes.

## Root structure

- **spec_meta** — Spec identity, version, source-of-truth URL, normative language, notation.
- **manifest** — Single source of truth for document-wide metadata (required).
- **atoms** — Array of spec atoms; each atom has only what varies per atom.

## Manifest (container)

The manifest is the **single source of truth** for shared metadata. All atoms are implicitly associated with the container’s `repo_revision`; atoms must not override it.

| Field            | Required | Description |
|------------------|----------|-------------|
| repo_revision    | Yes      | Git commit (full SHA) for the source revision; all references refer to this revision. |
| source_repo      | No       | Optional source repository identifier. |
| created_at       | No       | ISO 8601 timestamp when the document was created. |
| schema_version   | No       | Schema version identifier. |

**Rules:**

- Every atom is implicitly associated with `manifest.repo_revision`. There is exactly one revision per document.
- Atoms must **not** contain `repo_revision`. If present in a reference, validation fails (fail fast).

## Atoms and references

Atoms contain only what varies per atom. References point to source locations by **file**, **symbol**, and **lines** (start/end). No per-reference `repo_revision` or `excerpt_hash`.

### Reference shape (vNext)

| Field   | Required | Description |
|---------|----------|-------------|
| file    | Yes      | Path relative to vendor root (e.g. `RNS/Packet.py`). |
| symbol  | Yes      | Symbol name (function, constant, etc.). |
| lines   | Yes      | `{ start: number, end: number }` 1-indexed inclusive. |
| role    | Yes      | One of: definition, implementation, derivation, dispatch, note. |

**Forbidden in references:**

- **repo_revision** — Use `manifest.repo_revision` only. If present in a ref, validation fails.
- **excerpt_hash** — Removed in vNext. Integrity, if needed, belongs at the excerpt storage layer (e.g. optional `excerpt.digest`), not per atom.

### Inheritance

- **repo_revision**: Every atom inherits `manifest.repo_revision`. Lookups that previously used `atom.references[].repo_revision` must use `manifest.repo_revision` (or the container’s `repo_revision`).
- Atoms must not override or duplicate this value.

## Validation

- JSON schema and Spectral rules require `manifest` and forbid `repo_revision` and `excerpt_hash` in references.
- CI runs `validate_ssot.py`, which fails fast on any ref containing `repo_revision` or `excerpt_hash`.

## Summary

- **repo_revision**: Single `manifest.repo_revision`; refs must not contain it.
- **excerpt_hash**: Removed; integrity, if needed, belongs at the excerpt storage layer.
- **Ref shape**: file, symbol, lines, role only.

This keeps the schema lean and avoids inconsistency from repeated revision values.
