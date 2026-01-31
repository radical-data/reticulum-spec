# Vendor checkout (plan section 6.2 / 9.2)

`vendor/reticulum-source/` is the **checkout of the code the SSOT references**. Validation **always** reads referenced files from this directory, never from the working tree.

- **Do not commit** `vendor/reticulum-source/`. It is **not** a git submodule. It is populated at CI and locally by cloning and checking out the commit in `spec_meta.source_of_truth.revision.commit`. The repo ignores `vendor/reticulum-source/` so it is never committed.
- **CI:** Populates `vendor/reticulum-source/` every run (clone + checkout exact commit from SSOT).

## Populate locally

1. Set `spec_meta.source_of_truth.revision.commit` in `spec/reticulum-wire-format.ssot.yaml` to the commit you want to pin (e.g. current `git rev-parse HEAD`).
2. From repo root:
   ```bash
   rm -rf vendor/reticulum-source
   git clone . vendor/reticulum-source
   cd vendor/reticulum-source && git checkout <commit> && cd ../..
   ```
   Or if the SSOT references another repo, clone that repo and checkout the commit.

Never run validation against "main" or "latest"; always use the pinned commit so line references are meaningful.
