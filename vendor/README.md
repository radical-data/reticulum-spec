# Vendor checkout (plan section 6.2 / 9.2)

`vendor/reticulum-source/` is the **checkout of the code the SSOT references**. Validation **always** reads referenced files from this directory, never from the working tree.

- **If this repo contains RNS/:** The vendor checkout is **the same repo at the pinned commit**. Populate by cloning this repo and checking out the exact commit in `spec_meta.source_of_truth.revision.commit`.
- **CI:** Must populate `vendor/reticulum-source/` every run (checkout exact commit from SSOT header).

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
