# Pinned producer artifacts

`producer-contract.json` records SHA-256 hashes of exact producer bytes at a
full LureBench Git commit. It replaces tests that assumed another checkout
existed at `../lurebench`. Hash checks and independent semantic verification
run in a standalone LureScope checkout with no network access.

To check local copies and, optionally, the actual source commit:

```sh
python scripts/check_producer_contract.py
python scripts/check_producer_contract.py --producer-root /path/to/lurebench
```

When a shared contract changes, review its source diff, identify the exact
producer commit, compare the copied bytes, then update the manifest and tests.
Changing a hash alone does not establish compatibility. These pins prevent
accidental drift; repository review remains the trust anchor for their updates.
