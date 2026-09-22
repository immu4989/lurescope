# Pinned checkpoint byte verification (unreleased)

LureBench's offline checkpoint preflight checks a bounded sharded Safetensors
profile. LureScope can verify that a recipient's files exactly match that
preflight report, with **no imports from the producer implementation** and no
model execution. This is byte equality, not a second Safetensors parser.

## Receiving a checkpoint

1. Have a trusted reviewer inspect a read-only local checkpoint using the
   unreleased `lurebench checkpoint-inspect` command. Review both the report
   and the tool's documented limitations.
2. Obtain the SHA-256 of the exact approved report bytes through a separate
   trusted channel: for example, your organization's reviewed configuration.
   Do not trust a digest delivered beside an untrusted checkpoint. Merely
   computing a hash of a downloaded report establishes no trust in it.
3. Receive the checkpoint and report into a read-only directory under trusted
   parents. Use an explicit local byte budget when checking them:

   ```sh
   lurescope checkpoint-verify /trusted-parent/checkpoint \
     --report approved-inspection.json \
     --expected-report-sha256 APPROVED_64_CHARACTER_SHA256 \
     --max-bytes 1073741824 --out checkpoint-verification.json
   ```

4. Exit 0 and `CHECKPOINT BYTES: MATCH` mean the report matched the supplied
   digest and its indexed files matched the recorded bytes. Exit 2 rejects
   the input or reports an I/O failure. Output files must be new and are
   created with owner-only permissions. `--json` prints the result.
5. Keep the verified snapshot immutable. A later loader must consume those
   same bytes; this command does not start or control that loader.

The report contract, integer fields, shard names, bounds, and aggregate
arithmetic are independently checked before shard access. Files are opened
relative to a directory descriptor with no-follow/nonblocking flags; symlinks,
FIFOs, nonregular files, and observed mutations fail closed. Index bytes,
headers, and complete shard bytes are hashed, without loading tensor values.

## What remains unverified

This verifier trusts the externally pinned producer's structural inspection;
it does not independently reparse tensor layouts. It does not authenticate a
publisher or establish that the reviewer chose a trustworthy artifact. It does
not inspect configuration, tokenizers, custom code, or unreferenced files.
Report counts are structurally checked claims bound to the pinned report.

File identity checks are not an atomic snapshot under an adversarial concurrent
writer. A pass is not model safety, containment, compliance, or deployment
authorization. The result is unsigned evidence of this local comparison, not
a transferable attestation of who ran it. No dependency advisory is fixed by
running this command.

Both commands are currently source-branch features, not part of PyPI 0.11.0.
