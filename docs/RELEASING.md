# Releasing LureScope

Releases are built only from immutable `vMAJOR.MINOR.PATCH` tags whose commit is
reachable from protected `main`. The release workflow verifies all public version
metadata, runs `twine check`, attests the wheel and source archive, and attaches
them to the GitHub release.

It also builds the hardened Dockerfile for `linux/amd64` and `linux/arm64`,
publishes versioned and `latest` tags to `ghcr.io/immu4989/lurescope`, includes
an SBOM and BuildKit provenance, and creates a GitHub registry attestation.
GitHub documents this `GITHUB_TOKEN`-based pattern in its
[container publishing guide](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images).

PyPI publication is deliberately deferred until LureBench has been published as
a normal index dependency. The
[PyPA dependency specification](https://packaging.python.org/en/latest/specifications/version-specifiers/#direct-references)
says public index servers should not allow direct references, so LureScope's
immutable Zenodo dependency is not its long-term public packaging contract. Do
not replace it with an unpinned dependency merely to make publication easier.

## Release procedure

1. Update the version in `pyproject.toml`, `lurescope/__init__.py`,
   `CITATION.cff`, the README badge, and the changelog.
2. Run `python scripts/verify_release.py vX.Y.Z`.
3. Run the complete Python, browser, package, and container test gates.
4. Merge through protected CI.
5. Create a GitHub release targeting the exact tested `main` commit and tag it
   `vX.Y.Z`.
6. Confirm the attached distributions, GHCR tags, SBOM/provenance attestations,
   and Zenodo version record.
