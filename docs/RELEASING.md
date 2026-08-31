# Releasing LureScope

Releases are built only from immutable `vMAJOR.MINOR.PATCH` tags whose commit is
reachable from protected `main`. The release workflow verifies all public version
metadata, runs `twine check`, attests the wheel and source archive, and attaches
them to the GitHub release.
The package build runs with read-only repository permission and no OIDC or
release-write authority. A downstream job downloads that completed artifact,
then receives only the authority needed to attest it and attach it to the
release. Existing release assets are never overwritten automatically.

It also builds the hardened Dockerfile for `linux/amd64` and `linux/arm64`,
publishes versioned and `latest` tags to `ghcr.io/immu4989/lurescope`, includes
an SBOM and BuildKit provenance, and creates a GitHub registry attestation.
GitHub documents this `GITHUB_TOKEN`-based pattern in its
[container publishing guide](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images).

The [`lurescope` PyPI project](https://pypi.org/project/lurescope/) publishes
through OpenID Connect from GitHub Actions. PyPI trusts only owner `immu4989`,
repository `lurescope`, workflow `release.yml`, and environment `pypi`. The
GitHub environment requires manual approval and the repository Actions variable
`PYPI_PUBLISH` enables the publish job. No long-lived PyPI token belongs in
GitHub secrets.

## Verify downloaded provenance

Verify each downloaded distribution against this repository before installing
it:

```bash
gh attestation verify lurescope-X.Y.Z-py3-none-any.whl \
  --repo immu4989/lurescope
gh attestation verify lurescope-X.Y.Z.tar.gz \
  --repo immu4989/lurescope
```

For the container, prefer its immutable digest:

```bash
gh attestation verify \
  oci://ghcr.io/immu4989/lurescope@sha256:YOUR_PUBLISHED_DIGEST \
  --repo immu4989/lurescope
```

Successful verification binds an artifact to the repository and build
workflow. It is provenance evidence, not a guarantee that the artifact is
secure, correct, or suitable for a deployment.

## Release procedure

1. Update the version in `pyproject.toml`, `lurescope/__init__.py`,
   `CITATION.cff`, the README badge, and the changelog.
2. Run `python scripts/verify_release.py vX.Y.Z`.
3. Run the complete Python, browser, package, and container test gates.
4. Merge through protected CI.
5. Create a GitHub release targeting the exact tested `main` commit and tag it
   `vX.Y.Z`.
6. Approve the waiting `pypi` environment deployment only after the build and
   release-source verification jobs pass.
7. Confirm the PyPI project, attached distributions, GHCR tags,
   SBOM/provenance attestations, and Zenodo version record.
8. In a follow-up protected PR, update `space/requirements-space.txt` with the
   published wheel's exact PyPI SHA-256 and `compose.yaml` with the published
   multi-architecture GHCR digest. Never predict either value in the release
   commit or weaken the existing verified pins while waiting for new artifacts.
