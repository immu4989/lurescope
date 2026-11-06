# Dependency security review

This describes the unreleased source branch, not published PyPI 0.11.0 or an
updated deployment. A compatible lock is not a vulnerability-free certification
or proof of runtime reachability.

## Optional visualization stack — 4 November 2026

The approved read-only GitHub lookup returned 42 open default-branch alerts:
41 for Pillow (5 critical, 23 high, 13 medium) and one for certifi. All 41 Pillow
entries identify 13.0.0 as the first patched version. The branch previously
locked Pillow 12.3.0, through `lurescope[viz]` → Matplotlib → Pillow. The default
API dependency graph does not include that extra; the reviewed API environment
contained neither Pillow nor Matplotlib. This limited graph/installation check
does not prove that every deployment or custom environment excludes them.

The lock now selects **Pillow 13.0.0**, with other package versions unchanged.
The `viz` extra directly requires `pillow>=13.0.0`, so the floor is emitted into
wheel metadata for pip users as well as enforced by uv resolution. The default
API still does not acquire an imaging dependency. Python 3.11+ was already the
branch minimum and is compatible with Pillow's removal of Python 3.10 support.

Upstream's [13.0.0 release notes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html)
describe the security fixes and incompatible API changes. The maintainer's
[FlashPix advisory](https://github.com/python-pillow/Pillow/security/advisories/GHSA-5x8w-8jj5-q52h)
identifies a critical decoder issue fixed in that release. We did not execute
exploit samples or independently verify all upstream patches. The scorecard
renderers create charts from numeric aggregates, not user-uploaded image files;
this observation is not grounds to dismiss alerts or skip the patched version.

Both PNG renderers are tested with actual Matplotlib/Pillow on Python 3.11–3.13,
using synthetic aggregates and no model/provider calls. Checks cover PNG decoding,
nonempty image content, unchanged input data, closed figures, and missing rates
remaining masked rather than becoming zero. This is compatibility evidence for
the locked versions, not all possible future versions permitted by the extra.
The normal API suite remains usable without visualization dependencies.

## Updating an environment

Pulling source or a lockfile does not update an existing installation. From a
reviewed checkout, use `uv sync --locked --extra viz` (add `--extra dev` to test).
For pip, install the `viz` extra of a wheel built from this branch, or explicitly
upgrade Pillow to 13.0.0+ in an independently managed visualization environment
and verify its compatibility. Installing published `lurescope[viz]==0.11.0` does
not acquire this source-branch requirement. Rebuild relevant images separately.
Do not relax the floor or fall back to old Pillow to make an installer succeed.

The branch's certifi 2026.10.23 lock is above the advisory's fixed version and the
project's >=2026.10.19 uv constraint. That pre-existing constraint applies to uv
project resolution, not independent pip installations. See
[certifi's advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2).

GitHub alerts concern its default-branch dependency graph. These local changes
do not close them, modify released packages, upgrade environments, or establish
that no other vulnerability exists. No alert was dismissed; no push, deployment,
or publishing operation was performed. Consumers must audit their actual
interpreter, selected extras, transitive dependencies, and deployment images.
