# Releasing AISRF

AISRF (the AI Security & Research Framework, package and CLI `aisrf`) is released from `main` by pushing a `vX.Y.Z` tag. The `Release` workflow
(`.github/workflows/release.yml`) does everything else: it verifies the version, runs the test
suite, builds the wheel and sdist, generates an SBOM and checksums, pushes a multi-arch image to
GHCR and creates the GitHub Release. Nothing is published to PyPI yet (see the end of this page).

## Versioning

Semantic Versioning 2.0.0:

* `MAJOR`: breaking changes to the REST API, the ticket or policy semantics, the CLI, configuration
  names or the database schema without an automatic migration.
* `MINOR`: new analyzers, probes, formats, endpoints, settings, integrations.
* `PATCH`: fixes and documentation.

Prereleases use `X.Y.Z-rc.N`; they are published as GitHub prereleases and the image gets only the
exact version tag (no `latest`, no `X.Y`). The Node package in `sdk/node` carries its own version
and is bumped by hand in `sdk/node/package.json` when it changes.

## Procedure

1. Make sure `main` is green (CI, CodeQL) and your clone is up to date:

   ```bash
   git checkout main && git pull --ff-only
   make lint test && node sdk/node/test.js
   ```

2. Review the `Unreleased` section of `CHANGELOG.md`. Every user visible change since the last
   release must be listed under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or
   `Security`. Breaking changes get a short migration note.

3. Bump the version. The script updates `aisrf/__init__.py`, `pyproject.toml` and turns the
   `Unreleased` section into the dated release heading (adding a fresh empty `Unreleased` section
   and the compare links):

   ```bash
   .venv/bin/python scripts/bump_version.py --dry-run 1.1.0   # inspect the diff
   .venv/bin/python scripts/bump_version.py 1.1.0
   .venv/bin/python scripts/bump_version.py --check 1.1.0     # what the workflow will verify
   git diff
   ```

4. Commit and tag. The tag must be `v` plus the exact version:

   ```bash
   git commit -am "Release 1.1.0"
   git tag -a v1.1.0 -m "AISRF 1.1.0"
   git push origin main
   git push origin v1.1.0
   ```

5. Watch the `Release` workflow in the Actions tab. It takes roughly 10 to 20 minutes, most of it
   in the arm64 image build. When it finishes, the release page lists the artifacts and the
   container digest.

6. Verify (see below), then announce. If the workflow failed, fix the cause on `main`, delete the
   tag locally and remotely (`git tag -d v1.1.0 && git push origin :refs/tags/v1.1.0`) and tag
   again. Never move a tag that already produced a GitHub Release; cut a patch release instead.

The workflow can also be started by hand (`Actions > Release > Run workflow`) with the version as
input; the tag `v<version>` must already exist. This is how you rerun a release whose workflow
failed for an infrastructure reason.

## What the workflow does

| Job | Steps |
| --- | --- |
| `verify` | Derives the version from the tag (or the input), checks it is valid semver and equals both `aisrf.__version__` and `[project].version` (`scripts/bump_version.py --check`; the package directory is read from `[project].name`), warns when `CHANGELOG.md` has no section for it. |
| `test` | `ruff check`, `scripts/check_style.py`, `pytest`, Node self-test on Python 3.12. |
| `build` | `python -m build` (sdist and wheel), installs the wheel and checks `aisrf version`, generates a CycloneDX JSON SBOM of the installed environment with `cyclonedx-bom`, writes `SHA256SUMS.txt`, uploads everything as the `dist` artifact. |
| `docker` | Builds `linux/amd64` and `linux/arm64` with Buildx and QEMU, pushes `ghcr.io/keyuraghao/aisrf:{version, major.minor, latest}` (only the exact version for prereleases) with OCI labels, provenance attestation and an image SBOM, then pulls the image and runs `aisrf version`. |
| `release` | Extracts the release notes from `CHANGELOG.md` (`scripts/changelog_notes.py`), falling back to GitHub's auto-generated notes (categories in `.github/release.yml`), appends the artifact list and creates the GitHub Release with the wheel, sdist, SBOM and checksums attached. |

Permissions: `contents: write` (release), `packages: write` (GHCR), `id-token: write` (attestations
and future PyPI trusted publishing). Only `GITHUB_TOKEN` is used; no secrets need to be configured.

## Verifying a release

```bash
VERSION=1.1.0
# Container image: tags, architectures, version banner
docker pull ghcr.io/keyuraghao/aisrf:$VERSION
docker run --rm ghcr.io/keyuraghao/aisrf:$VERSION version          # aisrf 1.1.0
docker buildx imagetools inspect ghcr.io/keyuraghao/aisrf:$VERSION  # both linux/amd64 and linux/arm64
docker buildx imagetools inspect ghcr.io/keyuraghao/aisrf:latest    # same digest for stable releases
# Wheel and checksums from the release page
gh release download v$VERSION --repo keyuraghao/aisrf --dir /tmp/aisrf-$VERSION
(cd /tmp/aisrf-$VERSION && sha256sum -c SHA256SUMS.txt)
python -m venv /tmp/aisrf-check && /tmp/aisrf-check/bin/pip install /tmp/aisrf-$VERSION/aisrf-$VERSION-py3-none-any.whl
/tmp/aisrf-check/bin/aisrf version
# SBOM
python -c "import json; d=json.load(open('/tmp/aisrf-$VERSION/aisrf-$VERSION.cyclonedx.json')); print(d['specVersion'], len(d['components']))"
```

Then start the image once against an empty volume (`docker run --rm -p 127.0.0.1:8080:8080 -e
AISRF_SECRET_KEY=... ghcr.io/keyuraghao/aisrf:$VERSION`), log in, create an agent and approve one
ticket. Deployments upgrade as described in `docs/DEPLOYMENT.md` (Upgrading).

## Hotfixes

Branch from the release tag (`git checkout -b hotfix/1.1.1 v1.1.0`), cherry-pick the fix, run
`scripts/bump_version.py 1.1.1`, tag from that branch and merge it back into `main` afterwards.
The `X.Y` image tag moves to the hotfix, `latest` too unless a newer minor exists (in that case
release the hotfix from the older branch and re-tag `latest` by hand if needed).

## PyPI (not enabled)

`release.yml` contains a commented `pypi` job that uses PyPI trusted publishing (OIDC, no token).
To enable it: register the pending publisher on pypi.org (owner `keyuraghao`, repository `aisrf`,
workflow `release.yml`, environment `pypi`), create the `pypi` GitHub environment with required
reviewers, and uncomment the job. Until then, users install from the wheel attached to the release
or from the container image.
