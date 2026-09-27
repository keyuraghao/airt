# Releasing

AISRF is released from `main` by pushing a `vX.Y.Z` tag. The `Release` workflow (`.github/workflows/release.yml`) verifies the version, runs the tests, builds the wheel and sdist with an SBOM and checksums, pushes a multi-arch image to GHCR, builds the native binaries on four runners and creates the GitHub Release. Nothing is published to PyPI yet.

## Versioning

Semantic Versioning 2.0.0, validated by `scripts/bump_version.py` with the full semver regex (prerelease and build metadata allowed):

- `MAJOR`: breaking changes to the REST API, ticket or policy semantics, the CLI, configuration names or the database schema without an automatic migration.
- `MINOR`: new analyzers, probes, formats, endpoints, settings, integrations.
- `PATCH`: fixes and documentation.

Prereleases use `X.Y.Z-rc.N`; they become GitHub prereleases and the image gets only the exact version tag (no `latest`, no `X.Y`). The version lives in exactly two places, `aisrf/__init__.py` (`__version__`) and `pyproject.toml` (`[project] version`), and must agree. The Node package `sdk/node/package.json` is versioned independently and bumped by hand. Current version: `1.0.0`.

## Bump script

`scripts/bump_version.py` (also `make bump VERSION=1.1.0 [DRY=1]`):

```bash
.venv/bin/python scripts/bump_version.py --current            # print the current version (exit 1 if the two files disagree)
.venv/bin/python scripts/bump_version.py --dry-run 1.1.0      # unified diff of every change, nothing written
.venv/bin/python scripts/bump_version.py 1.1.0                # apply
.venv/bin/python scripts/bump_version.py --check 1.1.0        # exit 1 unless both files already say 1.1.0 (what the workflow runs)
.venv/bin/python scripts/bump_version.py 1.1.0 --date 2026-10-01 --no-changelog --force
```

It updates `__version__`, the `version =` line inside `[project]`, and turns `## [Unreleased]` in `CHANGELOG.md` into `## [1.1.0] - <date>` while inserting a fresh empty `## [Unreleased]` above it and rewriting the compare links at the bottom (`[Unreleased]: .../compare/v1.1.0...HEAD`, `[1.1.0]: .../compare/v1.0.0...v1.1.0`). It refuses a version that is not greater than the current one (`--force` overrides), a version that already has a changelog section, or a changelog without an Unreleased heading, and warns when the Unreleased section is empty. The package directory is read from `[project].name`.

## Changelog

`CHANGELOG.md` follows Keep a Changelog 1.1.0. Every user-visible change lands in `Unreleased` under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or `Security` as PRs merge (PRs without a user-visible change carry the `skip-changelog` label). Breaking changes get a short migration note. `scripts/changelog_notes.py <version>` prints the section for one version and exits 1 with nothing on stdout when it is missing or empty; the release workflow uses it for the release notes and falls back to GitHub's auto-generated notes (categories from `.github/release.yml`: Breaking changes, Security, Features, Fixes, Documentation; excludes `skip-changelog`, `duplicate`, `invalid`, `wontfix` and Dependabot).

## Procedure

```bash
git checkout main && git pull --ff-only
make lint test && node sdk/node/test.js          # main must be green (CI, CodeQL)
# review the Unreleased section of CHANGELOG.md
.venv/bin/python scripts/bump_version.py --dry-run 1.1.0
.venv/bin/python scripts/bump_version.py 1.1.0
.venv/bin/python scripts/bump_version.py --check 1.1.0
git diff
git commit -am "Release 1.1.0"
git tag -a v1.1.0 -m "AISRF 1.1.0"
git push origin main
git push origin v1.1.0
```

Watch Actions > Release. It takes roughly 10 to 20 minutes, most of it in the arm64 image build and the binary matrix. The workflow can also be started by hand (Actions > Release > Run workflow) with the version as input; the tag `v<version>` must already exist. That is how you rerun a release whose workflow failed for an infrastructure reason. The `concurrency` group `release-<ref>` with `cancel-in-progress: true` means a newer run for the same tag supersedes a queued one.

Hotfixes: branch from the release tag (`git checkout -b hotfix/1.1.1 v1.1.0`), cherry-pick, `scripts/bump_version.py 1.1.1`, tag from that branch, merge back into `main`. The `X.Y` image tag moves to the hotfix, `latest` too unless a newer minor exists.

## Release workflow job by job

Triggers: `push` of tags `v*.*.*`, or `workflow_dispatch` with `version`. Permissions: `contents: write` (release), `packages: write` (GHCR), `id-token: write` (attestations and future PyPI trusted publishing). Only `GITHUB_TOKEN` is used; no repository secrets. Env: `IMAGE=ghcr.io/keyuraghao/aisrf`, `PYTHON_VERSION=3.12`.

| Job | Needs | Steps |
| --- | --- | --- |
| `verify` (verify version) | | checks out the tag (or `refs/tags/v<input>`), derives `VERSION` from `GITHUB_REF_NAME` or the input, runs `python scripts/bump_version.py --check "$VERSION"`, computes `major_minor` and `prerelease` (true when the version contains `-`), outputs `version`, `major_minor`, `prerelease`, `tag`; warns (`::warning::`) when `scripts/changelog_notes.py` finds no changelog section |
| `test` (tests) | verify | `uv venv` 3.12 with `.[dev,codereview]`; `ruff check aisrf tests examples`; `scripts/check_style.py`; `pytest -q` with `AISRF_SECRET_KEY` and JSON console; `node sdk/node/test.js` |
| `build` (sdist, wheel, SBOM, checksums) | verify, test | `python -m build --sdist --wheel --outdir dist`; installs the wheel and asserts `aisrf.__version__` equals the version and `aisrf version` works; `cyclonedx-py environment` on a fresh venv with the wheel produces `aisrf-<version>.cyclonedx.json`; `sha256sum * > SHA256SUMS.txt` in `dist/`; uploads the `dist` artifact (30 days) |
| `docker` (multi-arch image to GHCR) | verify, test | QEMU and Buildx, login to `ghcr.io` with `GITHUB_TOKEN`, `docker/metadata-action` tags `<version>`, `<major.minor>` (stable only) and `latest` (stable only) with OCI labels (title, description, license, version); `docker/build-push-action` for `linux/amd64,linux/arm64` with GHA cache, `provenance: true`, `sbom: true`; pulls the pushed image and checks `aisrf version` prints the version; outputs the digest |
| `binaries` (binary `<os>-<arch>`) | verify, test | matrix: `ubuntu-latest` linux x86_64 (required), `ubuntu-24.04-arm` linux arm64 (`optional: true`, `continue-on-error`), `windows-latest` windows x86_64 (required), `macos-14` macos arm64 (required); each creates a uv venv with `-e . pyinstaller`, runs `scripts/build_binary.py` (PyInstaller onedir build from `packaging/pyinstaller/aisrf.spec`, smoke test, `aisrf-<version>-<os>-<arch>.tar.gz` or `.zip`, `SHA256SUMS-<os>-<arch>.txt`) and uploads `binary-<os>-<arch>` (30 days). An optional leg without a runner fails without blocking the release and its archive is simply absent |
| `release` (GitHub release) | verify, build, docker, binaries | downloads `dist` and every `binary-*` artifact into `dist/`; writes `release-notes.md` from `scripts/changelog_notes.py` (or enables `generate_release_notes` on failure) and appends an "Artifacts" section (image pull command with `<major.minor>` and `latest` for stable releases, digest, platforms; wheel, sdist, SBOM and checksums; binaries with the install one-liners); `softprops/action-gh-release` creates `AISRF <version>` on tag `v<version>`, `prerelease` and `make_latest` from the verify outputs, `fail_on_unmatched_files: true`, files `dist/*.whl`, `dist/*.tar.gz`, `dist/*.zip`, `dist/*.cyclonedx.json`, `dist/SHA256SUMS.txt`, `dist/SHA256SUMS-*.txt` |
| `pypi` (commented out) | verify, release | see PyPI below |

## Artifacts

For version `1.1.0` the release page carries: `aisrf-1.1.0-py3-none-any.whl`, `aisrf-1.1.0.tar.gz` (sdist), `aisrf-1.1.0.cyclonedx.json`, `SHA256SUMS.txt` (Python artifacts), `aisrf-1.1.0-linux-x86_64.tar.gz`, `aisrf-1.1.0-linux-arm64.tar.gz` (when the arm64 runner was available), `aisrf-1.1.0-macos-arm64.tar.gz`, `aisrf-1.1.0-windows-x86_64.zip`, `SHA256SUMS-linux-x86_64.txt`, `SHA256SUMS-linux-arm64.txt`, `SHA256SUMS-macos-arm64.txt`, `SHA256SUMS-windows-x86_64.txt`. The container image is `ghcr.io/keyuraghao/aisrf:1.1.0`, `:1.1`, `:latest` (linux/amd64 and linux/arm64) with provenance attestation and an image SBOM. The workflow run itself keeps the `dist` and `binary-*` artifacts for 30 days.

## Moving a tag after a failed release

If the workflow failed before the `release` job created the GitHub Release: fix the cause on `main`, delete the tag locally and remotely, and tag again.

```bash
git tag -d v1.1.0
git push origin :refs/tags/v1.1.0
# fix, commit, then
git tag -a v1.1.0 -m "AISRF 1.1.0"
git push origin v1.1.0
```

If the image was already pushed by the `docker` job, the retag simply pushes it again with the same tags. If the failure was infrastructure only (runner outage, registry hiccup), rerun with Actions > Release > Run workflow and the version as input instead of moving the tag. Never move a tag that already produced a GitHub Release; cut a patch release instead.

## Verifying GHCR and binaries

```bash
VERSION=1.1.0
docker pull ghcr.io/keyuraghao/aisrf:$VERSION
docker run --rm ghcr.io/keyuraghao/aisrf:$VERSION version               # aisrf 1.1.0
docker buildx imagetools inspect ghcr.io/keyuraghao/aisrf:$VERSION       # linux/amd64 and linux/arm64
docker buildx imagetools inspect ghcr.io/keyuraghao/aisrf:latest         # same digest for stable releases
gh release download v$VERSION --repo keyuraghao/aisrf --dir /tmp/aisrf-$VERSION
(cd /tmp/aisrf-$VERSION && sha256sum -c SHA256SUMS.txt && sha256sum -c SHA256SUMS-linux-x86_64.txt)
python -m venv /tmp/aisrf-check && /tmp/aisrf-check/bin/pip install /tmp/aisrf-$VERSION/aisrf-$VERSION-py3-none-any.whl
/tmp/aisrf-check/bin/aisrf version
python -c "import json; d=json.load(open('/tmp/aisrf-$VERSION/aisrf-$VERSION.cyclonedx.json')); print(d['specVersion'], len(d['components']))"
(cd /tmp/aisrf-$VERSION && tar -xzf aisrf-$VERSION-linux-x86_64.tar.gz && ./aisrf/aisrf version)
AISRF_VERSION=$VERSION bash scripts/install.sh                          # exercises the installer path
```

Then start the image once against an empty volume (`docker run --rm -p 127.0.0.1:8080:8080 -e AISRF_SECRET_KEY=... ghcr.io/keyuraghao/aisrf:$VERSION`), sign in, create an agent and approve one ticket. On macOS and Windows run the binary once (`aisrf desktop`) to confirm the quarantine and SmartScreen paths described in [[Installation]]. Deployments upgrade as described in [[Operations-and-Maintenance]].

## PyPI trusted publishing (not enabled)

`release.yml` contains a commented `pypi` job using `pypa/gh-action-pypi-publish@release/v1` with OIDC (no API token): it needs `verify` and `release`, runs only for stable versions, uses the `pypi` environment with URL `https://pypi.org/project/aisrf/<version>/`, downloads the `dist` artifact, keeps only the wheel and sdist and publishes with `print-hash: true`. To enable it:

1. On pypi.org add a pending publisher for project `aisrf`: owner `keyuraghao`, repository `aisrf`, workflow `release.yml`, environment `pypi`.
2. Create the GitHub environment `pypi` (Settings > Environments) with required reviewers.
3. Uncomment the job; `id-token: write` is already granted at the workflow level.

Until then users install from the wheel attached to the release, from git, or from the container image. Signed artifacts (Sigstore) are listed under "Later" in `docs/ROADMAP.md`.
