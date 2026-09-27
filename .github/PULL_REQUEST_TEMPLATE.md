## Summary

<!-- What changes and why. Link the issue: Fixes #123 -->

## Type of change

- [ ] Fix
- [ ] Feature / enhancement
- [ ] Breaking change (needs a major version bump and a migration note in CHANGELOG.md)
- [ ] Security (describe the impact below)
- [ ] Docs / CI / tooling only

## Security impact

<!-- Required when the change touches the gateway path, policy engine, authentication, credential
handling, the audit log or what a reviewer sees. Write "none" otherwise. -->

## Checklist

- [ ] Tests added or updated, `make test` passes locally (Python 3.11 and 3.12 run in CI)
- [ ] `make lint` passes (ruff plus `scripts/check_style.py`)
- [ ] Docs updated (`docs/API.md` for endpoints, `docs/CONFIGURATION.md` and `.env.example` for settings, `README.md` if user facing)
- [ ] `CHANGELOG.md` has an entry under `Unreleased` (or the PR is labelled `skip-changelog`)
- [ ] No em dash characters anywhere (use a hyphen or a comma) and no unnecessary blank lines
- [ ] No secrets, agent keys, provider keys, tokens or personal data in code, tests, fixtures or logs
- [ ] New analyzers have a positive and a benign sample; new probes have unique ids and a category
- [ ] Privileged actions go through `aisrf.audit.service.record`
