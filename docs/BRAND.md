# AISRF brand

AISRF is the acronym of AI Security & Research Framework. The short name matches the descriptor exactly: use "AISRF" in prose and titles, `aisrf` for the package, CLI, image and repository, and always the ampersand in the descriptor.

## Logo

The logo is the circular emblem in `docs/images/brand/logo.png` (1024 x 1024, supplied by the project owner and the single source of truth). It shows an unknown model specimen under examination by two researchers, with a scan readout on the right: the framework's job is to inspect AI systems before trusting them.

Every other asset is derived from it by `scripts/brand_assets.py`:

| File | Size | Use |
| --- | --- | --- |
| `logo.png` | 1024 x 1024 | source emblem |
| `logo-mark.png` | 1024 x 1024 | circle-cropped mark with transparent corners |
| `icon-512.png`, `icon-192.png` | 512, 192 | app and PWA icons |
| `favicon.png`, `favicon-32.png` | 64, 32 | browser tab icon (served at `/static/favicon.png`) |
| `logo-horizontal.png` | 2400 x 643 | mark plus wordmark for light backgrounds |
| `logo-horizontal-dark.png` | 2400 x 643 | mark plus wordmark for dark backgrounds |
| `social-preview.png` | 1280 x 640 | GitHub social preview card |
| `README-hero.png` | 1600 x 400 | README banner |

Regenerate after replacing `logo.png`:

```bash
.venv/bin/python scripts/brand_assets.py
```

The script also copies `logo-mark.png`, `favicon.png` and `icon-192.png` into `aisrf/dashboard/static/`, which the dashboard shell references.

## Colours

| Token | Hex | Use |
| --- | --- | --- |
| navy | `#0B1220` | dark backgrounds |
| slate | `#1E293B` | panels |
| teal | `#22D3EE` | accent, descriptor text, links |
| amber | `#F59E0B` | pending review state, highlights |
| white | `#FFFFFF` | wordmark on dark backgrounds |

## Usage rules

- Keep the emblem circular; do not crop it into a square or stretch it.
- Leave clear space of at least one tenth of the emblem diameter on all sides.
- Minimum size 24 px; at 16 px use `favicon-32.png` scaled by the browser.
- Do not recolour the emblem or place it on busy photographs.
- Earlier generated marks are kept only as history under `candidates/`.
