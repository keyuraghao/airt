# Airt brand guide

This document describes the Airt name, logo, colours and the rules for using them.
All source files live in `docs/images/brand/`.

## The name

**Airt** works on two levels.

- It is the acronym for **AI Red Team**, the discipline the product is built for. Airt is an enterprise
  human-in-the-loop AI Security & Research Framework: a gateway that puts a human reviewer
  between every AI request and your backend.
- It is also a Scots word. To *airt* something is to direct or guide it, and an *airt* is a
  compass point. The gateway airts every AI request: it directs each one through human
  review before it is allowed to reach your backend.

Write the product name as **Airt** (capital A, lowercase irt) in prose. Use `airt` only for the
package, CLI, repository and other code identifiers. Do not write "AIRT" or "AiRT".

## The mark

The mark combines three ideas in one geometric silhouette:

1. **A compass needle** (guidance). The needle points north-east and is split in two:
   the teal half is the request that has been approved and is moving forward, the amber half
   is the request that is still pending review. Amber is the same colour the dashboard uses
   for the "pending review" state, so the mark and the product speak the same language.
2. **A gate with a portcullis** (interception and control). The rounded square is the gate
   frame; the three pointed teeth hanging from the lintel are the portcullis. Nothing passes
   without going through it.
3. **A check mark on the pivot** (human approval). The needle turns on a human decision.

The mark is built on a 64 x 64 grid, uses flat fills and a single stroke weight, and has no
gradients, shadows or effects. It is drawn so that it still reads at 16 px: the frame and the
diagonal two-colour needle survive even when the teeth and check mark collapse into pixels.

### Variants

| File | Use it when |
|------|-------------|
| `logo-mark.svg` | Default mark for white and light backgrounds. Navy frame, white pivot. |
| `logo-mark-dark.svg` | Reversed mark for navy, slate and other dark backgrounds. White frame, navy pivot. |
| `favicon.svg` | Browser tabs and anywhere the mark is shown between 16 and 32 px. Solid navy tile, no check mark, simplified teeth. |
| `app-icon.svg` | Full-bleed tile for PWA, home-screen and store icons. Source for `icon-192.png` and `icon-512.png`. |
| `logo-horizontal.svg` | Mark plus wordmark plus tagline, for light backgrounds. |
| `logo-horizontal-dark.svg` | The same lockup, reversed for dark backgrounds. |

Always pick the variant that matches the background. Do not put the light mark on a dark
background or the reversed mark on a light one: the pivot colour is tuned to each.

### The wordmark

The wordmark is the word **Airt** set in a bold system sans-serif with slightly open
letter-spacing, and the tagline **AI SECURITY & RESEARCH FRAMEWORK** in small tracked capitals beneath it.
The tagline is always written with the ampersand, never "and".
The SVG uses the stack `Inter, 'Segoe UI', 'Noto Sans', Roboto, Helvetica, Arial, sans-serif`
at `font-weight: 700` (wordmark) and `600` (tagline), so it renders acceptably with any
generic sans-serif and does not depend on an embedded or external font. If you need a
pixel-identical wordmark on a system without those fonts, use the PNG exports.

## Colour tokens

| Token | Hex | Role |
|-------|-----|------|
| `--airt-navy` | `#0B1220` | Primary dark. Mark ink on light backgrounds, background for reversed material, favicon and app icon tile. |
| `--airt-slate` | `#1E293B` | Secondary dark. Tagline on light backgrounds, rules, panels and secondary surfaces on dark material. |
| `--airt-teal` | `#22D3EE` | Accent. North half of the needle, tagline on dark backgrounds, links and primary actions. |
| `--airt-amber` | `#F59E0B` | Pending review. South half of the needle, and the "pending" state in the dashboard. |
| `--airt-white` | `#FFFFFF` | Reversed ink, light backgrounds, pivot on the light mark. |

Teal and amber are the only two colours that ever appear together inside the needle. Do not
recolour either half, and do not use amber as a general-purpose accent: in the product it
means "waiting for a human".

## Clear space and minimum size

- **Clear space.** Keep an exclusion zone around the logo equal to the height of one
  portcullis tooth on every side, which is one quarter of the mark's height (for a 64 px
  mark that is 16 px; for a 96 px mark, 24 px). No text, other logos or busy imagery may
  enter this zone. The clear space applies to the whole lockup, not just the mark.
- **Minimum size.** Use `logo-mark.svg` or `logo-mark-dark.svg` at 24 px or larger. Below
  24 px use `favicon.svg`. Use the horizontal lockup at 120 px wide or larger; below that,
  drop the wordmark and use the mark alone.
- **Alignment.** In the horizontal lockup the mark and the text block share a common
  vertical centre. Do not stack the wordmark under the mark unless you rebuild the lockup
  with the same proportions.

## Do and don't

**Do**

- Use the SVG files wherever the medium supports them; use the PNGs only where SVG is not accepted.
- Use the light variant on white or light backgrounds, the dark variant on navy, slate or photographs that are dark enough for white to read.
- Scale the logo proportionally and keep the clear space.
- Use `favicon.svg` for anything at 32 px or smaller.
- Write the name as Airt in prose and `airt` in code.

**Don't**

- Don't rotate the needle, straighten it, or reverse its direction; it always points north-east.
- Don't swap or tint the teal and amber halves, and don't render the needle in a single colour.
- Don't outline, add drop shadows, glows, bevels or gradients to the mark.
- Don't stretch, skew or crop the mark, and don't remove the portcullis teeth from the full mark.
- Don't place the mark on a busy background, on teal, or on amber. Use the navy tile from `app-icon.svg` if you need a contained version.
- Don't set the wordmark in a serif, script or condensed face, in mixed case ("AiRT"), or in all capitals.
- Don't put any other element inside the frame or attach text to the mark.

## File inventory

All files are in `docs/images/brand/`. PNGs are exported from the SVGs with cairosvg; the
SVGs are the source of truth.

| File | Dimensions | Background | Notes |
|------|------------|------------|-------|
| `logo-mark.svg` | 64 x 64 viewBox, square | Transparent | Primary mark, light backgrounds |
| `logo-mark-dark.svg` | 64 x 64 viewBox, square | Transparent | Reversed mark, dark backgrounds |
| `favicon.svg` | 64 x 64 viewBox, square | Navy tile | Simplified mark for 16 to 32 px |
| `app-icon.svg` | 64 x 64 viewBox, square | Navy tile | Source for the PNG app icons |
| `logo-horizontal.svg` | 478 x 128 viewBox | Transparent | Mark plus wordmark plus tagline, light |
| `logo-horizontal-dark.svg` | 478 x 128 viewBox | Transparent | Same lockup, reversed |
| `social-preview.svg` | 1280 x 640 viewBox | Navy | Source for the social preview |
| `readme-hero.svg` | 1600 x 400 viewBox | Navy | Source for the README hero |
| `logo-mark.png` | 1024 x 1024 | Transparent | From `logo-mark.svg` |
| `icon-192.png` | 192 x 192 | Navy tile | From `app-icon.svg`, PWA manifest |
| `icon-512.png` | 512 x 512 | Navy tile | From `app-icon.svg`, PWA manifest and stores |
| `logo-horizontal.png` | 2400 x 643 | Transparent | From `logo-horizontal.svg` |
| `logo-horizontal-dark.png` | 2400 x 643 | Transparent | From `logo-horizontal-dark.svg` |
| `social-preview.png` | 1280 x 640 | Navy | GitHub social preview; tagline "Every AI request, reviewed by a human before it reaches your backend" |
| `README-hero.png` | 1600 x 400 | Navy | Banner for the top of the README |

### Regenerating the PNGs

From the repository root, with the project virtual environment:

```bash
uv pip install --python .venv/bin/python cairosvg pillow
.venv/bin/python - <<'PY'
import cairosvg
B = "docs/images/brand"
jobs = [
    ("app-icon.svg", "icon-192.png", 192, 192),
    ("app-icon.svg", "icon-512.png", 512, 512),
    ("logo-mark.svg", "logo-mark.png", 1024, 1024),
    ("logo-horizontal.svg", "logo-horizontal.png", 2400, None),
    ("logo-horizontal-dark.svg", "logo-horizontal-dark.png", 2400, None),
    ("social-preview.svg", "social-preview.png", 1280, 640),
    ("readme-hero.svg", "README-hero.png", 1600, 400),
]
for src, out, w, h in jobs:
    kw = {"output_width": w}
    if h:
        kw["output_height"] = h
    cairosvg.svg2png(url=f"{B}/{src}", write_to=f"{B}/{out}", **kw)
PY
```
