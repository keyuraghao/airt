# AISRF brand guide

This document describes the AISRF name, logo, colours and the rules for using them.
All source files live in `docs/images/brand/`.

## The name

**AISRF** is the acronym of **AI Security & Research Framework**, and the short name matches
that descriptor exactly. AISRF is an enterprise human-in-the-loop framework: a gateway that
puts a human reviewer between every AI request and your backend, so that nothing reaches
production without a person having approved it.

Write the product name as **AISRF** (all capitals) in prose and in the wordmark. Use `aisrf`
only for the package, CLI, repository and other code identifiers. Do not write "Aisrf" or
"aisrf" in prose. The full descriptor is always written with the ampersand,
"AI Security & Research Framework", never "and".

## The mark: "Held beam"

The mark is a single solid beam with a person cut out of it.

The beam is an AI request in flight. It enters from the left, and it would continue to the
right, straight into your backend, except that a human stands in its path. The person is not
drawn on top of the beam; the shoulders are cut out of it as negative space, and only the
head is painted, in amber, the colour the AISRF dashboard uses for "pending review". The
request is literally held at a person until that person decides.

There are only two elements, the beam and the head, and only two colours in the mark itself.
Everything else is negative space. That is what lets it survive at 16 px (a bright block with
a notch and an amber dot) while still reading as a story at 512 px. It is built on a 64 x 64
grid with flat fills, no strokes, no gradients and no effects.

### Why this mark was chosen

Three concepts were taken to a contact sheet (`candidates.png`): the Held beam, a
"Checkpoint arrow" (an arrow severed from its head by an amber bar) and a "Seam" (a rounded
square sliced on the diagonal with an amber dot at the cut). The Held beam won because it is
the only one that tells the whole product story without a caption, it is the only one whose
key idea, the human, is still unmistakable at 16 px, and it does not resemble an existing
glyph: the arrow drifts toward a media "skip" icon at small sizes and its gaps fuse at 16 px,
while the sliced square reads as a "disabled" symbol and its seam nearly vanishes below
32 px. The runners-up are kept in `candidates/` so the choice can be revisited.

### Variants

| File | Use it when |
|------|-------------|
| `logo-mark.svg` | Default mark for white and light backgrounds. Navy beam, amber head. |
| `logo-mark-dark.svg` | Reversed mark for navy, slate and other dark backgrounds. White beam, amber head. |
| `favicon.svg` | Browser tabs and anywhere the mark is shown between 16 and 32 px. White beam on a solid navy tile. |
| `app-icon.svg` | Full-bleed navy tile with a margin, for PWA, home-screen and store icons. Source for `icon-192.png` and `icon-512.png`. |
| `logo-horizontal.svg` | Mark plus wordmark plus descriptor, for light backgrounds. |
| `logo-horizontal-dark.svg` | The same lockup, reversed for dark backgrounds. |

Always pick the variant that matches the background: the notch is negative space, so it shows
whatever is behind the mark, and the beam must contrast with that.

### The wordmark

The wordmark is **AISRF** set in a bold system sans-serif, all capitals, with slightly open
letter-spacing, and the descriptor **AI SECURITY & RESEARCH FRAMEWORK** in small tracked
capitals beneath it. The SVG uses the stack
`Inter, 'Segoe UI', 'Noto Sans', Roboto, Helvetica, Arial, sans-serif` at `font-weight: 700`
(wordmark) and `600` (descriptor), so it renders acceptably with any generic sans-serif and
does not depend on an embedded or external font. If you need a pixel-identical wordmark on a
system without those fonts, use the PNG exports.

## Colour tokens

| Token | Hex | Role |
|-------|-----|------|
| `--aisrf-navy` | `#0B1220` | Primary dark. Beam on light backgrounds, background for reversed material, favicon and app icon tile. |
| `--aisrf-slate` | `#1E293B` | Secondary dark. Descriptor on light backgrounds, rules, panels and secondary surfaces on dark material. |
| `--aisrf-teal` | `#22D3EE` | Accent. Descriptor on dark backgrounds, links, primary actions and the subtle glow on hero material. |
| `--aisrf-amber` | `#F59E0B` | Pending review. The human head in the mark, and the "pending" state in the dashboard. |
| `--aisrf-white` | `#FFFFFF` | Reversed ink; the beam on dark backgrounds. |

Amber is reserved: in the mark it is the person, and in the product it means "waiting for a
human". Do not use it as a general-purpose accent; teal is the accent.

## Clear space and minimum size

- **Clear space.** Keep an exclusion zone around the logo equal to the diameter of the amber
  head on every side, which is one sixth of the mark's box (for a 64 px box that is about
  11 px; for a 96 px box, 16 px). No text, other logos or busy imagery may enter this zone.
  The clear space applies to the whole lockup, not just the mark.
- **Minimum size.** Use `logo-mark.svg` or `logo-mark-dark.svg` at 24 px or larger. Below
  24 px use `favicon.svg`, whose navy tile guarantees the notch has something to show. Use
  the horizontal lockup at 150 px wide or larger; below that, drop the wordmark and use the
  mark alone.
- **Alignment.** In the horizontal lockup the beam and the text block share a common
  vertical centre. Do not stack the wordmark under the mark unless you rebuild the lockup
  with the same proportions.

## Do and don't

**Do**

- Use the SVG files wherever the medium supports them; use the PNGs only where SVG is not accepted.
- Use the light variant on white or light backgrounds, the dark variant on navy, slate or photographs that are dark enough for white to read.
- Scale the logo proportionally and keep the clear space.
- Use `favicon.svg` or `app-icon.svg` for anything at 32 px or smaller, or on a background you do not control.
- Write the name as AISRF in prose and `aisrf` in code, and spell the descriptor with the ampersand.

**Don't**

- Don't fill the notch. The person must stay negative space; painting the shoulders turns the mark into a generic user icon.
- Don't recolour the head. It is amber on every variant because amber means "pending review".
- Don't outline, add drop shadows, glows, bevels or gradients to the mark, and don't add a face, arms or any detail to the person.
- Don't stretch, skew, rotate or crop the beam, and don't detach the head from the beam.
- Don't place the mark on amber, on teal, or on a busy background. Use the navy tile from `app-icon.svg` if you need a contained version.
- Don't set the wordmark in a serif, script or condensed face, in mixed case ("Aisrf"), or in lowercase.

## File inventory

All files are in `docs/images/brand/`. PNGs are exported from the SVGs with cairosvg; the
SVGs are the source of truth.

| File | Dimensions | Background | Notes |
|------|------------|------------|-------|
| `logo-mark.svg` | 64 x 64 viewBox, square | Transparent | Primary mark, light backgrounds |
| `logo-mark-dark.svg` | 64 x 64 viewBox, square | Transparent | Reversed mark, dark backgrounds |
| `favicon.svg` | 64 x 64 viewBox, square | Navy tile | For 16 to 32 px |
| `app-icon.svg` | 64 x 64 viewBox, square | Navy tile | Source for the PNG app icons |
| `logo-horizontal.svg` | 478 x 128 viewBox | Transparent | Mark plus wordmark plus descriptor, light |
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
| `candidates.png` | 1800 x 700 | Navy | Contact sheet of the three candidates at 256, 32 and 16 px with lockups |
| `candidates/logo-mark-a.svg` | 64 x 64 viewBox | Transparent | Candidate A, "Held beam" (chosen; identical to `logo-mark-dark.svg`) |
| `candidates/logo-mark-b.svg` | 64 x 64 viewBox | Transparent | Candidate B, "Checkpoint arrow" (runner-up) |
| `candidates/logo-mark-c.svg` | 64 x 64 viewBox | Transparent | Candidate C, "Seam" (runner-up) |

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
