"""Derive every brand asset from the single source logo docs/images/brand/logo.png.

Usage: .venv/bin/python scripts/brand_assets.py
Outputs (docs/images/brand/): logo-mark.png, icon-512.png, icon-192.png, favicon.png, favicon-32.png,
logo-horizontal.png, logo-horizontal-dark.png, social-preview.png, README-hero.png, and copies the
dashboard files into aisrf/dashboard/static/.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "docs" / "images" / "brand"
STATIC = ROOT / "aisrf" / "dashboard" / "static"
NAVY = (11, 18, 32)
TEAL = (34, 211, 238)
AMBER = (245, 158, 11)
WHITE = (255, 255, 255)
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def font(path: str, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


def circle_mark(src: Image.Image, size: int) -> Image.Image:
    """Square source cropped to a circle with transparent corners."""
    img = src.convert("RGBA").resize((size, size), Image.LANCZOS)
    mask = Image.new("L", (size * 4, size * 4), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, size * 4 - 1, size * 4 - 1), fill=255)
    mask = mask.resize((size, size), Image.LANCZOS)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def gradient(width: int, height: int) -> Image.Image:
    img = Image.new("RGB", (width, height), NAVY)
    px = img.load()
    for x in range(width):
        for y in range(height):
            t = (x / width) * 0.6 + (y / height) * 0.4
            px[x, y] = (int(11 + 6 * t), int(18 + 14 * t), int(32 + 22 * t))
    return img


def fit_font(draw: ImageDraw.ImageDraw, text: str, path: str, size: int, max_width: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Largest font at or below `size` whose rendered text fits in max_width."""
    while size > 8:
        f = font(path, size)
        if draw.textlength(text, font=f) <= max_width:
            return f
        size -= 1
    return font(path, size)


def text_block(draw: ImageDraw.ImageDraw, x: int, y: int, scale: float, color_word: tuple, color_tag: tuple, tagline: str, max_width: int) -> int:
    word = fit_font(draw, "AISRF", FONT_BOLD, int(150 * scale), max_width)
    tag = fit_font(draw, tagline, FONT_BOLD, int(34 * scale), max_width)
    draw.text((x, y), "AISRF", font=word, fill=color_word)
    wy = y + int(165 * scale)
    draw.text((x + int(4 * scale), wy), tagline, font=tag, fill=color_tag)
    return wy + int(50 * scale)


def lockup(mark: Image.Image, dark_text: bool) -> Image.Image:
    width, height = 2400, 643
    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    m = circle_mark(mark, 560)
    out.paste(m, (40, (height - 560) // 2), m)
    draw = ImageDraw.Draw(out)
    color_word = NAVY if dark_text else WHITE
    text_block(draw, 660, 150, 1.9, color_word, TEAL, "AI SECURITY & RESEARCH FRAMEWORK", width - 660 - 40)
    return out


def social(mark: Image.Image) -> Image.Image:
    out = gradient(1280, 640).convert("RGBA")
    m = circle_mark(mark, 420)
    out.paste(m, (90, 110), m)
    draw = ImageDraw.Draw(out)
    bottom = text_block(draw, 570, 150, 1.0, WHITE, TEAL, "AI SECURITY & RESEARCH FRAMEWORK", 1280 - 570 - 60)
    draw.line((574, bottom + 6, 630, bottom + 6), fill=AMBER, width=4)
    sub = fit_font(draw, "Every AI request, reviewed by a human", FONT_REG, 30, 1280 - 574 - 60)
    draw.text((574, bottom + 30), "Every AI request, reviewed by a human", font=sub, fill=(226, 232, 240))
    draw.text((574, bottom + 72), "before it reaches your backend", font=sub, fill=(226, 232, 240))
    return out


def hero(mark: Image.Image) -> Image.Image:
    out = gradient(1600, 400).convert("RGBA")
    m = circle_mark(mark, 320)
    out.paste(m, (60, 40), m)
    draw = ImageDraw.Draw(out)
    bottom = text_block(draw, 440, 80, 0.95, WHITE, TEAL, "AI SECURITY & RESEARCH FRAMEWORK", 1600 - 440 - 80)
    subtitle = "Human-in-the-loop gateway, guardrails, red teaming and code review for LLM applications"
    sub = fit_font(draw, subtitle, FONT_REG, 26, 1600 - 444 - 80)
    draw.text((444, bottom + 18), subtitle, font=sub, fill=(203, 213, 225))
    ghost = circle_mark(mark, 520)
    alpha = ghost.split()[3].point(lambda a: int(a * 0.08))
    ghost.putalpha(alpha)
    out.paste(ghost, (1200, -60), ghost)
    return out


def main() -> None:
    src = Image.open(BRAND / "logo.png")
    circle_mark(src, 1024).save(BRAND / "logo-mark.png")
    circle_mark(src, 512).save(BRAND / "icon-512.png")
    circle_mark(src, 192).save(BRAND / "icon-192.png")
    circle_mark(src, 64).save(BRAND / "favicon.png")
    circle_mark(src, 32).save(BRAND / "favicon-32.png")
    lockup(src, dark_text=True).save(BRAND / "logo-horizontal.png")
    lockup(src, dark_text=False).save(BRAND / "logo-horizontal-dark.png")
    social(src).convert("RGB").save(BRAND / "social-preview.png")
    hero(src).convert("RGB").save(BRAND / "README-hero.png")
    STATIC.mkdir(parents=True, exist_ok=True)
    for name in ("logo-mark.png", "favicon.png", "icon-192.png"):
        shutil.copy(BRAND / name, STATIC / name)
    print("brand assets regenerated from", BRAND / "logo.png")


if __name__ == "__main__":
    main()
