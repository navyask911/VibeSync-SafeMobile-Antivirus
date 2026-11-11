#!/usr/bin/env python3
"""Generate Android launcher and splash resources from the approved design pack."""
from __future__ import annotations

import io
import shutil
import sys
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
DESIGN_ASSETS = ROOT / "app/src/main/design_assets"
ARCHIVE = DESIGN_ASSETS / "AppIcons.zip"
SPLASH_SOURCE = DESIGN_ASSETS / "splash_logo.png"
RES = ROOT / "app/src/main/res"

DENSITIES = {
    "mdpi": (48, 108),
    "hdpi": (72, 162),
    "xhdpi": (96, 216),
    "xxhdpi": (144, 324),
    "xxxhdpi": (192, 432),
}
FOREGROUND_SCALE = 0.92  # shrink the supplied logo content by 8% for adaptive safe-zone margin
SPLASH_BACKGROUND = (217, 226, 233)  # clean cool light background


def png_from_archive(archive: ZipFile, member: str) -> Image.Image:
    try:
        raw = archive.read(member)
    except KeyError as exc:
        raise RuntimeError(f"Required design asset missing from AppIcons.zip: {member}") from exc
    try:
        return Image.open(io.BytesIO(raw)).convert("RGBA")
    except Exception as exc:
        raise RuntimeError(f"Cannot decode design asset {member}: {exc}") from exc


def save_png(image: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG", optimize=True)


def process() -> int:
    if not ARCHIVE.exists():
        print("AppIcons.zip is absent; launcher assets have already been processed. Nothing to do.")
        return 0
    if not SPLASH_SOURCE.exists():
        raise RuntimeError(f"Required splash image is missing: {SPLASH_SOURCE}")

    try:
        archive = ZipFile(ARCHIVE)
    except BadZipFile as exc:
        raise RuntimeError(f"Invalid AppIcons.zip: {exc}") from exc

    with archive:
        foreground_source = png_from_archive(archive, "android/adaptive-foreground.png")
        if foreground_source.size != (1024, 1024):
            raise RuntimeError(
                f"Adaptive foreground must be 1024x1024, got {foreground_source.size}"
            )

        # Keep the transparent canvas but shrink the supplied artwork by 8%, centered.
        inner_size = round(1024 * FOREGROUND_SCALE)
        inner = foreground_source.resize((inner_size, inner_size), Image.Resampling.LANCZOS)
        safe_foreground = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
        offset = (1024 - inner_size) // 2
        safe_foreground.alpha_composite(inner, (offset, offset))

        for density, (legacy_size, adaptive_size) in DENSITIES.items():
            legacy = png_from_archive(archive, f"android/mipmap-{density}/ic_launcher.png")
            if legacy.size != (legacy_size, legacy_size):
                legacy = legacy.resize(
                    (legacy_size, legacy_size), Image.Resampling.LANCZOS
                )
            # The source files use JPEG data despite their .png extension; write true PNGs.
            legacy = legacy.convert("RGB")
            directory = RES / f"mipmap-{density}"
            save_png(legacy, directory / "ic_launcher.png")

            round_icon = legacy.convert("RGBA")
            mask = Image.new("L", (legacy_size, legacy_size), 0)
            ImageDraw.Draw(mask).ellipse(
                (0, 0, legacy_size - 1, legacy_size - 1), fill=255
            )
            round_icon.putalpha(mask)
            save_png(round_icon, directory / "ic_launcher_round.png")

            density_foreground = safe_foreground.resize(
                (adaptive_size, adaptive_size), Image.Resampling.LANCZOS
            )
            save_png(density_foreground, directory / "ic_launcher_foreground.png")
            print(
                f"Generated {density}: legacy={legacy_size}px, "
                f"adaptive-foreground={adaptive_size}px, scale={FOREGROUND_SCALE:.2f}"
            )

    # Preserve the untouched supplied splash artwork as drawable-nodpi.
    splash_dir = RES / "drawable-nodpi"
    splash_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SPLASH_SOURCE, splash_dir / "splash_logo.png")

    # SplashScreen's icon is circle-masked. Place the full 1.84:1 brand artwork
    # inside the 160dp safe circle, centered on a 240dp canvas (140x76dp content).
    with Image.open(SPLASH_SOURCE) as opened:
        splash = opened.convert("RGB")
    center_logo = splash.resize((140, 76), Image.Resampling.LANCZOS)
    center_icon = Image.new("RGB", (240, 240), SPLASH_BACKGROUND)
    center_icon.paste(center_logo, ((240 - 140) // 2, (240 - 76) // 2))
    save_png(center_icon, RES / "drawable-mdpi" / "splash_center_icon.png")

    # Remove source design assets only after every generated output has been written.
    ARCHIVE.unlink()
    SPLASH_SOURCE.unlink()
    print(f"Moved splash logo to {splash_dir / 'splash_logo.png'}")
    print("All five densities generated; design ZIP and temporary splash source removed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(process())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
