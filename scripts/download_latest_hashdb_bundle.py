#!/usr/bin/env python3
"""Fetch the newest published release carrying the owner-signed SAFEHASH bundle."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ASSET = "safe-mobile-hashdb.bundle.zip"
DATABASE = "hashes.hsb"
SIGNATURE = "hashes.hsb.sig"
MAX_BUNDLE_BYTES = 18 * 1024 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4096
SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


def run(*args: str, capture: bool = False) -> str:
    result = subprocess.run(args, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else ""


def verify_signature(database: bytes, signature: bytes, public_key_b64: str) -> None:
    public_key = base64.b64decode(public_key_b64, validate=True)
    if len(public_key) != 32:
        raise ValueError("Trusted Ed25519 public key must decode to 32 bytes.")
    if len(signature) != 64:
        try:
            signature = base64.b64decode(signature.strip(), validate=True)
        except Exception as error:
            raise ValueError("Detached signature is neither 64 raw bytes nor Base64.") from error
    if len(signature) != 64:
        raise ValueError("Detached Ed25519 signature must be 64 bytes.")

    with tempfile.TemporaryDirectory(prefix="hashdb-verify-") as temp:
        root = Path(temp)
        (root / "public.der").write_bytes(SPKI_ED25519_PREFIX + public_key)
        (root / "database.hsb").write_bytes(database)
        (root / "database.sig").write_bytes(signature)
        run("openssl", "pkey", "-pubin", "-inform", "DER", "-in",
            str(root / "public.der"), "-out", str(root / "public.pem"))
        run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
            str(root / "public.pem"), "-in", str(root / "database.hsb"),
            "-sigfile", str(root / "database.sig"))


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    token = os.environ.get("GH_TOKEN", "").strip()
    if not repository or not token:
        print("SAFE STOP: GitHub repository context or read token is missing.", file=sys.stderr)
        return 2

    output_dir = Path("app/src/main/assets")
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / ASSET
    destination.unlink(missing_ok=True)

    try:
        # Query all stable published releases and choose the newest one that
        # actually carries the database bundle (the app APK release may be newer).
        release_rows = run(
            "gh", "api", "--paginate", f"repos/{repository}/releases?per_page=100",
            "--jq",
            f'.[] | select(.draft == false and .prerelease == false and '
            f'any(.assets[]?; .name == "{ASSET}")) | '
            '[.published_at, .tag_name] | @tsv',
            capture=True,
        )
        candidates = [line.split("\t", 1) for line in release_rows.splitlines() if "\t" in line]
        if not candidates:
            raise ValueError("No published stable release contains the signed database bundle.")
        _, tag = max(candidates, key=lambda row: row[0])
        run("gh", "release", "download", tag, "--repo", repository,
            "--pattern", ASSET, "--dir", str(output_dir), "--clobber")

        if not destination.is_file() or destination.stat().st_size > MAX_BUNDLE_BYTES:
            raise ValueError("Downloaded bundle is missing or exceeds the 18 MiB limit.")
        with zipfile.ZipFile(destination) as archive:
            if set(archive.namelist()) != {DATABASE, SIGNATURE}:
                raise ValueError("Bundle must contain exactly hashes.hsb and hashes.hsb.sig.")
            database = archive.read(DATABASE)
            signature = archive.read(SIGNATURE)
        if not database or len(database) > MAX_DATABASE_BYTES:
            raise ValueError("Database is empty or exceeds the 16 MiB app limit.")
        if not signature or len(signature) > MAX_SIGNATURE_BYTES:
            raise ValueError("Detached signature is empty or exceeds the app limit.")

        public_key = os.environ.get("SAFE_MOBILE_HASHDB_ED25519_PUBLIC_KEY_B64", "").strip()
        require_signature = os.environ.get("REQUIRE_DB_SIGNATURE", "false").lower() == "true"
        if public_key:
            verify_signature(database, signature, public_key)
            print("Verified bundle Ed25519 signature against the app trust root.")
        elif require_signature:
            raise ValueError("Trusted Ed25519 public key is missing; refusing production APK build.")

        print(f"Bundled {ASSET} from signed database release {tag}.")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError, zipfile.BadZipFile,
            json.JSONDecodeError) as error:
        destination.unlink(missing_ok=True)
        print(f"SAFE STOP: Could not prepare signed database asset: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
