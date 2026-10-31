#!/usr/bin/env python3
"""Strict byte validation for SHA-pinned MalwareBazaar Android APK samples.

Downloaded MalwareBazaar bytes are password-protected ZIP containers, not APKs.
Never execute extracted content or upload malware binaries as CI artifacts.
"""
import hashlib
import io
import re
import zipfile

APK_LIMIT = 75 * 1024 * 1024
ARCHIVE_LIMIT = 90 * 1024 * 1024
MANIFEST_LIMIT = 2 * 1024 * 1024
SHA256 = re.compile(r"^[a-f0-9]{64}$")
APK_ZIP_MAGIC = b"PK\x03\x04"
DEX_MAGIC = b"dex\n"

class InvalidAndroidAPK(ValueError):
    """Candidate was not a verified Android APK (safe to reject/replace)."""


def validate_apk_bytes(payload, sha256):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= APK_LIMIT:
        raise InvalidAndroidAPK("empty or oversized extracted payload")
    if payload.startswith(b"MZ") or payload.startswith(b"\x7fELF"):
        raise InvalidAndroidAPK("Windows PE or ELF is not an Android APK")
    if payload.startswith(DEX_MAGIC):
        raise InvalidAndroidAPK("raw DEX is not an installable APK for this benchmark")
    if payload[:4] != APK_ZIP_MAGIC:
        raise InvalidAndroidAPK("missing APK ZIP magic PK\\x03\\x04")
    if not SHA256.fullmatch(str(sha256)) or hashlib.sha256(payload).hexdigest() != sha256:
        raise InvalidAndroidAPK("SHA-256 mismatch after ZIP extraction")
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as apk:
            manifest = apk.getinfo("AndroidManifest.xml")
            if manifest.is_dir() or manifest.file_size < 8 or manifest.file_size > MANIFEST_LIMIT:
                raise InvalidAndroidAPK("missing or invalid AndroidManifest.xml")
            with apk.open(manifest) as source:
                axml = source.read(MANIFEST_LIMIT + 1)
            # A compiled Android APK has binary Android XML (AXML).
            if len(axml) < 8 or axml[:4] != b"\x03\x00\x08\x00":
                raise InvalidAndroidAPK("AndroidManifest.xml is not Android binary XML")
    except (zipfile.BadZipFile, KeyError, RuntimeError, EOFError, OSError) as exc:
        raise InvalidAndroidAPK("corrupt or non-Android ZIP package") from exc
    return payload


def unpack_malwarebazaar_apk(archive, sha256, source_filename):
    """Decrypt infected ZIP, bound decompression, reject non-APK and verify SHA."""
    if not SHA256.fullmatch(str(sha256)):
        raise InvalidAndroidAPK("invalid SHA-256")
    if not isinstance(source_filename, str) or not source_filename.lower().endswith(".apk"):
        raise InvalidAndroidAPK("declared filename is not .apk (DEX/EXE/ELF rejected)")
    if not isinstance(archive, bytes) or not archive.startswith(APK_ZIP_MAGIC) or len(archive) > ARCHIVE_LIMIT:
        raise InvalidAndroidAPK("MalwareBazaar response is not a bounded encrypted ZIP")
    try:
        import pyzipper
        with pyzipper.AESZipFile(io.BytesIO(archive)) as container:
            members = [z for z in container.infolist() if not z.is_dir()]
            if len(members) != 1:
                raise InvalidAndroidAPK("encrypted archive must have exactly one file")
            member = members[0]
            name = member.filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
            # Some containers use a SHA-256 basename. Reject known non-APK extensions.
            if not (name.endswith(".apk") or name == sha256):
                raise InvalidAndroidAPK("inner ZIP file is not an APK")
            if not 1 <= member.file_size <= APK_LIMIT:
                raise InvalidAndroidAPK("extracted member violates the size limit")
            with container.open(member, pwd=b"infected") as stream:
                payload = stream.read(APK_LIMIT + 1)
    except (zipfile.BadZipFile, RuntimeError, EOFError, OSError, NotImplementedError, OverflowError) as exc:
        raise InvalidAndroidAPK("cannot decrypt or decompress infected ZIP") from exc
    return validate_apk_bytes(payload, sha256)
