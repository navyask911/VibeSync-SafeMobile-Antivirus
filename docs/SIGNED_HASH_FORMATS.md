# Signed local hash definition bundle (Phase A)

**Status:** Implemented parser and signature checks. Distribution of real threat indicators is DISABLED until a valid trusted Ed25519 public key, independently signed versioned bundle, and verified redistribution permissions exist. The included EICAR fixture is for testing only.

Use Android's Storage Access Framework to select a ZIP containing exactly:
- `manifest.json`: UTF-8 JSON with `schema_version:1`, positive `version`, 64-hex `source_key`, 64-hex `sha256` of the original (uncompressed) text payload, and `format` (`hdb`, `hsb`, `sdb`).
- `manifest.sig`: 64 **raw bytes** of an Ed25519 signature over the exact unmodified `manifest.json` bytes.
- One payload called `hashes.hdb`, `hashes.hsb`, or `hashes.sdb` matching the signed format.

The trusted public key is configured only at build time with `SAFE_MOBILE_FEED_ED25519_PUBLIC_KEY_B64` (base64 of the raw 32-byte public key). Never ship a private key. If missing, the SAF import control is DISABLED. The importer rejects unsigned/tampered inputs, hash mismatches, duplicate archive entries, oversized uncompressed entries, malformed rows, and versions at or below the last successful import for each signed source ID. The payload is staged and atomically promoted only after the complete signed payload parses.

## Text formats
- `.hdb`: `md5_hex:exact_decimal_file_size:signature_label`.
- `.hsb`: `sha1_or_sha256_hex:exact_decimal_file_size:signature_label`.
- `.sdb` (SafeMobile custom format, **not** ClamAV .sdb semantics): `algorithm:hex_digest:exact_decimal_file_size:signature_label` where algorithm is `md5`, `sha1`, or `sha256`.

UTF-8, LF records; blank lines and `#` comment-only lines may occur. Max label 120 ASCII characters using letters, digits, hyphen, underscore and period. No wildcard sizes, extended ClamAV attributes, filenames, executable patterns, or colon-separated extensions are accepted. The label describes the **definition** and does not prove an app is malware. A match is an indicator to review.

Parsing uses bounded batches and indexed on-device Room queries; no file hashes are transmitted. At most 8 MiB of unsigned-uncompressed text is accepted in each signed archive for this release. **Peak RSS and detection performance are NOT MEASURED**. The legacy bundled JSON contains only an EICAR test fixture; no real malware signature database is distributed.

Optional signed HTTPS feed downloads use GET-only, a detached Ed25519 response signature and monotonic version guard. They remain disabled without explicit user opt-in and a pinned public key; the `offline` flavor has no INTERNET permission.
