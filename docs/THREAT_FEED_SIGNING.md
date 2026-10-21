# Signed threat-feed protocol

## Security requirements

A feed is not activated until all of these checks pass:
1. The response includes `X-SafeMobile-Manifest` and `X-SafeMobile-Signature`.
2. Both headers use standard base64. The manifest header decodes to at most 8 KiB of UTF-8 JSON; the signature decodes to exactly 64 bytes.
3. The manifest bytes are verified exactly as received with Ed25519 against a **raw 32-byte trusted public key** supplied at build time with `SAFE_MOBILE_FEED_ED25519_PUBLIC_KEY_B64`.
4. The JSON object includes `schema_version: 1`, a positive integer `version`, `source_key` equal to the SHA-256 of the configured HTTPS URL, and the SHA-256 `sha256` of the uncompressed response body.
5. The downloaded uncompressed body is hashed as it is parsed; after full parsing, its hash must match the signed digest.
6. `version` must be strictly greater than the last accepted version for that source. Version and manifest hash are stored with sync state in Room. Replays, rollback, a missing signature, an unknown key, body tampering, and a source mismatch leave the active indicator table unchanged.

The server signs the exact UTF-8 bytes in the manifest before base64-encoding them. Do not parse and re-serialize the JSON before signing. The signature covers all manifest fields, including schema version, monotonic version, source key and response-body digest.

## Key management and current release gate

The public key is not secret, but it is a trust root. The corresponding private key must remain in a controlled signing system and **must never be committed to this repository or included in the app**. Rotate keys with a reviewed app release and explicit transition policy.

This repository does not currently contain a configured production public key or a signed real-world feed snapshot. Builds without `SAFE_MOBILE_FEED_ED25519_PUBLIC_KEY_B64` can compile, but the feed sync toggle is disabled and the worker rejects remote feeds. This avoids quietly accepting unsigned data. A genuine feed requires source terms permitting redistribution, an independently operated signing process, a pinned public key, a signed versioned snapshot, and provenance review.

## Network boundary

The base and `offline` flavor do not declare INTERNET. The `feed` flavor adds INTERNET but makes requests only after a user enables the separate in-app opt-in switch and configures a trusted HTTPS endpoint. Core scans do not upload scan input, files, hashes, or history. Disabling the switch cancels scheduled and queued feed work.
