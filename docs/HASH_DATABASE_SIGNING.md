# Signed local hash database

## Runtime status

The multi-hash engine is **DISABLED by default**. No production hash list or trusted database-signing public key is bundled. The existing EICAR-only fixture remains a harmless test marker and is not a useful real-world malware database.

## Trust root and update process

Release/build configuration accepts SAFE_MOBILE_HASHDB_ED25519_PUBLIC_KEY_B64 as a raw 32-byte Ed25519 public key encoded with standard Base64. An empty value keeps the engine disabled. The key is separate from the optional feed-manifest key. It must be provided through a trusted release/owner channel; the private signing key must never be committed to the repository or a client APK.

A bundle is a ZIP with exactly two files and no directories:

- hashes.sdb, hashes.hdb, hashes.hsb, or hashes.s1b
- The matching detached signature file (for example, hashes.sdb.sig)

The detached Ed25519 signature covers the exact original database bytes, including the first-line header. A Base64-encoded 64-byte signature or raw 64-byte signature is accepted. Header syntax is: # SAFEHASH version=42 source=publisher-id license=CC0-1.0. Version must be positive and strictly greater than the last accepted version on import. Startup re-verifies the saved bundle before restoring the active index. Bad signatures, malformed records, duplicate hashes, resource-limit violations and version rollback are rejected.

Multi-algorithm .sdb records use md5:HASH:name, sha1:HASH:name, or sha256:HASH:name. ClamAV-style .hdb (MD5) and .hsb (SHA-256) rows use HASH:size:name; .s1b is the corresponding SHA-1 compatibility form. A .sdb must explicitly prefix each row's algorithm. Labels are metadata and are not independent proof of maliciousness.

The importer accepts no more than 18 MiB of compressed bundle data, 16 MiB per database, 4 KiB per signature, 200,000 records, and 4,096 characters per record line. The fixed ZIP entry allow-list, duplicate-entry check and streaming bounds prevent path traversal and unbounded ZIP expansion. Hashes are inserted in bounded batches inside a Room transaction. A Bloom positive is never a final verdict: each candidate must match an exact indexed Room query.

## Download privacy

The optional WorkManager client performs HTTPS GET only, only in the network-enabled flavor, and only when a trusted public key and user-configured HTTPS URL are present. It rejects redirects and never sends files, hashes, package names, permissions, scan results, telemetry or credentials. The offline flavor retains its no-INTERNET-permission build gate. Manual import uses Android's Storage Access Framework; no data is uploaded.

## Baseline and licensing decision

No production signature dataset is bundled until its redistribution rights, provenance, freshness and false-positive characteristics have been reviewed and its exact bytes have been signed by the configured trusted key. The publicly cited 201,549-row Mendeley manifest is research metadata (CC BY 4.0), not a corpus of APK binaries or an independently authenticated live-threat feed. It is not silently promoted to a production signature baseline.
## Exact-size hash matching in the clean-room integration

The size-aware local lookup extends SHA-256, SHA-1, and MD5 imported-indicator matches with the number of bytes actually hashed. A record with a declared `file_size` must match that size; legacy records with no size field remain supported. In the Ed25519-signed hash database, explicit size metadata from `.hdb` or `.hsb` rows is preserved when stored, and candidate lookups check it after the existing Bloom prefilter. A hash Bloom hit alone is never a threat verdict. Signing keys and a legally vetted production malware corpus are **not bundled**, so the signed database remains **disabled/inert** until separately provisioned. The application does not claim measured detection efficacy.
