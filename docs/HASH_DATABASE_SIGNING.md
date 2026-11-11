# Signed local hash database

## Runtime status

The multi-hash engine starts inactive until a signed database has been downloaded. The APK/AAB contains no production database. The raw 32-byte Ed25519 public key is embedded in production builds as the verification trust root; the private key remains in GitHub Secrets. The harmless EICAR fixture is not a useful real-world malware database.

## Trust root and update process

Release/build configuration accepts SAFE_MOBILE_HASHDB_ED25519_PUBLIC_KEY_B64 as a raw 32-byte Ed25519 public key encoded with standard Base64. An empty value keeps the engine disabled. The key is separate from the optional feed-manifest key. It must be provided through a trusted release/owner channel; the private signing key must never be committed to the repository or a client APK.

A bundle is a ZIP with exactly two files and no directories:

- hashes.sdb, hashes.hdb, hashes.hsb, or hashes.s1b
- The matching detached signature file (for example, hashes.sdb.sig)

The detached Ed25519 signature covers the exact original database bytes, including the first-line header. A Base64-encoded 64-byte signature or raw 64-byte signature is accepted. Header syntax is: # SAFEHASH version=42 source=publisher-id license=CC0-1.0. Version must be positive and cannot roll back below the active database version. Startup re-verifies the saved bundle before restoring the active index. Bad signatures, malformed records, duplicate hashes, resource-limit violations and version rollback are rejected.

Multi-algorithm .sdb records use md5:HASH:name, sha1:HASH:name, or sha256:HASH:name. ClamAV-style .hdb (MD5) and .hsb (SHA-256) rows use HASH:size:name; .s1b is the corresponding SHA-1 compatibility form. A .sdb must explicitly prefix each row's algorithm. Labels are metadata and are not independent proof of maliciousness.

The Android app checks only this repository's GitHub Releases every 6 hours when connected. WorkManager performs the initial download and later silent updates; every download is signature-verified before atomic activation. Network failures are retried. MalwareBazaar is contacted only by the owner-gated GitHub Actions database builder; the Android app never calls MalwareBazaar, and scan data is never uploaded. The importer accepts no more than 18 MiB of compressed bundle data, 16 MiB per database, 4 KiB per signature, 200,000 records, and 4,096 characters per record line. The fixed ZIP entry allow-list, duplicate-entry check and streaming bounds prevent path traversal and unbounded ZIP expansion. Hashes are inserted in bounded batches inside a Room transaction. A Bloom positive is never a final verdict: each candidate must match an exact indexed Room query.

## Download privacy

The WorkManager hash database client performs HTTPS GET only to this repository's GitHub Releases API and signed release asset hosts. It checks at first launch and every 6 hours when connected, uses bounded redirects and response sizes, verifies every bundle with the embedded Ed25519 trust root, then atomically activates it. The APK/AAB contains no database file. Scan files, hashes, package names, permissions, results and telemetry are never uploaded. The generic optional feed is a separate user-configured feature.

## Baseline and licensing decision

No production signature dataset is bundled until its redistribution rights, provenance, freshness and false-positive characteristics have been reviewed and its exact bytes have been signed by the configured trusted key. The publicly cited 201,549-row Mendeley manifest is research metadata (CC BY 4.0), not a corpus of APK binaries or an independently authenticated live-threat feed. It is not silently promoted to a production signature baseline.
## Exact-size hash matching in the clean-room integration

The size-aware local lookup extends SHA-256, SHA-1, and MD5 imported-indicator matches with the number of bytes actually hashed. A record with a declared `file_size` must match that size; legacy records with no size field remain supported. In the Ed25519-signed hash database, explicit size metadata from `.hdb` or `.hsb` rows is preserved when stored, and candidate lookups check it after the existing Bloom prefilter. A hash Bloom hit alone is never a threat verdict. The private signing key and production database are **not bundled**. Hash matching remains inactive until a valid signed GitHub Release database is downloaded. The application does not claim measured detection efficacy.
