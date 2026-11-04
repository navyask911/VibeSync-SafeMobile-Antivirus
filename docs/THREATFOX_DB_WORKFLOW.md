# ThreatFox SHA-256 hash database workflow

**Status: permission-gated.** This workflow builds a signed SHA-256-only SafeMobile database from recent ThreatFox IOCs. It does not download malware samples. The Android app downloads only the signed bundle from this repository's GitHub Releases and verifies it against the pinned Ed25519 trust root before activation.

## Source, API and license status

- Source: [ThreatFox](https://threatfox.abuse.ch/) by abuse.ch / Spamhaus.
- API: [ThreatFox Community API documentation](https://threatfox.abuse.ch/api/).
- API URL: https://threatfox-api.abuse.ch/api/v1/
- Recent IOC request: POST with the Auth-Key header and JSON body {"query":"get_iocs","days":1}. The API accepts days from 1 through 7 and returns an object containing a data array.
- This repository extracts only records where ioc_type is exactly sha256_hash; the digest is the record's ioc field. Domains, IP addresses, URLs, file names and all other IOC types are ignored. Invalid SHA-256 IOC values cause a safe failure rather than being silently truncated or rewritten.

**Important licensing point:** ThreatFox Community API data is **not a general CC0 license for commercial use**. The current abuse.ch Terms of Use identify ThreatFox as a platform for which commercial or for-profit use may require a paid enhanced API subscription. The Terms' express CC0 commercial exception applies to Feodo Tracker, SSL Blacklist and YARAify, not ThreatFox. The Terms also prohibit using abuse.ch data to train or improve AI models without Spamhaus' express prior written consent. Review the live [Terms of Use](https://abuse.ch/terms-of-use/) and [ThreatFox API terms](https://threatfox.abuse.ch/api/) before enabling a production pipeline.

A free Auth-Key only authenticates API requests; it is not proof of commercial API access, public redistribution permission or AI-training consent. This repository therefore keeps explicit gates. No .hsb database or public GitHub Release is created unless all required commercial and redistribution settings are present. These settings are repository-owner attestations and do not replace an agreement with abuse.ch / Spamhaus.

## Required GitHub Actions secrets

Configure these secrets only after confirming the applicable rights directly with abuse.ch / Spamhaus:

| Secret | Required value / purpose |
|---|---|
| THREATFOX_AUTH_KEY | Auth-Key for the ThreatFox API |
| THREATFOX_COMMERCIAL_USE_APPROVED | Literal true only when the applicable commercial API use is authorized |
| THREATFOX_REDISTRIBUTION_APPROVED | Literal true only when publishing the derived SHA-256 list in a public GitHub Release is permitted |
| THREATFOX_COMMERCIAL_LICENSE_ID | A real short commercial agreement / permission reference; this is recorded in the signed SAFEHASH header and must match [A-Za-z0-9.+-]{1,80} |
| DB_SIGNING_PRIVATE_KEY | Base64-encoded Ed25519 private key in DER form; never commit it |
| DB_SIGNING_PUBLIC_KEY | Base64 of the raw 32-byte Ed25519 public key trusted by Android |

A missing Auth-Key, missing/false commercial or redistribution gate, missing permission reference, missing signing key, invalid ThreatFox response, empty SHA-256 IOC set, invalid hash, oversized full database, public-key mismatch, signing failure or GitHub Release failure stops the run. No partial hash database is published.

## SAFEHASH format and Android import

The converter writes a header and the normalized ThreatFox hashes:

~~~text
# SAFEHASH version=<monotonically increasing integer> source=threatfox.abuse.ch license=<commercial-permission-reference>
# VERSION: 1
# DATE: <ISO-8601 UTC timestamp>
<64-hex SHA-256>:ThreatFox.SHA256
~~~

VERSION: 1 is an informational format tag. The first-line SAFEHASH version is the rollback-prevention version. The detached Ed25519 signature covers the exact .hsb bytes, including the header.

The Android app imports safe-mobile-hashdb.bundle.zip, containing exactly hashes.hsb and hashes.hsb.sig at ZIP root. Separate .hsb and .sig assets are attached to the GitHub Release for independent audit, not for direct Android import.

The converter refuses to truncate or publish an oversized feed. It enforces the Android limits of 200,000 rows and 16 MiB uncompressed database bytes. A larger complete feed requires a separately reviewed Android streaming/chunking redesign.

## Optional hash enrichment

After creating data/new_hashes.txt, the workflow may enrich hash strings with Hybrid Analysis. VirusTotal remains disabled when its API key or its separate commercial approval is absent and writes vt_malicious_count=-1. The enrichment code sends hash strings only; it does not upload APK/file bytes.

scripts/enrich_threats.py is intentionally separate from the ThreatFox fetcher: it consumes the already-normalized SHA-256 list and authenticates only with the respective VirusTotal / Hybrid Analysis credentials. THREATFOX_AUTH_KEY is used by scripts/build_threatfox_hsb.py for ThreatFox IOC retrieval and must not be reused as a VirusTotal or Hybrid Analysis key.

## ML feature extraction is not part of the ThreatFox feed job

ThreatFox get_iocs supplies indicators, not APK sample binaries or the MalwareBazaar get_file download API. A SHA-256 digest alone cannot be used to derive the 215 Drebin features. Accordingly, this workflow does not download samples, create ML feature rows or dispatch records to the training repository.

scripts/extract_features_ci.py can read ThreatFox SHA-256 IOC records only when a separately authorized sample source stages local APKs named <sha256>.apk. It verifies each APK's SHA-256 before static parsing and refuses feature extraction unless THREATFOX_AI_TRAINING_APPROVED=true is present. Set that flag only after obtaining Spamhaus' express prior written AI-training consent. No source for these APK binaries is configured by this workflow.

## Run and interpret

The scheduled workflow runs every six hours. It requests the last one day of ThreatFox IOCs, so each run can overlap with the previous window; the signed database converter deduplicates repeated hashes within that response. The Android consumer continues to use the same signed bundle contract and GitHub Releases endpoint.

A green Android CI run is not evidence of live ThreatFox access, commercial redistribution permission, AI-training consent or malware-detection efficacy. Detection metrics remain separately measured and documented.
