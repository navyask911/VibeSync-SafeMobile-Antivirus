# TweetFeed SHA-256 hash database workflow

This workflow builds a signed SHA-256-only SafeMobile database from TweetFeed's public weekly malware-tagged hash feed. It does not download malware samples. The Android app imports the signed ZIP bundle from this repository's GitHub Releases and verifies it against its pinned Ed25519 trust root.

## Source, API and license

- Source: [TweetFeed](https://tweetfeed.live/), which republishes indicators shared publicly by the security research community.
- API documentation: [TweetFeed REST API](https://tweetfeed.live/api/).
- Data license: [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/). TweetFeed's published Terms state that data distributed through its JSON API and feeds is public domain under CC0 1.0. The license covers the IOC data, not the website design, source code, trademarks or branding.
- Endpoint: `https://api.tweetfeed.live/v1/week/malware/sha256`.
- Authentication: none. No API key, OAuth token, registration or TweetFeed GitHub Secret is required.

The builder makes a normal HTTPS GET with a standard HTTP client, validates the JSON array and takes only objects with `type == "sha256"`. It extracts the `value` field, validates exactly 64 hexadecimal characters, normalizes to lowercase and deduplicates. Other IOC types are ignored. The script fails closed for non-JSON responses, malformed hashes, empty feeds, API errors, truncated responses, or a dataset that exceeds Android's parser limits.

TweetFeed publishes community-sourced OSINT and explicitly says its IOCs are not independently verified. A feed match should therefore be treated as a reported indicator for review, not independent proof that a file is malicious. The signed hash database uses the label `TweetFeed.CommunityIOC` to preserve that provenance.

## Signing and release format

The workflow requires only the repository's Ed25519 signing material:

| GitHub Secret | Purpose |
|---|---|
| `DB_SIGNING_PRIVATE_KEY` | Base64-encoded Ed25519 private key in DER form; never commit it |
| `DB_SIGNING_PUBLIC_KEY` | Base64 of the raw 32-byte Ed25519 public key trusted by the Android app |

No `TWEETFEED_API_KEY` or TweetFeed authentication secret exists or is read by the workflow.

The SAFEHASH header identifies the source and license:

~~~text
# SAFEHASH version=<monotonically increasing integer> source=tweetfeed.live license=CC0-1.0
# VERSION: 1
# DATE: <ISO-8601 UTC timestamp>
<64-hex SHA-256>:TweetFeed.CommunityIOC
~~~

The detached Ed25519 signature covers the exact `.hsb` bytes, including the header. The Android bundle ZIP contains exactly `hashes.hsb` and `hashes.hsb.sig` at its root. The separate `.hsb` and `.sig` assets are attached to the GitHub Release for audit.

The converter enforces the Android limits of 200,000 records and 16 MiB uncompressed database bytes. It refuses to truncate a larger feed or publish a partial database. TweetFeed documents a maximum of 10,000 records per search and sends an `X-Result-Truncated` header if a response was cut; this workflow treats that header as a fatal error.

## Optional reputation enrichment and ML

The workflow may enrich the hash strings using the separately configured reputation providers in `scripts/enrich_threats.py`. VirusTotal remains disabled unless both its key and the separate commercial-use approval are present. Enrichment is hash-only; no APK/file bytes are uploaded. This optional enrichment is not a condition for signing the TweetFeed database.

TweetFeed publishes IOCs, not APK binaries. A SHA-256 hash by itself cannot produce Drebin-215 features. For that reason, the scheduled feed workflow does not create or dispatch ML feature rows. The offline extractor can only use APKs that have been separately and lawfully staged locally, and it verifies that each APK's SHA-256 matches its TweetFeed IOC before static parsing. The rights for any separately sourced APK samples must be confirmed independently; TweetFeed's CC0 data license does not license third-party APK binaries.

## Operational notes

The workflow runs every six hours and fetches the last seven days of SHA-256 indicators tagged `malware`. Windows overlap by design. The converter removes duplicates within each response; the Android consumer retains its existing signed-bundle and rollback-prevention contract.

A successful CI build verifies code and tests, not the accuracy of individual community IOCs or the efficacy of malware detection. The release notes and app-facing provenance should retain the community-reported status.
