# Offline Attestation Boundaries

**Status:** helper implemented; a complete release trust chain is not configured.

## What the offline helper can check
- Calculate the current APK signing-certificate SHA-256 and compare it with a fingerprint pinned through trusted build/distribution configuration.
- Calculate a bundled asset SHA-256 and compare it with an independently trusted expected digest.
- Bloom loading verifies its declared asset digest before deserializing; missing or invalid manifests/assets fail closed.

## What this cannot guarantee
- A manifest shipped beside an asset is not an independent trust root; replacing both defeats this comparison.
- A signer fingerprint supplied by the APK itself is not a pin. The expected fingerprint must come through a trusted release process; rotation requires a reviewed update.
- Offline checks do not prove the OS is uncompromised, the device is unrooted, or a downloaded definition set is authentic.
- Google Play Integrity and online reputation services are intentionally not used.

## Release requirement
Record and independently pin the expected signing-certificate SHA-256, test certificate rotation, and define a signed, versioned offline signature database before describing the app as attested.
