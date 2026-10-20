# Third-party notices — audit checkpoint

**Status: NOT COMPLETE; this is not a release-compliance certificate.**

No new third-party runtime library, native scanner, threat feed, signature database, or rule collection is introduced by the proprietary-hardening change.

The app's existing Gradle build declares AndroidX/Jetpack Compose and lifecycle components, Room, WorkManager, Kotlin coroutines, Google Tink, Google Mobile Ads, Google's User Messaging Platform (UMP), Google Play In-App Updates, JUnit, and their transitive dependencies. This file does not yet reproduce all licences and notice texts for every exact artifact/version and transitive dependency.

Before a production release, maintainers must review the dependency graph artifact produced by CI, verify each component's exact licence and notice requirements from the published artifact or authoritative upstream source, and then populate this file with the required notices and licence texts. Do not treat a package name or an upstream project's usual licence as proof of the licence for every resolved artifact.

No ClamAV engine, VirusTotal Public API client, YARA runtime, MalwareBazaar client, URLhaus client, or remote threat-intelligence feed is approved or added by this change.

The bundled EICAR definition is a harmless antivirus test-marker signature, not a malware sample. No real malware binaries are bundled by this change.
