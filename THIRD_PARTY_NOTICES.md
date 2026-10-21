# Third-party notices — audit checkpoint

**Status: NOT COMPLETE; this is not a release-compliance certificate.**

 No new third-party runtime library, native scanner, provider-specific threat-intelligence SDK/client, or signature/rule corpus is introduced by this change. The branch does add an app-owned, configurable HTTPS JSON/CSV feed synchronization engine using platform networking and the app's existing Room/WorkManager stack. It is inactive until the user supplies a trusted endpoint; no provider URL, vendor credential, or third-party feed data is bundled by default.

The app's existing Gradle build declares AndroidX/Jetpack Compose and lifecycle components, Room, WorkManager, Kotlin coroutines, Google Tink, Google Mobile Ads, Google's User Messaging Platform (UMP), Google Play In-App Updates, JUnit, and their transitive dependencies. This file does not yet reproduce all licences and notice texts for every exact artifact/version and transitive dependency.

Before a production release, maintainers must review the dependency graph artifact produced by CI, verify each component's exact licence and notice requirements from the published artifact or authoritative upstream source, and then populate this file with the required notices and licence texts. Do not treat a package name or an upstream project's usual licence as proof of the licence for every resolved artifact.

No ClamAV engine, VirusTotal Public API client, YARA runtime, MalwareBazaar/URLhaus/ThreatFox provider-specific client, or remote signature dataset is approved, bundled, or integrated by this change. The generic importer is not a threat-data provider: terms, authorization, and redistribution rights must be reviewed for any endpoint or content a maintainer chooses to use.

The bundled EICAR definition is a harmless antivirus test-marker signature, not a malware sample. No real malware binaries are bundled by this change.
