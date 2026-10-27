# Native localization for v1.0.12

The owner requested native XML edits, sequentially, without translation APIs,
translation clients, or generation scripts. PR #35 was squash-merged into main
at e426f1f734e6b3d90824abd427a84335480003c7. The external translator script,
its tests and requirements were removed in the Spanish commit.

Work branch: `feat/v1.0.12-native-localization`.

| Order | Language | Android folder | Status |
|---|---|---|---|
| 1 | Spanish | values-es | Complete; 700 keys validated |
| 2 | French | values-fr | Complete; 700 keys validated |
| 3 | Hindi | values-hi | Complete; 700 keys validated |
| 4 | Kannada | values-kn | Complete; 700 keys validated |
| 5 | Russian | values-ru | Complete; 700 keys validated |
| 6 | Chinese | values-zh-rCN | Complete; 700 keys validated |
| 7 | Japanese | values-ja | Complete; 700 keys validated |
| 8 | Arabic | values-ar | Complete; 700 keys validated |
| 9 | Portuguese | values-pt | Complete; 700 keys validated |
| 10 | Italian | values-it | Complete; 700 keys validated |
| 11 | Korean | values-ko | Complete; 700 keys validated |
| 12 | Turkish | values-tr | Complete; 700 keys validated |
| 13 | Vietnamese | values-vi | Complete; 700 keys validated |
| 14 | Indonesian | values-id | Complete; 700 keys validated |
| 15 | Bengali | values-bn | Complete; 700 keys validated |
| 16 | Tamil | values-ta | Complete; 700 keys validated |
| 17 | Telugu | values-te | Complete; 700 keys validated |
| 18 | Marathi | values-mr | Complete; 700 keys validated |
| 19 | Gujarati | values-gu | Complete; 700 keys validated |
| 20 | Malayalam | values-ml | Complete; 700 keys validated |
| 21 | Punjabi | values-pa | Pending |
| 22 | Urdu | values-ur | Pending |

Each completed locale includes all default string keys, including the separate
posture, incident, siren, download and uninstall resources. XML parsing,
duplicate-key detection, source-key coverage and printf-placeholder parity were
checked locally using the existing runtime XML parser. Unchanged entries are
reviewed brand names, native language names, technical identifiers or numeric
formats (French “Notifications” is also a valid French word).

Existing stale translations for storage access and absolute trust are corrected
while each language is processed. No translation service is contacted. Other
locale folders are outside the owner's 22-language scope and retain their
existing fallback until separately translated.

Do not mark the complete 22-language task finished or publish the fully localized
v1.0.12 release until all rows are complete and the final head passes all five
Android CI checks. Then merge, verify main and use the repository's signed APK
release workflow. Current app version is 1.0.12, versionCode 20261104; preserve
application ID and signing settings.
