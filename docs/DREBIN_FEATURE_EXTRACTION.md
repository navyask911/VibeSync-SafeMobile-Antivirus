# Drebin-215 APK Feature Extraction

## Installed packages: base APK plus splits

For an installed third-party package, `PackageScanner` resolves
`ApplicationInfo.sourceDir` as the base APK and reads every path in
`ApplicationInfo.splitSourceDirs`. The base path is passed first, followed by
the distinct split paths. All of those APKs now feed one package-wide
`DrebinApkExtractor` call and one 215-feature vector.

Each supplied APK must be readable, contain a valid binary
`AndroidManifest.xml`, and be completely traversable within the parser limits.
Manifest permissions and `<action android:name>` values are unioned across the
base and split manifests. Every DEX entry matching `classes*.dex` is traversed
in every component, including DEX stored only in a feature split. DEX class
definitions, string references, invoked method references, and the two tracked
callback method names contribute to one combined observation set. The feature
contract vectorizes that union once.

The installed-package hash/YARA path also inspects the base and declared split
APK files. The Drebin extraction path previously did not: it accepted only the
base APK file. That meant feature-module permissions/actions or DEX code present
only in a split could be absent from the ML vector even when the other scan
engines had inspected the split.

## Standalone and SAF APKs

A standalone APK passed to `PackageScanner.scanFile` is extracted as one APK.
A SAF/content-URI APK passed through `scanStream` is staged temporarily in the
app-private cache and follows the same one-file path. These flows do not have
PackageManager-provided sibling split paths, so a selected standalone/base APK
cannot expose features held only in separately selected split APKs. A ZIP
containing APKs continues through the archive-inspection path; it is not treated
as a PackageManager-installed split set.

## Failure versus a valid zero vector

Extraction returns a sealed result: `Features(vector, apkCount, dexCount)` or
`Unscannable(reason)`. Failure reasons include unreadable/missing files,
invalid ZIP/APK, parser limits, invalid/missing manifest, missing/invalid DEX,
and invalid schema. If any declared component is missing, unreadable, malformed,
or only partially parsed, the whole aggregate fails. The ML caller records the
reason code and the typed TFLite entry point returns no score; no fallback
`FloatArray(215)` is fabricated or inferred.

A 215-element all-zero vector remains valid when all supplied manifests and DEX
entries were parsed successfully, at least one valid DEX was present, and none
of the 215 schema features matched. That successful result is distinguishable
from every extraction failure.

## Offline and resource limits

The parser does not execute APK code or upload APK content. It reads bounded
ZIP entries and uses dexlib2 only for local DEX traversal. The current limits are:
129 APK components (base plus up to 128 splits), 512 MiB aggregate APK bytes,
1,800 ZIP entries per APK and 12,000 entries aggregate, 2 MiB per manifest,
4 MiB per DEX entry and 12 MiB DEX bytes aggregate, 30 DEX entries,
300,000 string references, 150,000 methods, 1,500,000 instructions, and a
5-second extraction budget. Exceeding a limit is an explicit
`LIMIT_EXCEEDED` result, never a partial feature vector.

The current Drebin parser extracts manifest permissions/actions and DEX-based
signals. It does not disassemble native `.so` libraries, interpret resource
tables, unpack encrypted payloads, or treat non-DEX assets as Drebin features.
Apps with no DEX anywhere in the supplied APK set are explicitly
`DEX_MISSING`; this does not mean the APK is clean.

## Model readiness

This change does not alter the model artifact, feature schema, inference tensor
contract, threshold metadata, model readiness constants, verdict fusion, or
production approval. The model remains `research_candidate` with
`MODEL_VALIDATED=false` and `MODEL_PRODUCTION_READY=false`.
