#!/usr/bin/env python3
"""Static release guard for SafeMobile v1.10.6 scan, SAF, 16 KB and edge-to-edge requirements."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "gradle": "app/build.gradle.kts",
    "activity": "app/src/main/java/com/vibesync/antivirus/MainActivity.kt",
    "screen": "app/src/main/java/com/vibesync/antivirus/presentation/SafeMobileScreen.kt",
    "verifier": "app/src/main/java/com/vibesync/antivirus/core/security/SecurityVerifier.kt",
    "baseline": "app/src/main/java/com/vibesync/antivirus/core/security/LocalBaselineTrust.kt",
    "score": "app/src/main/java/com/vibesync/antivirus/core/security/DeviceSecurityScore.kt",
    "worker": "app/src/main/java/com/vibesync/antivirus/core/worker/DeepScanWorker.kt",
    "postInstallWorker": "app/src/main/java/com/vibesync/antivirus/core/worker/MultiLayerScanWorker.kt",
    "scheduler": "app/src/main/java/com/vibesync/antivirus/core/worker/DeepScanScheduler.kt",
    "service": "app/src/main/java/com/vibesync/antivirus/core/worker/ScanForegroundService.kt",
    "dao": "app/src/main/java/com/vibesync/antivirus/data/local/ThreatDao.kt",
    "repository": "app/src/main/java/com/vibesync/antivirus/data/repository/ThreatRepository.kt",
    "coordinator": "app/src/main/java/com/vibesync/antivirus/core/worker/ScanExecutionCoordinator.kt",
    "packageScanner": "app/src/main/java/com/vibesync/antivirus/core/engine/PackageScanner.kt",
    "viewmodel": "app/src/main/java/com/vibesync/antivirus/presentation/SafeMobileViewModel.kt",
    "inventoryModel": "app/src/main/java/com/vibesync/antivirus/core/engine/InstalledAppItem.kt",
    "scanResult": "app/src/main/java/com/vibesync/antivirus/core/engine/ScanResult.kt",
    "scanItemEntity": "app/src/main/java/com/vibesync/antivirus/data/local/ScanSessionItemEntity.kt",
    "scanAudit": "app/src/main/java/com/vibesync/antivirus/data/local/ScanAudit.kt",
    "scanSessionEntity": "app/src/main/java/com/vibesync/antivirus/data/local/ScanSessionEntity.kt",
    "scanSessionState": "app/src/main/java/com/vibesync/antivirus/data/local/ScanSessionState.kt",
    "appScanCache": "app/src/main/java/com/vibesync/antivirus/data/local/AppScanCache.kt",
    "foregroundNotifications": "app/src/main/java/com/vibesync/antivirus/core/worker/ScanForegroundNotifications.kt",
    "banner": "app/src/main/java/com/vibesync/antivirus/presentation/AdMobBanner.kt",
    "proguard": "app/proguard-rules.pro",
}
errors = []
source = {}
for key, relative in FILES.items():
    try:
        source[key] = (ROOT / relative).read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"Missing {relative}: {error}")
        source[key] = ""

gradle = source["gradle"]
version_name = re.search(r'\bversionName\s*=\s*"([^"]+)"', gradle)
version_code = re.search(r"\bversionCode\s*=\s*(\d+)", gradle)
ndk = re.search(r'\bndkVersion\s*=\s*"([^"]+)"', gradle)
if not version_name or version_name.group(1) != "1.10.6":
    errors.append("Gradle versionName must be 1.10.6.")
if not version_code or version_code.group(1) != "20261160":
    errors.append("Gradle versionCode must be 20261160.")
if not ndk or tuple(int(part) for part in ndk.group(1).split(".")[:1]) < (28,):
    errors.append("Gradle must pin Android NDK r28 or higher.")
if "com.google.ai.edge.litert:litert:1.4.2" not in gradle:
    errors.append("16 KB-compatible LiteRT Interpreter runtime 1.4.2 is missing.")
if "org.tensorflow:tensorflow-lite" in gradle:
    errors.append("Legacy TensorFlow Lite AAR must not remain alongside LiteRT.")

activity = source["activity"]
on_create = activity.split("override fun onCreate", 1)[-1].split("override fun onNewIntent", 1)[0]
if "enableEdgeToEdge()" not in on_create:
    errors.append("MainActivity.onCreate must explicitly call enableEdgeToEdge().")
if "LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS" not in on_create:
    errors.append("MainActivity.onCreate must set LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS on API 30+.")
if "setStatusBarColor" in activity or "setNavigationBarColor" in activity:
    errors.append("MainActivity must not use deprecated Window status/navigation color setters.")
if "WindowInsets.safeDrawing" not in source["screen"] and "WindowInsets.systemBars" not in source["screen"]:
    errors.append("Compose screen must apply safeDrawing or systemBars insets.")

baseline = source["baseline"]
for required in (
    "Build.TAGS", "test-keys", "Settings.Global.ADB_ENABLED",
    "ro.boot.verifiedbootstate", "GoogleApiAvailability",
    "NET_CAPABILITY_VALIDATED",
):
    if required not in baseline:
        errors.append(f"Local baseline is missing required heuristic: {required}.")
if "endpoint.isBlank() || !validatedInternet" not in baseline:
    errors.append("Local fallback must apply when the remote URL is absent or internet is not validated.")
if "LOCAL_BASELINE_PASSED" not in source["verifier"] or "applyLocalBaselineFallback" not in source["verifier"]:
    errors.append("SecurityVerifier does not publish the local-baseline fallback result.")
package_scanner = source["packageScanner"]
if 'Log.e("SafeMobileScan", "Publish failed", error)' not in package_scanner:
    errors.append("Package scan result publication failures must be isolated and logged.")
if "OnConflictStrategy.REPLACE" not in source["dao"] or "insertScanSessionItem" not in source["dao"]:
    errors.append("Scan-session item persistence must use REPLACE on Room conflicts.")
if "contentResolver.query(" in source["repository"] or "fromSingleUri(" in source["repository"]:
    errors.append("SAF scanning must not query or request optional single-document metadata.")
if "contentResolver.openInputStream(uri)" not in source["repository"]:
    errors.append("SAF payloads must be read through ContentResolver.openInputStream().")
if 'Log.e("SafeMobileScan", "SAF file scan failed; continuing with the next document: $uri", error)' not in source["repository"]:
    errors.append("SAF read failures must be logged and isolated to the current document.")
if "-keep @androidx.room.Entity class * { *; }" not in source["proguard"]:
    errors.append("R8 must keep Room entity classes and members.")
if "return try" not in source["worker"]:
    errors.append("DeepScanWorker must wrap the entire doWork body in a top-level try/catch.")
if "return try" not in source["postInstallWorker"] or 'Log.e("SafeMobileScan", "Worker CRASHED", error)' not in source["postInstallWorker"]:
    errors.append("The post-install scan worker must contain uncaught exceptions and return Result.failure().")
if "ScanExecutionCoordinator.mutex.withLock" not in source["postInstallWorker"]:
    errors.append("Post-install scans must share the process scan mutex with foreground and periodic scans.")
banner = source["banner"]
if "AdSize.LEADERBOARD" not in banner or "adWidthDp >= 970" not in banner:
    errors.append("AdMob banner must use LEADERBOARD at the 970 dp width threshold.")
worker = source["worker"]
if 'Log.d("ScanDebug", "Worker STARTED for: $tags")' not in worker:
    errors.append("DeepScanWorker must log its WorkManager tags when it starts.")
if 'Log.e("ScanDebug", "Worker CRASHED", error)' not in worker:
    errors.append("DeepScanWorker must log caught worker failures.")
if 'Log.d("ScanDebug", "Worker FINISHED with result: $result")' not in worker:
    errors.append("DeepScanWorker must log its terminal result.")
if "clearScanSessionStateCheckpoints()" not in worker:
    errors.append("DeepScanWorker must clear Room checkpoints before a fresh session.")
scheduler = source["scheduler"]
if ".setRequiredNetworkType(NetworkType.NOT_REQUIRED)" not in scheduler:
    errors.append("Periodic scans must explicitly use NetworkType.NOT_REQUIRED.")
if '.cancelAllWorkByTag(WORK_TAG)' not in scheduler or 'const val WORK_TAG = "ScanWorker"' not in scheduler:
    errors.append("New scans must reset stale tagged ScanWorker work.")
if ".addTag(WORK_TAG)" not in scheduler:
    errors.append("Periodic deep-scan work must carry the ScanWorker tag.")
coordinator = source["coordinator"]
if "Mutex()" not in coordinator:
    errors.append("Foreground and periodic scans must share a coroutine mutex.")
if "ScanExecutionCoordinator.mutex.withLock" not in source["service"] or "ScanExecutionCoordinator.mutex.withLock" not in worker:
    errors.append("Foreground and periodic scans must share the process scan mutex.")
service = source["service"]
if "operation == OP_RESUME || operation == null" not in service:
    errors.append("Only explicit/system service redelivery may resume an interrupted scan.")
if "repo.clearScanSessionStateCheckpoints()" not in service:
    errors.append("Fresh foreground scans must clear stale Room checkpoints.")
dao = source["dao"]
if '@Query("DELETE FROM scan_session_state")' not in dao or "suspend fun clearAllSessions()" not in dao:
    errors.append("ThreatDao must expose clearAllSessions() for scan_session_state.")
repository = source["repository"]
if 'Log.d("ScanDebug", "Scanning: ${result.packageName ?: result.displayName}")' not in repository:
    errors.append("Installed-app scan loops must emit per-item ScanDebug logs.")
if 'Log.d("ScanDebug", "Scanning: ${file.displayName}")' not in repository:
    errors.append("SAF file scan loops must emit per-item ScanDebug logs.")
if "persistedUriPermissions" not in source["screen"] or "persistedReadGrants.isNotEmpty()" not in source["screen"]:
    errors.append("Deep scan must revalidate persisted SAF read grants and reprompt when absent.")

if "integrityCheckPassed" not in source["score"]:
    errors.append("Device Security Score does not consume the effective remote-or-local integrity result.")


# v1.10.6 ColorOS boundary: platform package metadata is deliberately confined
# to PackageScanner and collapsed to scalar values before crossing app layers.
viewmodel = source["viewmodel"]
inventory_model = source["inventoryModel"]
scan_result = source["scanResult"]
for label, text_value in (("SafeMobileViewModel", viewmodel), ("ScanResult", scan_result)):
    forbidden = ("PackageInfo", "ApplicationInfo", "Drawable", "Bitmap", "Bundle", "Parcelable", "SavedStateHandle")
    if any(token in text_value for token in forbidden):
        errors.append(f"{label} must not retain PackageManager, graphics, Bundle or saved-state parcelable objects.")
required_inventory_fields = (
    "val packageName: String", "val appLabel: String", "val verdict: String",
    "val fileSize: Long", "val isSystem: Boolean",
)
if not all(field in inventory_model for field in required_inventory_fields):
    errors.append("InstalledAppItem must expose packageName/appLabel/verdict/fileSize/isSystem scalar fields only.")
if "pending.map { packageName ->" not in package_scanner or "val pending = all.filterNot { it in completedPackageNames }" not in package_scanner:
    errors.append("PackageInfo records must be collapsed to package-name strings before worker coroutine fan-out.")
for label in ("service", "foregroundNotifications"):
    text_value = source[label]
    forbidden = ("PackageInfo", "ApplicationInfo", "Drawable", "Bitmap", "Parcelable", "Bundle", "putParcelable(", "putSerializable(")
    if any(token in text_value for token in forbidden):
        errors.append(f"{label} must not pass Android package/graphics objects or parcelables through service/PendingIntent payloads.")
room_scalar_types = {"String", "Int", "Long", "Boolean", "Float", "Double"}
for label in ("scanItemEntity", "scanAudit", "scanSessionEntity", "scanSessionState", "appScanCache"):
    entity_source = source[label]
    forbidden = ("Bundle", "Parcelable", "Serializable", "PackageInfo", "ApplicationInfo", "Drawable", "Bitmap")
    if any(token in entity_source for token in forbidden):
        errors.append(f"{label} must not contain Bundle, Parcelable, Serializable or Android framework columns.")
    for line in entity_source.splitlines():
        declaration = line.strip()
        if not declaration.startswith("val ") or ":" not in declaration:
            continue
        field_type = declaration.split(":", 1)[1].split("=", 1)[0].strip().rstrip("?,")
        if field_type not in room_scalar_types:
            errors.append(f"{label} contains a non-scalar Room column type: {field_type}.")
            break

if errors:
    print(f"Android release readiness FAILED ({len(errors)} issue(s)):")
    print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
    sys.exit(1)
print("Android release readiness passed: v1.10.6/20261160, NDK r28+, LiteRT 1.4.2, offline scan work and SAF grants.")
