#!/usr/bin/env python3
"""Fail-closed source guard for optional Global Threat Intelligence contributions."""
from pathlib import Path
import re
import sys

ROOT = Path("app/src/main/java/com/vibesync/antivirus")
donor = ROOT.joinpath("core/security/GlobalThreatIntelligence.kt").read_text(encoding="utf-8")
settings = ROOT.joinpath("presentation/ProductSettings.kt").read_text(encoding="utf-8")
incident = ROOT.joinpath("core/observer/ThreatDetectedActivity.kt").read_text(encoding="utf-8")
screen = ROOT.joinpath("presentation/SafeMobileScreen.kt").read_text(encoding="utf-8")
notifier = ROOT.joinpath("core/observer/SecurityAlertNotifier.kt").read_text(encoding="utf-8")

errors = []
endpoint = "https://misty-fog-d936.navyask911.workers.dev/donate"
if donor.count(endpoint) != 1:
    errors.append("The client must use only the approved fixed HTTPS Worker endpoint.")
if '.getBoolean(KEY_ENABLED, false)' not in donor:
    errors.append("Master contribution consent must default to OFF.")
if donor.count("GlobalThreatIntelligenceConsent.isEnabled(app)") < 4:
    errors.append("The client must check consent before extraction and immediately before upload.")
if "result.verdict != ScanVerdict.THREAT" not in donor:
    errors.append("Only confirmed THREAT results may be donated.")
if "FEATURE_COUNT = 215" not in donor or "features.size == FEATURE_COUNT" not in donor:
    errors.append("Any transmitted feature vector must contain exactly 215 values.")
if '.put("verdict", ScanVerdict.THREAT.name)' not in donor:
    errors.append("Every threat contribution must identify its confirmed THREAT verdict.")
if '.put("sha256", sha256)' not in donor or '.put("features", features)' not in donor:
    errors.append("The JSON payload must contain the malware hash and feature vector.")
if ".followRedirects(false)" not in donor or ".followSslRedirects(false)" not in donor:
    errors.append("Contribution requests must not forward the payload through redirects.")
for pattern in (r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}", r"Authorization\s*[:=]"):
    if re.search(pattern, donor, re.IGNORECASE):
        errors.append("A GitHub token or authorization credential was found in the Android client.")
for field in ('"packageName"', '"deviceId"', '"androidId"', '"location"'):
    if field in donor:
        errors.append("A personal or device identifier field was added to the JSON payload.")
if "global_threat_intelligence_title" not in settings:
    errors.append("Settings must expose the optional contribution switch.")
if "global_threat_intelligence_donate_message" not in incident:
    errors.append("The install incident must expose a per-sample consent prompt.")
if "GlobalThreatIntelligenceDonationScheduler.enqueue(context, detectedThreat)" not in screen:
    errors.append("The per-sample Donate action must enqueue lifecycle-independent background work.")
if "GlobalThreatIntelligenceDonor(context).donateScanResult" in screen:
    errors.append("Donation uploads must not run directly from the Compose screen.")
if "GlobalThreatIntelligenceDonationScheduler.enqueueInstalledPackage" not in incident:
    errors.append("Install-alert donation must also enqueue durable WorkManager delivery.")
if "GlobalThreatIntelligenceDonor(this@ThreatDetectedActivity)" in incident:
    errors.append("Install-alert donation must not run in the Activity lifecycle scope.")
if "Donation worker started" not in worker:
    errors.append("The donation worker must log its start and local source type.")
if "operation.result.addListener" not in worker:
    errors.append("WorkManager queue persistence failures must be logged.")
if "EXTRA_SHA256" not in notifier:
    errors.append("The install incident must bind donation to the detected hash.")

worker = ROOT.joinpath("core/security/GlobalThreatIntelligenceDonationWorker.kt").read_text(encoding="utf-8")
manifest = Path("app/src/main/AndroidManifest.xml").read_text(encoding="utf-8")
if "CoroutineWorker" not in worker or "NetworkType.CONNECTED" not in worker:
    errors.append("Donation delivery must use a network-constrained WorkManager CoroutineWorker.")
if "Result.retry()" not in worker:
    errors.append("Transient donation transport errors must be retryable.")
if 'Log.d(TAG, "Sending hash to Cloudflare: $url")' not in donor:
    errors.append("A clear Logcat line must identify the Cloudflare donation URL.")
if 'Log.e(TAG, "Failed", error)' not in donor:
    errors.append("Donation exceptions must be logged with the exception.")
if "Could not stage selected document for background donation" not in donor:
    errors.append("A SAF document staging failure must be logged before the network request is skipped.")
if "takePersistableUriPermission" not in screen:
    errors.append("Selected documents must retain read permission for deferred donation work.")
if 'android.permission.INTERNET' not in manifest:
    errors.append("The main app manifest must declare INTERNET permission.")

if errors:
    print("Global Threat Intelligence privacy guard FAILED:", file=sys.stderr)
    print("\n".join("- " + item for item in errors), file=sys.stderr)
    raise SystemExit(1)
print("Global Threat Intelligence guard passed: OFF by default, per-sample consent, fixed HTTPS Worker, 215 binary features, no Android GitHub credentials.")
