# v1.0.13: install monitoring, trust controls and local charts

Version 1.0.13, code 20261106. Application identity, signing configuration,
existing database schema/migrations and absolute package trust are preserved.
New UI strings are maintained directly in XML for all 51 configured locales.
The earlier complete localization coverage remains the 22 requested languages;
the other locales have their new v1.0.13 labels translated as well.

## Install delivery and alarm diagnostics

After the privacy disclosure is accepted, opening the app starts the install
sentinel. Its persistent low-priority notification shows that monitoring is
active. It owns one runtime receiver for protected system PACKAGE_ADDED and
PACKAGE_REPLACED broadcasts, irrespective of the installer. Messaging apps do
not supply a separate APK-content URI to this protected system broadcast.

The service is idle until an install event arrives: no polling, network loop,
timer or wake lock is added. A single serial processor performs local checks;
WorkManager retains a durable fallback. Event IDs and completed assessment state
prevent the two paths from alerting twice. The receiver posts silent delivery
proof before dispatch; confirmed matches replace it with the existing bounded
five-second alarm. Full-screen presentation still requires Android approval.
Notification permission, notification-channel settings, force-stop, and OEM
background restrictions can limit presentation or delivery. No service can
guarantee survival after an Android/ColorOS force-stop.

Use Settings > install monitoring or the notification Stop action to disable it.
Opening the app does not override that choice. Background Application/worker
startup does not attempt to launch a new foreground service.

The file `SafeMobile-Siren-Test.apk` has package `com.safemobile.sirentest`;
hyphens are not legal in Android package identifiers. Installing this reserved
component-free, no-code fixture triggers a clearly marked diagnostic alarm,
without importing a database or recording a malware verdict. Release builds
verify that the reserved package has no executable application code, activities,
services, receivers, providers or instrumentation before taking this path.
Other package names containing a normalized `sirentest` marker trigger this
diagnostic only in debug builds. User trust takes priority even over diagnostics.
Real applications retain all ordinary signature, rule and heuristic checks.

Build the harmless fixture with the existing `scripts/test_siren.sh`. CI builds
it before emulator startup, pushes it to `/data/local/tmp/`, and an instrumentation
test starts monitoring, backgrounds the activity, installs it using the system
package manager, verifies the diagnostic notification/audio, and verifies audio
stops. No malware samples or external translation services are used.

For a physical WhatsApp/Oppo test, enable notification permission, confirm the
persistent sentinel notification, background SafeMobile, then install the
fixture through WhatsApp. Inspect local logs with:

```sh
adb logcat -s SafeMobileScan SafeMobileInstallSentinel SafeMobileSecurityAlert
```

## Trust and analytics

Trusted scan cards and previously posted incident details hide the primary
uninstall action. Their name-row options expose guarded Android uninstall and
Remove trust. Revocation removes both package and legacy digest trust. Results
are marked unscanned until reassessed; an old override is never relabeled as a
measured clean result.

The dashboard and analytics destination use Compose Canvas donut/bar charts.
Room aggregates cover all stored audits, not the 50-row recent-history window.
No-match results are not a safety guarantee; detected threats are not claimed
as blocked installations. Other/incomplete results are shown separately.
Weekly bars count distinct recorded scan sessions Monday–Sunday, including
legacy rows and partial runs. Local calendar boundaries respect DST; missing
days remain zero. Charts expose accessible labels and mirror bars with RTL text.

## Overlay settings

The first intent always uses ACTION_MANAGE_OVERLAY_PERMISSION with the flagged
app's dynamic `package:` URI and FLAG_ACTIVITY_NEW_TASK. A regression test checks
two distinct app identities. Android 11+ deliberately ignores this URI and opens
the global list; a localized hint identifies the app to select. The application
does not claim it can override that platform behavior or change permissions.

Reference: https://developer.android.com/about/versions/11/privacy/permissions
