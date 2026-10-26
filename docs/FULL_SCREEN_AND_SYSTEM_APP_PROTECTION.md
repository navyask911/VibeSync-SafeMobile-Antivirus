# Full-screen alerts and system-app management exclusions

This change builds on PR #26. It does not replace the five-second siren, TTS, repeat-install
scan scheduling, quarantine deletion handling, theme, signing, or six-hour database sync.

## Full-screen access

On Android 14+, the dashboard checks `NotificationManager.canUseFullScreenIntent()` at initial
composition, on resume, and during its existing foreground status refresh. Denied access keeps a
persistent clickable card visible. The card opens this app's
`Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT` page only when tapped. It does not auto-open
settings or block onboarding, scans, or dashboard use.

Full-screen access is independent of Security Alerts. With Security Alerts enabled, denial still
leaves the existing five-second STREAM_ALARM siren and high-priority notification available,
subject to Android notification/sound/DND controls. The notification's **Review Threat** action
uses the same pending Activity intent as full-screen delivery and opens `ThreatDetectedActivity`.
Opening SafeMobile or dismissing the incident retains PR #26's immediate audio cancellation.

Test: deny full-screen access, enable Security Alerts and notifications, then use the valid harmless
fixture from `scripts/test_siren.sh`. Confirm siren and **Review Threat** work. Return from settings
after granting access: the card must disappear. Revoke access and return: it must reappear.

Android 14+ and Google Play restrict automatic full-screen grants. Declaring the manifest permission
does not make an antivirus automatically eligible as an alarm/calling app.

## Installed-package management policy

`TrustedPackageWhitelist` is the shared **installed-package exclusion policy**, not a malware
verification service. It excludes SYSTEM and UPDATED_SYSTEM_APP flags and namespaces
`com.google.android.*`, `com.android.*`, `com.google.*`, and the existing `android.*` protection.
Installed-app inventory/single-package scans skip them before local hash classification.
Post-install source prompts, reviewable results, incident lists with uninstall actions, Guardian's
source inventory, the optional permission-review worker, and the Sentinel's installed-result guard
use this policy. Existing uninstall guards remain in force. Guardian and permission-review counts
must not reintroduce excluded system packages through their independent package-manager queries.

The dashboard therefore says **System apps protected from review and uninstall**. A clean result
reports no threats in the items actually checked and explicitly says this scan did not verify
system-component integrity. It must not assert “all system apps are verified and secure”.

Downloaded APKs remain files rather than installed components. A Google-like filename or package
namespace is not proof of publisher identity: blindly trusting it would let malware spoof the
allowlist. Raw downloaded files retain exact-hash detection/quarantine and cannot uninstall or
disable the installed OS component. No known-malware file hash is rewritten as a safe verdict.
An installed third-party app can also choose a previously unused Google-like namespace and be
excluded by the requested broad installed-package rule. This is a detection tradeoff, not proof
that the publisher is Google. Strong publisher verification would additionally require trusted
signer certificates; this change does not invent a certificate trust list.

Google Play's Device and Network Abuse policy prohibits unauthorized interference; it does not
define this namespace list as a security certification or require declaring known malware safe.
These management exclusions are SafeMobile's explicit product policy, not a claim of Play
approval or cryptographically verified system integrity.

References:

- https://developer.android.com/about/versions/14/behavior-changes-14#secure-fsi-notifications
- https://source.android.com/docs/core/permissions/fsi-limits
- https://support.google.com/googleplay/android-developer/answer/9888379
- https://developer.android.com/build/configure-app-module

Regression coverage includes system flags/namespaces, an installed system package with a seeded
exact hash, denied/granted system access checks, safe settings targets, and a raw-file threat whose
Google-like name must not create a detection blind spot. Device audio and OEM notification
presentation should still be verified using the existing incident-response testing guide.
