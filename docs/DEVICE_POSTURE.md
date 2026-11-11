# Device Posture and Loophole Monitor

Device Posture is available from the dashboard and features menu. It audits permission metadata
in the current Android profile. It does not declare an AccessibilityService or notification
listener, bind to these services, read screens/messages/notifications, click controls, revoke
permissions, uninstall apps, or change device policies. It makes no network requests. Existing
malware scans and six-hour signed GitHub definition updates are independent and unchanged.

## Findings and Settings navigation

* Accessibility: enabled services, including each component and its screen-content capability.
* Device administrators: every active administrator exposed by Android.
* Notification access: enabled listener components from the same read-only secure setting used
  by AndroidX NotificationManagerCompat. No notification contents are collected.
* Draw over other apps: visible installed packages declaring SYSTEM_ALERT_WINDOW, with the
  read-only AppOps grant check. Allowed grants are HIGH RISK. Denied declarations are labelled
  not granted; an unavailable query is labelled unknown, never assumed allowed or safe.

Non-system enabled accessibility, administrator and notification-reader access is HIGH RISK.
Every enabled overlay is HIGH RISK. These labels describe capabilities, **not a spyware or
malware verdict**. Legitimate screen readers, work management and companion apps can need this
access. System classification uses actual FLAG_SYSTEM / FLAG_UPDATED_SYSTEM_APP metadata,
not an app's name or a spoofable `com.google.*` namespace. System entries are informational
permission metadata, with no uninstall controls; existing system-package scan protections remain.

“Fix this” opens the app/component's Android settings where supported. Accessibility detail
and notification-listener detail pages have category-page fallbacks; administrator access opens
the active-administrators page, never an activation request. Overlay access targets the package;
Android 11+ and OEMs may show the category list instead. General Settings is the final fallback.
SafeMobile cannot bypass Android's settings restrictions or revoke grants itself. Changes appear
after returning to the app or running another audit. An incomplete query retains last-known
findings with a stale label until access can be checked again.

Android package visibility, managed profiles and OEM restrictions can limit coverage. Unknown
metadata is shown explicitly. This audit does not certify that a device has no spyware.

## Six-hour monitor

After the existing privacy disclosure is accepted, WorkManager schedules an immediate baseline
and a separate six-hour periodic job with no network requirement. Android may defer jobs during
Doze or battery restrictions; this is not real-time permission interception. The screen includes
a monitor toggle and comparison/storage status. Disable it to cancel these jobs.

The monitor compares accessibility, active administrators and notification listeners (not
overlays). Each category's first successful read establishes a **silent baseline**. Later newly
observed package/capability pairs create a pending change. Multiple services in one app are
deduplicated by capability. Revocation removes pending changes; a later observed re-grant
creates a fresh event. Grants and revocations entirely between checks cannot be observed.
If a category is unavailable its prior baseline is retained and the job retries with exponential
backoff. Foreground audits never advance this comparison baseline.

Notifications use a separate high-importance channel, respect Android notification permission
and the existing opt-in **Security Alerts** switch, and open Device Posture. The message says
the app gained access since a previous check; it does not claim precisely when or accuse it of
spying. Security-change notifications never invoke the malware siren, TTS or full-screen alert.
Dashboard warnings and manual review work with alerts disabled. Pending changes remain
encrypted until delivered or observed revoked. They are persisted before delivery and
acknowledged afterward; stable event notification identifiers make retries idempotent.

## Local encrypted state

The snapshot contains only package/capability identifiers, initialized categories, comparison
times and undelivered event times. It contains no app labels, screen text, message contents or
notification contents. Tink AES-256-GCM authenticates the entire snapshot with an
application/schema-bound associated-data value. Android Keystore wraps the separate keyset;
the implementation refuses Tink's unprotected-keyset fallback. AtomicFile stores ciphertext in
`noBackupFilesDir`. App backup is disabled, including shared-preference keysets. No snapshot
is uploaded or exported. Clear app data/uninstall deletes this local history and keys.

Unreadable ciphertext, unavailable Keystore and write failures fail closed: the job retries,
shows a storage error, and does not silently replace the baseline or save plaintext. Local
non-sensitive preferences hold only the monitor toggle and numeric health/status counters.

## Validation

Unit tests cover quiet initialization, new grants, revocation/re-grant, partial coverage,
deduplication, overlay exclusion, stale finding retention, pending delivery, and read/write
failure handling. Device tests cover encrypted round trips, fresh ciphertext, tamper rejection,
settings contracts and metadata-only inspection on the CI API 26/30/34/36 matrix. The existing
proprietary safety guard also prohibits action/content/network APIs in this module.

On a physical device: review a legitimate test app's access in Settings, run an initial monitor
check, then grant one capability and run the worker again (or wait for scheduled work). Confirm
a change notification with Security Alerts enabled, no notification with it disabled, and a
persistent dashboard warning either way. Revoke and check again. OEM Settings destinations,
work-profile visibility, Doze scheduling and overlay-query restrictions still need device review.
