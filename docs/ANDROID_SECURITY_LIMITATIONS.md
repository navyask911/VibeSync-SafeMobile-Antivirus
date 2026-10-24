# Android security feature limitations and implementation notes

## Offline scanning and installation timing

SafeMobile's core scan pipeline hashes readable local APK/file bytes and compares them with locally stored definitions. It does not need the internet to scan, store scan results, or evaluate locally available indicators. The optional threat-feed flavor is a separate, explicitly configurable network feature.

Android's `ACTION_PACKAGE_ADDED` / `ACTION_PACKAGE_REPLACED` signals arrive after the system package manager has committed an install or update. SafeMobile queues the local WorkManager assessment and may show a high-priority alert after the assessment finds a confirmed or suspicious result. A normal consumer application cannot intercept the system installer before it appears, veto another app's install, or promise that every installation is detected. Alert delivery also depends on the user's notification permission, notification-channel settings, OEM background behavior, and whether Android delivers the broadcast/work.

The siren is attached to the `security_alert_high` notification channel. On Android 8.0 and newer, the user controls channel sound and importance after creation; the app cannot override a user-muted channel. Spoken alerts are optional, disabled by default, and use the configured Android text-to-speech engine. Core hash scanning does not send a scan result or file content to a remote service.

## Consumer Device Administrator versus Device Owner

The consumer Device Administrator prompt is user-mediated. These narrowly scoped policies are declared: `force-lock` and `limit-password`. They enable a force-lock request. The `limit-password` declaration is retained for platforms that still support it, but Android rejects legacy password-policy APIs for device-admin apps targeting API 29 and newer. In this target-36 app, the password-policy action therefore fails safely on current Android; it is not a reliable consumer-mode control. Platform documentation: https://developers.google.com/android/work/device-admin-deprecation.

Classic Device Administrator **cannot block APK installation**, cannot stop Android's package installer from presenting its UI, and cannot guarantee anti-uninstall. The disable-request callback can explain consequences but cannot deny a user who chooses to deactivate the administrator. Stronger managed installation restrictions belong to a fully managed Device Owner deployment; they are not activated by a consumer one-tap prompt and should not be implied as available on ordinary personal devices. No `wipe-data` policy is declared.

## Accessibility services

This build does not install an Accessibility Service to watch installation UI. If an optional advisory service is considered in a future release, it must be plainly disclosed, opt-in, and advisory only: it may explain that post-install scanning is available but must never claim that it can reliably prevent Android's system installer from opening or completing an install. Android remains in control of package installation.

## Compose window insets and keyboard behavior

The top-level `Scaffold` uses `WindowInsets.safeDrawing` and applies `innerPadding` to the screen content, then calls `consumeWindowInsets(innerPadding)` so descendants do not apply those same insets again. Do not also apply `navigationBarsPadding()` to the primary button; that double-counts bottom navigation space and can clip the button on gesture-navigation devices. A scrollable onboarding column keeps the button reachable when the available height is small.

Use `imePadding()` only on a screen or container that hosts inputs and must remain visible above the on-screen keyboard. The onboarding flow contains no text input, so adding it there would not solve a relevant problem. When composing a form, use a single clear owner for IME/system insets and consume already-applied insets to avoid duplicated bottom space.

## Permanent quarantine deletion

Quarantined payload deletion runs from the ViewModel on `Dispatchers.IO`. The app verifies that the file exists before attempting deletion, catches `SecurityException`, and removes its metadata only after the payload deletion succeeds. If a file disappeared or the OS denied deletion, the UI reports failure and refreshes the list instead of deleting a stale list position or pretending the file was removed.
