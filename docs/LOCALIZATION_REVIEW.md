# Localization review checklist

Automated resource-key and placeholder-parity checks are useful, but they do not establish translation quality. This checklist must be completed by a native speaker for each release.

- [ ] Review every new/changed privacy, storage-access, feed opt-in, threat verdict, quarantine, and permission-disclosure string in each shipped locale.
- [ ] Verify all interpolated placeholders match the English source exactly and in compatible order.
- [ ] Check right-to-left layouts for Arabic, Hebrew and Urdu; confirm dialog order, button placement, clipping and accessibility reading order.
- [ ] Check long words and narrow-device wrapping in German, Russian, Hindi, Kannada, Tamil, Telugu, Bengali and Marathi.
- [ ] Confirm the SAF explanation says the user chooses one folder and does not imply full-device storage access.
- [ ] Confirm feed opt-in wording accurately describes the configured endpoint, possible provider Auth-Key transmission, and that scan files/hashes/history are not sent.
- [ ] Capture real screenshots on a small phone, large phone and tablet/landscape where supported.
- [ ] Record reviewer name/role, locale, build version, date, unresolved issues and screenshot links in the release review.

Current status: **not yet signed off by native speakers**. Strings marked non-translatable use English fallback and must be localized or deliberately withheld from non-English release claims before production.
