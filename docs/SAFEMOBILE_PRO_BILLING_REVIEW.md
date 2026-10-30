# SafeMobile Pro billing and Play upload handoff

Branch: `playstore/v1.0.16-monetization`, Android version **1.0.17**, code **20261110** (published 1.0.16 already uses 20261109).

## Implementation and distribution

- **Supported SDK**: `com.android.billingclient:billing-ktx:8.3.0` replaces 7.1.1. Product queries read `QueryProductDetailsResult.productDetailsList`; eligible buy offers supply their offer token at checkout. Rentals and preorders are not sold as annual Pro passes. Automatic reconnection is enabled and entering/resuming the paywall recovers still-unconsumed transactions.
- **Purchase quantity**: consumable product `safemobile_pro_1_year` must be configured and activated in Google Play Console, with its regional price and optional multi-quantity support. The 1–10 year selector is a price estimate; the Google Play cart controls actual quantity. Credit every positive, representable `Purchase.quantity`, including a cart quantity above the estimate range. All expiry arithmetic checks overflow. No price or purchase result is fabricated locally.
- **Permanent loss possible**: consumed purchases and 365-day increments are device-bound to a locally SHA-256-hashed Android ID and Keystore-encrypted SharedPreferences; reinstall, hardware reset, migration, signing-key change or Keystore loss can delete years. The restore button checks local data ONLY and **cannot** restore consumed purchases from Play. Establish a durable customer remedy and refund policy before charging users.
- **Verification limits**: client-only Billing callbacks do not independently verify purchase tokens against Play Developer API, chargebacks, or revoked orders. Require security review before selling long-term entitlements.
- **Languages**: all 26 paywall resources are present in base English and the 51 translated locale folders. The exact requested device-bound disclaimer is the final paywall text. A nearby network disclosure clarifies that core protection is offline while Play purchases and optional model updates use a connection. CI rejects missing, empty, English-fallback and placeholder-mismatched paywall copy; product brands stay unchanged.
- **Product claims**: existing offline hash/YARA scanning and siren protection stay FREE. The ML model is unvalidated and is NEVER advertised as paid active threat defense. Pro can shorten optional research-model candidate refresh from weekly to daily, but no claimed malware detection. No ad SDK is present in free or paid builds.

**Dependency licences**: Google `billing-ktx:8.3.0` is under the Android Software Development Kit License and applicable Play Billing terms (https://developer.android.com/studio/terms.html). AndroidX `security-crypto:1.1.0` is Apache-2.0. Exact upstream artifact review is recorded in THIRD_PARTY_LICENSES.md; resolved dependencies and notices are generated in CI.

## Validation and owner rollout

Before squash merge, require all five Android CI jobs: unit tests/lint/signed builds plus API
26, 33, 34 and 36 instrumentation. Real encrypted-ledger tests cover quantity, token replay,
expiry, clock rollback and irreversible local-data loss. The source guard rejects billing
entitlement checks in core scanning, posture, quarantine and incident-response code.

The production release workflow builds the signed offline Play AAB with the pinned research
model still inactive, reviewed YARA, all locales, billing metadata and no bundled hash database.
Generating this AAB does not publish it to Google Play or configure products in Play Console.
Before public rollout, use a licensed tester on the Play internal track to verify the activated
product, prices, pending/canceled/paid transactions, actual cart quantity and consumption retry.
CI uses no real Google account, card or paid order and cannot establish that live checkout passed.

Privacy: No Android ID, purchase token, APK, or protected content is transmitted to the developer's servers. Google Play Billing communicates with Google during purchase. WorkManager network access remains confined to optional downloaded research models; scanning, verdicts and stored malware evidence remain local.
