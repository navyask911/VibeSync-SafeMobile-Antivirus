# SafeMobile Pro monetization: DRAFT — not approved for Play release

Branch: `playstore/v1.0.16-monetization`, Android version **1.0.17**, code **20261110** (published 1.0.16 already uses 20261109).

**Do not publish the paid product until these checks pass:**

- **Deprecated SDK**: requested `com.android.billingclient:billing-ktx:7.1.1` has passed Google's August 31, 2026 normal Play update deadline (extension deadline November 1, 2026). Upgrade to supported Billing 8 or 9 before distribution unless Play explicitly grants the extension.
- **Real Play testing**: create consumable `safemobile_pro_1_year` in Google Play Console; enable multi-quantity and price (₹299 is a target, not authoritative until Play returns the formatted price). Test pending/cancelled/paid, 1–10 quantity, restart, network loss and consumption retry. Billing 7.1.1 has NO `BillingFlowParams.ProductDetailsParams.Builder.setQuantity`. The paywall selector is only an estimate; Google Play cart controls actual quantity. Credit `Purchase.quantity`.
- **Permanent loss possible**: consumed purchases and 365-day increments are device-bound to a locally SHA-256-hashed Android ID and Keystore-encrypted SharedPreferences; reinstall, hardware reset, migration, signing-key change or Keystore loss can delete years. The restore button checks local data ONLY and **cannot** restore consumed purchases from Play. Establish a durable customer remedy and refund policy before charging users.
- **Verification limits**: client-only Billing callbacks do not independently verify purchase tokens against Play Developer API, chargebacks, or revoked orders. Require security review before selling long-term entitlements.
- **Languages**: Existing 51-language screens and siren remain untouched; new Pro strings have Kannada/Japanese translations. Pro strings in **49 other locales are explicitly marked provisional English fallbacks**, not genuine localization. Translate and review those disclosures before shipping paid purchases.
- **Product claims**: existing offline hash/YARA scanning and siren protection stay FREE. The ML model is unvalidated and is NEVER advertised as paid active threat defense. Pro can shorten optional research-model candidate refresh from weekly to daily, but no claimed malware detection. No ad SDK is present in free or paid builds.

**Dependency licences**: Google `billing-ktx:7.1.1` is under the Android Software Development Kit License and applicable Play Billing terms (https://developer.android.com/studio/terms.html). AndroidX `security-crypto:1.1.0` is Apache-2.0, though deprecated in favour of platform Keystore APIs. Review resolved SBOM and transitive dependencies.

Privacy: No Android ID, purchase token, APK, or protected content is transmitted to the developer's servers. Google Play Billing communicates with Google during purchase. WorkManager network access remains confined to optional downloaded research models; scanning, verdicts and stored malware evidence remain local.
