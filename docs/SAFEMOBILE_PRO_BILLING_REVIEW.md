# SafeMobile Pro subscription billing review

Branch: `feat/billing-subs-v1.4.2`  
App version: **1.4.2**  
Version code: **20261121**

## Subscription product

- New Google Play product ID: `safemobile_pro_1y_subs`.
- Product type: **SUBS**, with an annual auto-renewing base plan. The Play Console product and its annual ₹299 price must be activated and tested on the Play internal track before rollout.
- The app queries subscription ProductDetails and uses a returned subscription offer token at checkout. The Play Billing offer and price are authoritative; the in-app paywall discloses the annual auto-renewing offer and cancellation through Google Play.
- Subscription purchases are **never consumed**. An initial purchased subscription is acknowledged with `acknowledgePurchase()` when `Purchase.isAcknowledged` is false. Already-acknowledged renewals do not need another acknowledgement.
- The Pro paywall's one-year selection uses the annual auto-renewing SUBS product. Selections of 2–10 years use the former annual one-time consumable SKU `safemobile_pro_1_year` as a prepaid pass.
- The multi-year value in the slider is an estimate. Google Play Billing does not expose a client-side quantity parameter in `BillingFlowParams.ProductDetailsParams.Builder`; the user must select the matching quantity in Google's purchase cart. The app grants years from the actual `Purchase.quantity` returned by Google Play, not from the slider.
- Multi-quantity must be enabled for the one-time product in Play Console. It is only supported for eligible consumable one-time purchase options, not subscription plans or discount offers. The app selects the buy purchase option and excludes offer/rental entries.
- The one-time pass does not auto-renew. The annual SUBS plan does auto-renew until canceled in Google Play.

## Restore and legacy migration

- `restoreProLicenseFromPlayStore()` queries `ProductType.SUBS` for the active subscription product and rehydrates local access from a purchased result.
- The manager performs a `ProductType.INAPP` compatibility lookup for the former SKU `safemobile_pro_1_year`. It grants only a still-owned, purchased legacy transaction and consumes that old transaction after recording it, preventing repeated migration grants. The same product's eligible buy purchase option is priced for the prepaid multi-year checkout.
- Existing encrypted local entitlements and redeemed-token markers retain their original preference store and keys, so an app update does not discard the existing local pass.
- **Important migration limit:** the former product was consumable. Google Play does not return an already-consumed one-time purchase from `queryPurchasesAsync`; the fallback can therefore only discover a legacy transaction that is still owned and unconsumed. Previously credited local legacy access remains available while its encrypted local data remains intact. A consumed legacy purchase cannot be reconstructed after local app data or its Keystore key is lost.
- The restore/check action can restore an active subscription from Google Play after reinstall when the user is signed in and Play can return the subscription. Offline status checks continue to use the encrypted local cache.

## Local entitlement and privacy boundaries

- The existing device fingerprint and `EncryptedSharedPreferences` store remain in place. The Android ID is hashed locally and is not uploaded or logged.
- Subscription cache expiry is calculated as `Purchase.purchaseTime + 365 days + 1 day` (the requested local grace buffer). The cache is an offline gating approximation, not an independent receipt-verification service. The app does not call the Google Play Developer API and cannot independently detect server-side refunds or revocations while offline.
- The encrypted device-bound cache drives the existing Pro status consumed by AdMob. The Free tier remains eligible for consent-gated ads; a locally active Pro entitlement excludes Pro users from ad requests and preloaded interstitials. Billing changes do not alter the AdMob manager, UMP consent logic, or privacy disclosures.
- Billing code remains isolated under `core/billing`; no Pro entitlement gate is introduced into scanning, YARA, hash matching, posture checks, quarantine, or the siren/incident-response pipeline.
- No Android ID, purchase token, APK, scan data, or verdict is sent to a developer server.

## Validation and rollout

- CI must pass the unit/lint/build job and instrumented test jobs on API 26, 33, 34, and 36.
- Encrypted-ledger tests cover legacy quantity idempotency, subscription expiry plus grace buffer, repeated subscription-query idempotency, renewal expiry movement, invalid inputs, and clock rollback.
- CI cannot validate a real paid order. Before public rollout, activate the subscription product and test pending, canceled, purchased, acknowledged, restore-after-reinstall, renewal, and cancellation behavior with licensed Play internal-track testers.
- This change does not trigger the signed production release workflow or publish to Google Play.
