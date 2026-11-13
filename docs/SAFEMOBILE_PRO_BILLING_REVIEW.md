# SafeMobile Pro prepaid subscription and device-binding review

Branch: `release/v1.9.0-final`  
Target app: **1.9.0**

## Google Play Console configuration required

Create a subscription product with:

- Product ID: `pro_access`
- Prepaid base plan ID: `prepaid-1-year`
- Billing period: `P1Y` (one year)
- Plan type: **Prepaid**, not auto-renewing
- Enable the prepaid-plan extension/top-up option for the base plan
- Configure country availability and price, then activate it for the intended testing/release tracks

**Google Play does not support a single 2–10-year prepaid base plan.** The maximum prepaid base-plan duration is one year. The app therefore sells one prepaid year at a time. The same active plan can be purchased again to top it up by another year. Do not create or advertise `prepaid-2-year` through `prepaid-10-year` plans; Play Console does not offer those durations.

The app queries only `pro_access` as `SUBS` and accepts only the `prepaid-1-year` offer whose last pricing phase is non-recurring and has billing period `P1Y`. Auto-renewing plans and other base-plan IDs are not silently substituted.

## Device binding in the Android client

- The app derives a non-personal, 64-character SHA-256 identifier from the Android ID, app package name and a SafeMobile namespace. It never uploads or logs the raw Android ID.
- Android 8+ Android ID normally survives uninstall/reinstall when package name and signing key remain unchanged; factory reset or signing-key changes can change the ID.
- Checkout passes the hash through `BillingFlowParams.setObfuscatedAccountId()`.
- Every confirmed `pro_access` purchase and restore is checked against `Purchase.accountIdentifiers.obfuscatedAccountId` before granting access.
- A missing identifier is rejected as un-verifiable. A different identifier clears the local entitlement and displays **Subscription active on another device**.
- Prepaid purchases and top-ups are acknowledged after a successful local grant. They are never consumed.
- Pending prepaid purchases are enabled with `PendingPurchasesParams.enablePrepaidPlans()`. Entitlement is not granted until Play reports `PURCHASED`.

This is client-side device enforcement, not a server-enforced anti-transfer guarantee. A modified/rooted client can bypass local checks. A production one-device policy should validate purchase tokens and the obfuscated account ID through a secure backend using the Google Play Developer API.

## Restore and prepaid top-up behavior

- The application-scoped billing manager runs `queryPurchasesAsync(ProductType.SUBS)` during application startup and again when the Pro screen resumes.
- A same-device reinstall retains the Android ID and can restore the current active Play purchase through its matching obfuscated account ID.
- The encrypted local ledger accumulates each distinct prepaid top-up while app data is present. Repeated callbacks for the same token are idempotent.
- **Important restore boundary:** Android's encrypted local ledger is removed when the app is uninstalled (the app disables backup). A Play client purchase query exposes the latest purchase metadata, but does not return a complete server-authoritative expiry ledger for every previous prepaid top-up. After reinstall, the client can rebuild the latest one-year prepaid period, but cannot reliably reconstruct multiple prior top-ups from client-only purchase data. Accurate restoration of the entire accumulated multi-year term requires a secure backend to query the Google Play Developer API and persist/derive the authoritative subscription expiry.
- The historical auto-renewing product `safemobile_pro_1y_subs` was created before device IDs were passed to Play. It is not migrated into the new device-bound product automatically. Existing encrypted local entitlement remains device-local until its recorded expiry; old Play subscriptions and billing must be reviewed in Play Console before rollout to avoid unintended continued renewals.

## Validation and rollout

- Billing dependency: Google Play Billing Library Kotlin extensions **9.1.0**.
- Source checks should confirm no one-time product type, consumable purchase, consume call or quantity-based grant remains in the active billing manager.
- Instrumented tests cover one-year prepaid grants, top-up accumulation, token idempotency, mismatch clearing and invalid purchase metadata.
- CI/build and instrumented tests must pass before release. A real Play internal-track test is still required for prepaid purchase, pending payment, top-up, acknowledgement, same-device reinstall and a different-device mismatch.
- The Play Console product/base plan and prices are not created by this repository change. No production release or Play Store upload is triggered by this commit.
