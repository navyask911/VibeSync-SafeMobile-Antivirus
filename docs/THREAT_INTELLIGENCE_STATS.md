# Threat Intelligence Engine statistics

Detection Capabilities reads only the last valid app-private `ml-research-candidates/stats.json`.
The screen makes no network requests. Its lifecycle-aware observer reloads the cache when the
optional model update worker writes it and when the screen becomes active again.

The existing consent-controlled ModelUpdateWorker looks for one optional `stats.json` asset on
the selected complete ML release. It refreshes statistics even when `candidate_version` is unchanged.
The download uses the existing HTTPS repository/redirect allowlist, a 16 KiB limit, the declared
asset size and GitHub's SHA-256 asset digest. Model bundles can also list `stats.json` in SHA256SUMS;
older four-entry manifests remain valid. Stats never enable inference or change model approval.

Expected JSON (illustrative values only; no fixture is bundled or shown as live data):

```json
{
  "total_malware_samples": 5560,
  "accuracy": 97.45,
  "total_downloads": 12000,
  "last_updated": "2026-10-31T00:00:00Z"
}
```

Counts must be nonnegative integral JSON numbers within signed 64-bit range. Accuracy accepts
numeric fractions from 0 through 1, numeric percentages above 1 through 100, or an explicit
percentage string such as `"1%"`. Dates must be ISO dates or ISO timestamps with an explicit offset.
All four fields must validate. Numbers, percentages and dates are formatted in the app locale.
The download count is the upstream global count, never a local device counter or an invented total.

Missing, duplicate, oversized, unverified or malformed statistics preserve the previous cache.
Transport/storage failures request a WorkManager retry while a valid model can still be staged.
Without a valid cache the card shows the localized updating message. A release without statistics
remains compatible; the ML repository must publish the asset before the first live numbers appear.
The current `v1.0.1-model` release did not contain that asset when this feature was implemented.

Training accuracy describes the upstream evaluation. Existing detection layers continue to report
whether inference is actually available on this device. No dataset, model, schema, protection gate,
signing configuration, telemetry or dependency was added or changed by this feature.
