# Public dashboard metrics

The signed TweetFeed database workflow refreshes
`docs/dashboard_metrics.json` every six hours. The JSON is published with the
main branch and can be read without credentials at:

`https://raw.githubusercontent.com/navyask911/VibeSync-SafeMobile-Antivirus/main/docs/dashboard_metrics.json`

## Data definitions

- `tweetfeed_count`: number of unique SHA-256 values in the exact weekly
  TweetFeed feed fetched and validated earlier in the same workflow
  (`/v1/week/malware/sha256`). This avoids querying the separate `/v1/counts`
  endpoint, whose response in run #41986159798 did not contain the expected
  `windows.today.types.sha256` field. The feed builder reported 21 unique hashes
  in that run.
- `ha_verified_count`: unique SHA-256 hashes in this workflow's current
  TweetFeed input that have a cached Hybrid Analysis verdict of `malicious`
  and a current Hybrid Analysis report verdict of `malicious`. A supplied
  numeric threat score must be >= 70; if the API omits a score, the explicit
  `malicious` verdict is still counted. The enrichment step uses
  `GET /api/v2/search/hash?hash={sha256}` and then
  `GET /api/v2/report/{job_id}/summary` when a report ID is returned.
- `cloudflare_total_donations` and `cloudflare_confirmed_threats`: read from
  the Cloudflare KV contribution namespace. The SafeMobile contribution
  client submits only after a confirmed `ScanVerdict.THREAT`; in deployments
  where KV stores one item per SHA-256, distinct hash keys are counted. If the
  namespace stores an aggregate JSON object, the script reads the donation and
  confirmed-threat counters from it.

## Required GitHub Actions secrets

- `HYBRID_ANALYSIS_API_KEY`: already used by the preceding reputation
  enrichment step; the metrics step checks that it is configured.
- `CLOUDFLARE_API_TOKEN`: read-only Cloudflare API token with permission to
  read the selected account's KV namespace and values/keys.
- `CLOUDFLARE_ACCOUNT_ID`: repository **Secret**. The workflow passes it
  through to `scripts/generate_dashboard_metrics.py` using
  `secrets.CLOUDFLARE_ACCOUNT_ID`, avoiding account discovery.
- `CLOUDFLARE_KV_NAMESPACE_ID`: repository **Secret** containing the ID of
  the dedicated contribution KV namespace. The workflow reads it with
  `secrets.CLOUDFLARE_KV_NAMESPACE_ID`.

## Optional GitHub Actions variables

- `CLOUDFLARE_KV_NAMESPACE_TITLE`: retained for deployments that configure a
  namespace title; it does not replace the namespace ID required by the metrics
  step.
- `CLOUDFLARE_KV_METRICS_KEY`: optional Actions Variable override for the
  aggregate key. The default is `safemobile_donation_totals`.

The metrics reader requests exactly one value from the configured namespace:
`safemobile_donation_totals` by default. Its expected JSON shape is:

```json
{
  "total_donations": 1420,
  "confirmed_threats": 312
}
```

The parser also accepts camelCase field names and counters nested inside JSON
objects. If the deployed Worker uses another KV key name, set the
`CLOUDFLARE_KV_METRICS_KEY` Actions Variable to that exact name. The repository
does not contain the deployed Worker implementation, so the default key is a
configuration default rather than an independently confirmed Worker literal.

The workflow logs the selected key, response status/size and parsed aggregate
counts. The raw KV value is intentionally not printed: GitHub Actions logs can
be visible to repository readers, and arbitrary Worker values may contain
sensitive data. Empty, missing, JSON `null`, invalid JSON, or an object without
recognized count fields produces zero Cloudflare counts without interrupting
TweetFeed or Hybrid Analysis metrics.

When `CLOUDFLARE_KV_NAMESPACE_ID` is missing, the generator prints
`WARNING: CLOUDFLARE_KV_NAMESPACE_ID is missing`, skips all Cloudflare KV
requests, and writes `0` for both Cloudflare counters. This is a non-fatal
configuration state: TweetFeed and Hybrid Analysis metrics are still generated
normally. Once the namespace exists, store its ID in the repository Secret
`CLOUDFLARE_KV_NAMESPACE_ID` to enable Cloudflare reads.

The script never prints credentials and never sends the Cloudflare token to
the public Worker. It publishes counts only; no hashes, feature vectors,
sample data, device identifiers or user identifiers are included. For other
provider failures, the generator retains a previous valid count or uses the
explicit safe default 0; workflow logs identify each fallback so a fallback
zero is not mistaken for a successful empty result.
