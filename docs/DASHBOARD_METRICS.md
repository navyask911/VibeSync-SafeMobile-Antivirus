# Public dashboard metrics

The signed TweetFeed database workflow refreshes
\`docs/dashboard_metrics.json\` every six hours. The JSON is published with the
main branch and can be read without credentials at:

\`https://raw.githubusercontent.com/navyask911/VibeSync-SafeMobile-Antivirus/main/docs/dashboard_metrics.json\`

## Data definitions

- \`tweetfeed_count\`: TweetFeed's pre-aggregated \`windows.today.types.sha256\`
  value. TweetFeed's "today" window is UTC and its \`/v1/counts\` endpoint is
  cached/pre-aggregated. The script makes one unauthenticated request per cron.
- \`ha_verified_count\`: unique SHA-256 hashes in this workflow's current
  TweetFeed input that have a cached Hybrid Analysis verdict of \`malicious\`
  and threat score >= 70. Hybrid Analysis requests are made by the existing
  quota-limited \`scripts/enrich_threats.py\` step; the metrics script reuses
  that output and does not issue duplicate provider requests.
- \`cloudflare_total_donations\` and \`cloudflare_confirmed_threats\`: read from
  the Cloudflare KV contribution namespace. The SafeMobile contribution
  client submits only after a confirmed \`ScanVerdict.THREAT\`; in deployments
  where KV stores one item per SHA-256, distinct hash keys are counted. If the
  namespace stores an aggregate JSON object, the script reads the donation and
  confirmed-threat counters from it.

## Required GitHub Actions secrets

- \`HYBRID_ANALYSIS_API_KEY\`: already used by the preceding reputation
  enrichment step; the metrics step checks that it is configured.
- \`CLOUDFLARE_API_TOKEN\`: read-only Cloudflare API token with access to list
  the target account's KV namespaces and read KV values/keys.

Optional GitHub repository **Variables** (not secrets) can avoid Cloudflare
account/namespace discovery:

- \`CLOUDFLARE_ACCOUNT_ID\`
- \`CLOUDFLARE_KV_NAMESPACE_ID\`, or \`CLOUDFLARE_KV_NAMESPACE_TITLE\`
- \`CLOUDFLARE_KV_METRICS_KEY\` if the aggregate JSON uses a nonstandard key
  name (the default candidates include \`dashboard_metrics\`, \`stats\` and
  \`metrics\`).

The script never prints credentials and never sends the Cloudflare token to
the public Worker. It publishes counts only; no hashes, feature vectors,
sample data, device identifiers or user identifiers are included. If an
unambiguous metrics source cannot be read, generation fails and the prior
public JSON is left untouched rather than publishing fabricated zeroes.
