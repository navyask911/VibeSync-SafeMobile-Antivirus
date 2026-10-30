# Phase F — 200-APK cloud benchmark

The pilot runs entirely on GitHub Actions in the existing SafeMobile repository. The owner's computer does not need to download malware or run an emulator.

## Set up the sample API secret

Open **Repository Settings → Secrets and variables → Actions → Secrets → New repository secret**. Add the secret named **MALWAREBAZAAR_AUTH_KEY**, obtained from the [official MalwareBazaar API portal](https://bazaar.abuse.ch/api/). Do not paste the key in a commit or public workflow log. MalwareBazaar applies fair-use terms, authentication requirements and daily download limits.

The workflow retrieves a list of up to 1,000 APK candidates through the authenticated get_file_type API, selects 100 distinct SHA-256 hashes and downloads each sample as an encrypted ZIP, using the documented archive password. It verifies every unpacked APK against the manifest and checks ZIP/APK structure. F-Droid supplies 100 benign-labelled APKs with signed-index hashes.

**Important:** These are MalwareBazaar/F-Droid source labels, not independent malware adjudication. All malware APKs stay in temporary GitHub runner/emulator storage, are never installed or executed, and are deleted after each batch. No APKs are committed or uploaded in Actions artifacts.

## Run

1. Open [SafeMobile GitHub Actions](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions).
2. Select **Industry Benchmark (200 real APKs)**.
3. Select **Run workflow**, branch **main**, then confirm.
4. On success, download the **industry-benchmark-report** artifact. A separate publish job commits the verified aggregate Markdown report to main.

The first merge of the updated benchmark workflow to main also triggers the pilot automatically; the action does not run on ordinary source changes.

HTTP 429, quota denial, unavailable APKs, decompression errors, digest mismatches or missing samples are treated as **incomplete**, with clear messages and **no published numeric detection claim**. There are twenty batches of ten APKs (100 benign plus 100 malware candidates).

## Interpretation

Confirmed TPR = 100 malware candidates with THREAT / 100. Confirmed FPR = benign-labelled THREAT / 100. SUSPICIOUS is reported separately for triage. Average latency is the mean measured per-file scanner duration on the CI emulator. No fake percentages are allowed.

An external research model with 215 Drebin features is available from the separate ML repository. The app currently bundles an untrained 32-input model; its ML inference is disabled. Real on-device deployment requires independent validation of the exact model, feature schema and operating threshold before changing the production readiness metadata. A reported 97.45% research holdout figure is not a SafeMobile detection benchmark measurement.

The hidden Settings card is available after seven taps on the version label. It reads a report embedded at build time; install a later version to display subsequently published benchmark results.
