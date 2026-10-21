# Mendeley research dataset attribution and import record

## Dataset attribution

- **Title:** A 200K Malware Hash Dataset with Experimental Splits for Machine Learning Classification
- **Creators:** Antonio Lara Gutiérrez; Nicolas Alvarez; Jose A Onieva
- **Publisher:** Mendeley Data
- **Source:** https://data.mendeley.com/datasets/xv84w8cc72/1
- **Version:** 1
- **DOI:** https://doi.org/10.17632/xv84w8cc72.1
- **Publication date:** 14 September 2026
- **Related dataset link listed by publisher:** https://doi.org/10.5281/zenodo.19342248
- **License stated by publisher:** Creative Commons Attribution 4.0 International (CC BY 4.0)
- **License URL:** https://creativecommons.org/licenses/by/4.0/

The publisher describes a manifest.csv containing 201,549 SHA-256 hashes for both malicious (malware) and benign (goodware) software samples, including binary labels, granular categories, predefined train/test splits, and experiment masks. This is publisher metadata; actual archive headers and row counts must be confirmed by running the importer and inspecting its report.json.

## Purpose and separation

This dataset is a research and machine-learning classification resource. Its labels must not be treated as authenticated live threat intelligence or automatically merged into SafeMobile's operational threat-indicator table. False positives, label provenance, sample freshness, and third-party content restrictions require separate review.

The archive and extracted source files are development-time inputs only. They are not intended to be committed to Git or packaged in the Android APK/AAB. The import tool creates a separate local SQLite research index under .cache/datasets/. The runtime Room database and scanner are not modified by this research import.

## Changes made by the tooling

The importer leaves the source archive and extracted manifest.csv unchanged. In a separate SQLite research index it:
- normalizes valid SHA-256 values to lowercase for indexed lookup;
- counts invalid SHA-256 rows and does not use invalid values as index keys;
- preserves original columns and values in a JSON field for each CSV record;
- preserves label, category, and experimental split/mask values in separate fields where discovered;
- counts duplicate SHA-256 occurrences without silently discarding source rows;
- records detected source-column names, row totals, and import timestamp.

The separate research index is a derived development artifact, not a replacement for the original dataset and not a production antivirus signature database.

## Download and verification record

The reproducible importer is scripts/mendeley_dataset.py. It streams the versioned ZIP over HTTPS when no valid local archive exists, checks response size and ZIP structure/CRC, validates archive paths before extraction, rejects traversal/symlink/special-file entries and configured size limits, extracts into a dedicated cache directory, and writes an inspection/import report.

The coding workspace's first direct download attempt failed because DNS resolution for data.mendeley.com was unavailable (curl: (6) Could not resolve host). This is an environment/network limitation, not evidence that the publisher archive is invalid. The GitHub Actions research workflow retries the download on a network-enabled runner and uploads the inspection report as an artifact. Until that workflow produces a report, actual archive bytes, archive checksum, extracted member list, CSV header, actual row counts, and import statistics remain unverified.

## No endorsement

Attribution does not imply endorsement by the dataset creators, Mendeley Data, Elsevier, Universidad de Málaga, or any third-party rights holder.
