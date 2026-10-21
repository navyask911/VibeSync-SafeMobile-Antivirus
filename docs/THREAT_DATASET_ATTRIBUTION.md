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

The local container's first direct download attempt failed because DNS resolution for data.mendeley.com was unavailable (curl: (6) Could not resolve host). The separate GitHub Actions research workflow then downloaded the actual archive successfully, verified ZIP structure and CRCs, safely extracted the manifest, built a separate SQLite research index, ran PRAGMA integrity_check, and uploaded the inspection report as a workflow artifact. The archive and SQLite index remain in the GitHub Actions dataset cache and are not committed to the repository or bundled in the APK/AAB.

Verified by workflow run https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/39579356832 on 21 October 2026:
- Download archive size: 8,086,309 bytes.
- Archive SHA-256: eacfd9a2ef80568d48049169521f9a4779a4ab1ee5d3ad78b2d2967624d282f5.
- ZIP entries: 1; declared expanded bytes: 22,322,772.
- Manifest member: A 200K Malware Hash Dataset with Experimental Spli/manifest.csv.
- Extracted manifest SHA-256: a0727c77e6041b2a3ca1d621253557c9acef7b466686fb53e4bfa493905ead0a.
- Actual headers: sha256, category, binary_label, split, in_binary_experiment, in_multiclass_experiment, in_trimodal_binary, in_trimodal_multiclass.
- Rows examined (excluding the header): 201,549. Valid SHA-256 rows: 201,549. Invalid hash rows: 0. Duplicate hash rows after the first: 0. Unique SHA-256 hashes: 201,549.
- binary_label counts: Goodware 111,219; Malware 90,330.
- category counts: Goodware 111,219; Trojan 42,113; Adware 17,682; Malware_Generic 10,640; Infectors 8,311; Downloaders 5,392; Obfuscated 3,023; Ransomware 1,760; Spying_Stealing 1,011; Other_Malware 398.
- Five real imported SHA-256 samples were queried against the research index; all returned the expected first source row, and SQLite `EXPLAIN QUERY PLAN` confirmed use of `research_hashes_sha256_idx` (`sample_lookup_validation: passed`).
- The resulting research SQLite database passed `PRAGMA integrity_check`. No records were inserted into or merged with the operational Room malware-indicator database.

The tooling leaves the downloaded ZIP and original extracted manifest unchanged. SHA-256 values are normalized to lowercase only in the derived research index; original field values and all experimental split/mask fields remain preserved in each row's raw JSON record. Dataset labels remain research labels, not verified live threat indicators.

## No endorsement

Attribution does not imply endorsement by the dataset creators, Mendeley Data, Elsevier, Universidad de Málaga, or any third-party rights holder.
