This directory contains NO executable rules and only documents the review-only import boundary.
Bundled, immutable DEX subset rules are under `assets/yara/`. User imports are saved in no-backup
app-private storage as PENDING and NOT EXECUTED; they cannot affect active scanning.
See docs/YARA_STATUS.md for subset limitations and source licensing.
