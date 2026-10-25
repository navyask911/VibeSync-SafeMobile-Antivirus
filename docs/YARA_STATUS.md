# YARA status and rule-import boundary

## Current status

YARA is **DISABLED — no compliant Android runtime/rules bundled**. The current app does not parse rules as an interpreter, compile them, or claim a YARA match/no-match result. A readable input receives an explicit DISABLED status; an unreadable input is NOT_SCANNED.

The upstream YARA engine is BSD-3-Clause and is license-compatible in principle, but this repository does not yet contain reviewed Android JNI artifacts for supported ABIs, bounded execution/cancellation controls, a signature-verification trust configuration, or a vetted and redistributable mobile rule pack. No Hypatia AGPL source or rules were copied.

## Pending-rule import

A user-selected UTF-8 .yar file can be stored under the app-private no-backup directory yara-rules/pending for later review. Import is bounded to 2 MiB and performs only basic text/control-byte and declaration checks. This is not a YARA parser, does not establish the rule's license or provenance, does not compile it, and does not activate scanning. It must remain visibly marked PENDING / NOT EXECUTED until a compliant native runtime and signed, license-reviewed rule bundle are available. Imported rules are never uploaded.

Before enabling the engine, add tests for the exact native ABI builds, timeouts and memory limits, signed rule-pack versions, tampered rules, false positives/negatives, and maliciously crafted rule inputs. No production efficacy claim is made.