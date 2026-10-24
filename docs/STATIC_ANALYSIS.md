# Deep static analysis coverage

## Implemented, local-only checks

Installed-package analysis now requests activity, service, receiver and provider metadata and emits a structured RiskReport. Each finding has a stable rule ID, severity (LOW/MEDIUM/HIGH), evidence text and a confidence score from 0 to 100. Findings are advisory; they do not by themselves prove malware.

Checks include exported components without a manifest permission gate (code-level gates may still exist), AccessibilityService declarations and combinations with overlay/SMS/call-log permissions, Device Administrator receivers, SMS plus call-log combinations, debug-signer indicators, missing signer metadata, DEX header inconsistencies, a bounded DEX entropy sample, and common packer/protector filename markers. A small requested-permission vs known-DEX-string check is low confidence and is skipped for oversized/incomplete DEX scans. All APK access is read-only, bounded by entry count and DEX size, and remains on-device.

Certificate rotation history is shown as informational rather than suspicious. There is no known-bad certificate fingerprint list, so that sub-engine is explicitly DISABLED. The API-string check is not full disassembly and can miss reflection, native methods, generated code and encrypted strings. Packer names and high entropy have legitimate uses and can false-positive. Exported components are not automatically unsafe if code performs its own authorization. These signals are never presented as a deterministic malware proof.

## Not bundled

APKiD is dual-licensed GPL/commercial and relies on YARA rules. No compatible closed-source APKiD license was acquired, so no APKiD code/rules were copied. The in-app structural checks are a deliberately small advisory detector and are not represented as equivalent coverage. YARA and TFLite remain disabled.