# SafeMobile bundled DEX rule subset

This is a reviewed, locally shipped **limited YARA-compatible subset**, not libyara and not full YARA execution.
Only ASCII literal strings and explicitly referenced AND/OR/parenthesized boolean conditions are supported. No regex, byte masks, wildcards, modules, imports, numerical expressions, wide/nocase modifiers, user rule activation, unpacking, or emulation. The loader rejects all unsupported syntax for the entire pack and disables the capability. DEX input is bounded to 16 MiB per entry, and existing APK archive extraction limits remain in force.

The bundled `safemobile_android_dex.yar` is adapted from MIT-licensed Takopii detection rules (source: https://github.com/F2u0a0d3/takopii/tree/master/detection/yara). Specifically adapted from banker-shape.yar, dcl-antiforensics.yar, rat-capabilities.yar and dropper.yar. Original APK ZIP header conditions were removed to target already-extracted DEX; some original conditions were narrowed/recast for the supported grammar. These are behavioral **heuristics**, not verified family-specific detections. Source authors: Takopii Framework / Takopii Project Contributors (2026), MIT. Preserve upstream attribution and MIT notice in docs/THIRD_PARTY_LICENSES.md and NOTICE.

Rules never access the network. The APK signature authenticates bundled assets; this does not implement independent signed rule updates. Pending third-party imports stay **PENDING / NOT EXECUTED**. A no-match is never proof that an APK is safe.
