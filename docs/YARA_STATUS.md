# YARA-compatible DEX subset — current status

**Active (limited) when and only when all bundled assets parse successfully.**
At startup SafeMobile loads `app/src/main/assets/yara/safemobile_android_dex.yar`
from its signed APK. Any missing, oversize, malformed, unsupported or duplicate
rule disables the entire pack. No runtime-generated or downloaded rules are
executed. The detection-capabilities UI displays the rule count (five in this
version), current status and per-scan match count.

The Kotlin engine is deliberately **not** libyara/full YARA. Implemented syntax:
`rule NAME { meta: ... strings: ... condition: ... }` with bounded metadata,
case-sensitive ASCII literal strings only, references like `$marker`, `and`,
`or`, and parentheses. No regex, hexadecimal/wildcard patterns, wide strings,
modules, imports, numeric functions, offsets, repeats, counting operators, nocase,
private/global rules or generated executable code. Unsupported content fails closed
at pack load rather than being silently ignored.

An APK is hashed and inspected using the existing static pipeline. Extracted
`classes.dex`, `classes2.dex`, etc are ZIP-bounded to 16 MiB per entry and
24 MiB total and inspected on the repository's I/O scan dispatcher.
Rule matches include name, severity, MITRE identifier, matched authored string
patterns and DEX filename. Findings are **advisory / SUSPICIOUS**, not THREAT
unless independent verified malware indicators justify that classification.
Missing, malformed and omitted DEX content must not be called safe.

Rules: source [Takopii detection corpus](https://github.com/F2u0a0d3/takopii/tree/2e539dc150228a06cc983c33367b06d605c12a85/detection/yara),
revision `2e539dc150228a06cc983c33367b06d605c12a85`,
Copyright (c) 2026 Takopii Project Contributors, MIT. Five adaptations
cover multi-vector overlays, reflective dynamic DEX loading, RAT capability
combination, authenticator targeting and dropper fetch patterns. Original
ZIP-header conditions were removed for extracted DEX inputs. See NOTICE for
complete MIT permission/warranty text. No GPL/AGPL patterns are included.

Existing `YaraRuleImportStore` persists user-selected `.yar` under
`noBackupFilesDir/yara-rules/pending`, max 2 MiB, review-only. Imported files
are not loaded, compiled or scanned. Bundled assets are authenticated as part
of Android's APK signing chain; there is no separate, independently signed
hot-update rule protocol or owner-approved external feed. A new bundle requires
a normal signed app release. This is **not** a substitute for a verified native
YARA engine, unpacking, real malware test corpora or measured accuracy.
