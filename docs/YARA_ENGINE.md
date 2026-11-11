# SafeMobile YARA-X Android Engine

## Architecture

SafeMobile pins the Android JNI wrapper from `RevEngiSquad/yarax_android` at commit
`b666fbc15ff67fba1ceaf5deb68d071b44a1cbfe`. The wrapper's Java API is vendored under
`org.revengi.abhi.yarax`; its native library is built from the pinned upstream Rust
source and recursive submodules during Android packaging. No YARA-X library is loaded
from the network at runtime.

The Android wrapper and the underlying YARA-X native engine are both BSD 3-Clause.
Their license copies are included at
`app/src/main/assets/licenses/YARAX_ANDROID_BSD-3-Clause.txt` and
`app/src/main/assets/licenses/YARA-X-BSD-3-Clause.txt`, respectively.

## Build requirements

Android packaging requires Rust stable, the Android Rust targets for armv7, arm64 and
x86_64, the Android NDK, Git, Make, and `cargo-ndk`. The Gradle task fetches the
pinned public source revision into the local Gradle build directory, initializes its
pinned recursive submodules, and builds `libyarax_android.so` for:

- `armeabi-v7a`
- `arm64-v8a`
- `x86_64`

The generated JNI libraries are packaged into the APK/AAB. They are build outputs and
are not committed. CI installs the Rust targets and cargo-ndk before the Android build.
A native build or source-fetch failure fails packaging; it does not silently omit YARA-X.

## Rule loading

Only signed-APK assets in `app/src/main/assets/yara_rules/` are loaded. All `.yar` and
`.yara` sources are size-bounded and compiled once per process. Rule compilation errors,
empty rule packs, native initialization errors and scanner errors are fail-closed.

The native engine source is fetched at build time from the pinned public upstream revision
and compiled into the Android package. First-time builds therefore require source-network
access, Git, Rust stable, cargo-ndk and Android NDK; the installed application has no runtime
YARA update or scan-data network dependency.

The current placeholder rule has `classification = "informational"`. It is deliberately
not a malware signature and cannot generate a THREAT or SUSPICIOUS verdict.

## APK extraction

The extractor reads only the root `AndroidManifest.xml` and root `classes*.dex` entries.
Manifest bytes are scanned in their original Android binary-XML representation. DEX and
manifest contents are retained only in bounded memory; no extracted content is written
to public storage or transmitted.

Bounds include a 512 MiB APK file cap, 10,000 ZIP entry cap, 2 MiB manifest cap, 16 MiB
per DEX, 32 MiB aggregate extracted content, and a 200:1 maximum declared compression
ratio. A missing manifest, missing DEX, malformed archive, size-limit failure or partial
component scan returns NOT_SCANNED rather than NO_MATCH.

## JNI resource management and results

The wrapper exposes `Compiler.addSource`, `Compiler.build`, `Scanner.scanBytes`,
scanner timeout and match-count configuration, and explicit `close()` methods. SafeMobile
creates one scanner per component and closes it in `finally`; compiled rules are cached
and closed through the manager lifecycle. Calls are serialized around the native rules
handle.

The wrapper returns JSON containing `matches`, `nonMatching`, or `error`. SafeMobile
parses rule identifier, namespace, tags, metadata and pattern identifiers. It does not
persist matched byte contents.

Only explicit rule metadata `classification = "threat"` or `"suspicious"` may influence a
verdict. Severity alone and informational matches do not establish malware. An
incomplete or unavailable YARA-X scan never becomes a clean result.

## Known limitations

- Only components explicitly extracted by the bounded APK extractor are scanned.
- Encrypted or unsupported ZIP structures, dynamic code downloaded after installation,
  runtime behavior, and native execution are outside this static scan.
- Rule quality and classification metadata require independent review before production
  rules are added.
- This integration does not add a remote rule-update service or upload scan data.
