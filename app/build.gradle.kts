import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.util.Base64
import java.util.zip.GZIPOutputStream
import java.security.MessageDigest
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.AtomicMoveNotSupportedException
plugins {
 id("com.android.application")
 id("org.jetbrains.kotlin.android")
 id("org.jetbrains.kotlin.kapt")
 id("org.jetbrains.kotlin.plugin.compose")
 id("app.cash.paparazzi")
}
fun cfg(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

val feedManifestPublicKey = providers.environmentVariable("SAFE_MOBILE_FEED_ED25519_PUBLIC_KEY_B64").orNull?.trim().orEmpty()
val hashDatabasePublicKey = providers.environmentVariable("SAFE_MOBILE_HASHDB_ED25519_PUBLIC_KEY_B64").orNull?.trim().orEmpty()
val releaseStoreBase64 = providers.environmentVariable("KEYSTORE_BASE64").orNull
val releaseStorePassword = providers.environmentVariable("KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("KEY_PASSWORD").orNull
val signingValues = listOf(releaseStoreBase64, releaseStorePassword, releaseKeyAlias, releaseKeyPassword)
val releaseSigningEnabled = signingValues.all { !it.isNullOrBlank() }
if (signingValues.any { !it.isNullOrBlank() } && !releaseSigningEnabled) {
    throw GradleException("Release signing is partially configured. Set all four KEYSTORE_BASE64, KEYSTORE_PASSWORD, KEY_ALIAS and KEY_PASSWORD variables, or leave all empty.")
}

android {
 namespace = "com.vibesync.antivirus"
 compileSdk = 36
 flavorDimensions += "network"
 productFlavors {
  create("offline") {
   dimension = "network"
   buildConfigField("Boolean", "OPTIONAL_FEED_ENABLED", "false")
  }
  create("feed") {
   dimension = "network"
   buildConfigField("Boolean", "OPTIONAL_FEED_ENABLED", "true")
  }
 }
 defaultConfig {
  applicationId = "com.vibesync.antivirus"
  minSdk = 26
  targetSdk = 36
  versionCode = 20261147
  // [release-v1.8.1] Compliance hardening: truthful posture score, minimized Device Admin, no own overlay permission.
  versionName = "1.8.1"
  testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
  buildConfigField("String", "FEED_MANIFEST_PUBLIC_KEY_B64", cfg(feedManifestPublicKey))
  buildConfigField("Boolean", "FEED_MANIFEST_KEY_CONFIGURED", (!feedManifestPublicKey.isBlank()).toString())
  buildConfigField("String", "HASHDB_PUBLIC_KEY_B64", cfg(hashDatabasePublicKey))
  buildConfigField("Boolean", "HASHDB_PUBLIC_KEY_CONFIGURED", (!hashDatabasePublicKey.isBlank()).toString())
 }
 signingConfigs {
  if (releaseSigningEnabled) {
   create("release") {
    val keystoreFile = layout.buildDirectory.file("signing/safemobile-release.jks").get().asFile
    if (!keystoreFile.isFile) {
     keystoreFile.parentFile.mkdirs()
     keystoreFile.writeBytes(Base64.getDecoder().decode(releaseStoreBase64))
    }
    storeFile = keystoreFile
    storePassword = releaseStorePassword
    keyAlias = releaseKeyAlias
    keyPassword = releaseKeyPassword
   }
  }
 }
 buildTypes {
  debug {
   applicationIdSuffix = ".debug"
   versionNameSuffix = "-debug"
  }
  release {
   isMinifyEnabled = true
   isShrinkResources = true
   // Keep x86_64 available to debug emulator tests; production APK/AAB ships ARM only.
   ndk {
    abiFilters += listOf("arm64-v8a", "armeabi-v7a")
    debugSymbolLevel = "FULL"
   }
   if (releaseSigningEnabled) signingConfig = signingConfigs.getByName("release")
   proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
  }
 }
 buildFeatures { compose = true; buildConfig = true }
 compileOptions {
  sourceCompatibility = JavaVersion.VERSION_17
  targetCompatibility = JavaVersion.VERSION_17
 }
 kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
 packaging { resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1") }
}

// YARA-X Android JNI wrapper, pinned to an immutable upstream revision.
// The application performs no network access for scanning; the native source is
// fetched only when building APK/AAB artifacts and compiled into packaged jniLibs.
val yaraXSourceRevision = "b666fbc15ff67fba1ceaf5deb68d071b44a1cbfe"
val yaraXSourceDirectory = layout.buildDirectory.dir("native/yarax_android")
val yaraXGeneratedJniDirectory = layout.buildDirectory.dir("generated/yarax-jniLibs")
val yaraXAndroidAbis = providers.gradleProperty("yaraxAndroidAbis").orNull
    ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }?.distinct()
    ?: listOf("arm64-v8a", "armeabi-v7a")
require(yaraXAndroidAbis.isNotEmpty() &&
    yaraXAndroidAbis.all { it in setOf("arm64-v8a", "armeabi-v7a", "x86_64") }) {
    "yaraxAndroidAbis must contain supported Android ABI names."
}

val prepareYaraXNativeSource = tasks.register("prepareYaraXNativeSource") {
    val sourceDirectory = yaraXSourceDirectory.get().asFile
    val revisionMarker = sourceDirectory.resolve(".safemobile-source-revision")
    inputs.property("yaraxAndroidRevision", yaraXSourceRevision)
    outputs.dir(yaraXSourceDirectory)
    outputs.upToDateWhen {
        revisionMarker.isFile &&
            revisionMarker.readText().trim() == yaraXSourceRevision &&
            sourceDirectory.resolve("src/lib.rs").isFile &&
            sourceDirectory.resolve("yarax_patches/yara-x/Cargo.toml").isFile
    }
    doLast {
        if (!sourceDirectory.resolve(".git").isDirectory) {
            sourceDirectory.deleteRecursively()
            check(sourceDirectory.parentFile.mkdirs() || sourceDirectory.parentFile.isDirectory) {
                "Could not create YARA-X build source directory."
            }
            project.exec {
                commandLine(
                    "git", "clone", "--no-checkout",
                    "https://github.com/RevEngiSquad/yarax_android.git",
                    sourceDirectory.absolutePath
                )
            }.assertNormalExitValue()
        }

        project.exec {
            workingDir = sourceDirectory
            commandLine("git", "fetch", "--depth=1", "origin", yaraXSourceRevision)
        }.assertNormalExitValue()
        project.exec {
            workingDir = sourceDirectory
            commandLine("git", "checkout", "--force", "--detach", yaraXSourceRevision)
        }.assertNormalExitValue()
        project.exec {
            workingDir = sourceDirectory
            commandLine("git", "submodule", "sync", "--recursive")
        }.assertNormalExitValue()
        project.exec {
            workingDir = sourceDirectory
            commandLine("git", "submodule", "update", "--init", "--recursive", "--depth", "1")
        }.assertNormalExitValue()

        check(sourceDirectory.resolve("src/lib.rs").isFile) {
            "Pinned YARA-X Android JNI source is incomplete."
        }
        check(sourceDirectory.resolve("yarax_patches/yara-x/Cargo.toml").isFile) {
            "Pinned YARA-X recursive source submodule is missing."
        }
        revisionMarker.writeText(yaraXSourceRevision + System.lineSeparator())
    }
}

// The upstream JNI crate's build.rs intentionally skips patching when the nested
// YARA-X submodule already has local changes. Gradle caches can restore that tree
// in an unpatched state, so never rely on the upstream dirty-tree heuristic.
// Reset the pinned nested checkout and apply the complete patch set before cargo
// starts; build.rs will then correctly observe the applied patches and leave them.
val prepareYaraXPatches = tasks.register("prepareYaraXPatches") {
    group = "build"
    description = "Apply the pinned YARA-X DEX protobuf/parser patches deterministically."
    dependsOn(prepareYaraXNativeSource)
    doLast {
        val patchesDirectory = yaraXSourceDirectory.get().asFile.resolve("yarax_patches")
        val patchedYaraXDirectory = patchesDirectory.resolve("yara-x")
        check(patchesDirectory.resolve("Makefile").isFile &&
            patchesDirectory.resolve("patches").isDirectory &&
            patchedYaraXDirectory.resolve(".git").exists()) {
            "Pinned YARA-X patch submodule is incomplete."
        }

        project.exec {
            workingDir = patchesDirectory
            commandLine("make", "patch")
        }.assertNormalExitValue()

        // The pinned YARA-X fork defaults to Wasmtime/Cranelift JIT. Android 9 and
        // earlier deny the executable-memory/membarrier path used by JIT, so enable
        // Wasmtime Pulley and select it at runtime only for SDK levels below 29.
        // Restore the pinned JNI files before applying the deterministic bridge patch.
        val nativeSourceDirectory = yaraXSourceDirectory.get().asFile
        project.exec {
            workingDir = nativeSourceDirectory
            commandLine("git", "checkout", "--", "Cargo.toml", "src/lib.rs")
        }.assertNormalExitValue()

        val nativeManifest = nativeSourceDirectory.resolve("Cargo.toml")
        val nativeManifestText = nativeManifest.readText()
        val defaultYaraXDependency = "yara-x = { path = \"./yarax_patches/yara-x/lib\", default-features = false, features = [\"dex-module\", \"hash-module\", \"crypto\", \"pe-module\", \"elf-module\", \"generate-proto-code\"]}"
        val pulleyYaraXDependency = "yara-x = { path = \"./yarax_patches/yara-x/lib\", default-features = false, features = [\"dex-module\", \"hash-module\", \"crypto\", \"pe-module\", \"elf-module\", \"generate-proto-code\", \"pulley\"]}"
        check(nativeManifestText.contains(defaultYaraXDependency) ||
            nativeManifestText.contains(pulleyYaraXDependency)) {
            "Pinned YARA-X JNI dependency changed; review the Android Pulley feature patch."
        }
        nativeManifest.writeText(nativeManifestText.replace(defaultYaraXDependency, pulleyYaraXDependency))

        val nativeJniSource = nativeSourceDirectory.resolve("src/lib.rs")
        val nativeJniText = nativeJniSource.readText()
        val compilerCreateBefore = """pub extern "system" fn Java_org_revengi_abhi_yarax_Compiler_create(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let compiler = Compiler::new();"""
        val compilerCreateAfter = """pub extern "system" fn Java_org_revengi_abhi_yarax_Compiler_create(
    mut env: JNIEnv,
    _class: JClass,
) -> jlong {
    configure_yara_x_android_runtime(&mut env);
    let compiler = Compiler::new();"""
        check(nativeJniText.windowed(compilerCreateBefore.length).count { it == compilerCreateBefore } == 1) {
            "Pinned YARA-X JNI Compiler_create entry point changed; refusing to apply an unsafe runtime patch."
        }
        val runtimeBridgeHelper = """
            fn configure_yara_x_android_runtime(env: &mut JNIEnv) {
                let api_level = match env.find_class(concat!("android/os/Build", "$", "VERSION")) {
                    Ok(version_class) => match env
                        .get_static_field(version_class, "SDK_INT", "I")
                        .and_then(|value| value.i())
                    {
                        Ok(api_level) => api_level,
                        Err(_) => {
                            let _ = env.exception_clear();
                            0
                        }
                    },
                    Err(_) => {
                        let _ = env.exception_clear();
                        0
                    }
                };
                // Fail safe to the interpreter if Android SDK lookup fails.
                yara_x::set_android_api_level(api_level);
            }
        """.trimIndent()
        val nativeJniUpdated = nativeJniText
            .replace("struct NativeCompiler {", runtimeBridgeHelper + "\nstruct NativeCompiler {")
            .replace(compilerCreateBefore, compilerCreateAfter)
        val deserializeBefore = """pub extern "system" fn Java_org_revengi_abhi_yarax_Rules_deserializeFromBytes(
    env: JNIEnv,
    _class: JClass,
    bytes: JByteArray,
) -> jlong {
    let bytes_len = env.get_array_length(&bytes).unwrap_or(0) as usize;"""
        val deserializeAfter = """pub extern "system" fn Java_org_revengi_abhi_yarax_Rules_deserializeFromBytes(
    mut env: JNIEnv,
    _class: JClass,
    bytes: JByteArray,
) -> jlong {
    configure_yara_x_android_runtime(&mut env);
    let bytes_len = env.get_array_length(&bytes).unwrap_or(0) as usize;"""
        check(nativeJniUpdated.windowed(deserializeBefore.length).count { it == deserializeBefore } == 1) {
            "Pinned YARA-X JNI Rules_deserializeFromBytes entry point changed; refusing to apply an unsafe runtime patch."
        }
        nativeJniSource.writeText(nativeJniUpdated.replace(deserializeBefore, deserializeAfter))

        // Add an Android-only configuration hook to the pinned YARA-X library.
        // The JNI bridge calls it before the shared Wasmtime engine is created.
        val yaraRoot = patchedYaraXDirectory.resolve("lib/src/lib.rs")
        val yaraRootText = yaraRoot.readText()
        check(yaraRootText.windowed("mod wasm;".length).count { it == "mod wasm;" } == 1) {
            "Pinned YARA-X crate root changed; refusing to apply the Android runtime hook."
        }
        yaraRoot.writeText(yaraRootText.replace(
            "mod wasm;",
            """mod wasm;

            #[cfg(all(target_os = "android", feature = "pulley"))]
            /// Sets the Android API level before the shared YARA-X WASM runtime is initialized.
            ///
            /// On Android API levels below 29, YARA-X uses the portable Pulley
            /// interpreter instead of Cranelift JIT to avoid restricted executable-memory
            /// and membarrier syscalls. Call this before constructing a compiler or ruleset.
            pub fn set_android_api_level(api_level: i32) {
                wasm::set_android_api_level(api_level);
            }"""
        ))

        val wasmRuntime = patchedYaraXDirectory.resolve("lib/src/wasm/mod.rs")
        val wasmRuntimeText = wasmRuntime.readText()
        val syncImport = "use std::sync::{LazyLock, OnceLock};"
        check(wasmRuntimeText.windowed(syncImport.length).count { it == syncImport } == 1) {
            "Pinned YARA-X WASM module imports changed; refusing to apply the Android runtime hook."
        }
        val androidApiState = """
            #[cfg(all(target_os = "android", feature = "pulley"))]
            use std::sync::atomic::{AtomicI32, Ordering};

            #[cfg(all(target_os = "android", feature = "pulley"))]
            static ANDROID_API_LEVEL: AtomicI32 = AtomicI32::new(0);

            #[cfg(all(target_os = "android", feature = "pulley"))]
            pub(crate) fn set_android_api_level(api_level: i32) {
                ANDROID_API_LEVEL.store(api_level, Ordering::Release);
            }
        """.trimIndent()
        val withAndroidApiState = wasmRuntimeText.replace(syncImport, syncImport + "\n" + androidApiState)
        val defaultPulleyConfig = """
            #[cfg(feature = "pulley")]
            {
                #[cfg(target_pointer_width = "64")]
                config.target("pulley64").unwrap();
                #[cfg(target_pointer_width = "32")]
                config.target("pulley32").unwrap();
            }
        """.trimIndent().prependIndent("    ")
        val apiAwarePulleyConfig = """
            // Android 9 (API 28) and lower block syscalls needed by Cranelift.
            // Select Pulley only on those devices; newer Android keeps native JIT.
            #[cfg(all(feature = "pulley", target_os = "android"))]
            if ANDROID_API_LEVEL.load(Ordering::Acquire) < 29 {
                #[cfg(target_pointer_width = "64")]
                config.target("pulley64").unwrap();
                #[cfg(target_pointer_width = "32")]
                config.target("pulley32").unwrap();
            }

            // Preserve explicit Pulley behavior on non-Android consumers.
            #[cfg(all(feature = "pulley", not(target_os = "android")))]
            {
                #[cfg(target_pointer_width = "64")]
                config.target("pulley64").unwrap();
                #[cfg(target_pointer_width = "32")]
                config.target("pulley32").unwrap();
            }
        """.trimIndent().prependIndent("    ")
        check(withAndroidApiState.windowed(defaultPulleyConfig.length).count { it == defaultPulleyConfig } == 1) {
            "Pinned YARA-X Pulley configuration changed; refusing to apply the Android SDK gate."
        }
        val finalWasmRuntime = withAndroidApiState.replace(defaultPulleyConfig, apiAwarePulleyConfig)
        check(finalWasmRuntime.contains("ANDROID_API_LEVEL.load(Ordering::Acquire) < 29") &&
            finalWasmRuntime.contains("config.target(\"pulley64\")") &&
            finalWasmRuntime.contains("config.target(\"pulley32\")")) {
            "Android Pulley interpreter configuration is incomplete."
        }
        wasmRuntime.writeText(finalWasmRuntime)

        // Verify the Android runtime patch in the exact source tree consumed by cargo.
        check(nativeManifest.readText().contains("\"pulley\"") &&
            nativeJniSource.readText().contains("yara_x::set_android_api_level") &&
            yaraRoot.readText().contains("pub fn set_android_api_level") &&
            wasmRuntime.readText().contains("ANDROID_API_LEVEL.load(Ordering::Acquire) < 29")) {
            "Android 9 Pulley runtime patch was not completely applied."
        }

        val dexParser = patchedYaraXDirectory.resolve("lib/src/modules/dex/parser.rs")
            .takeIf { it.isFile }?.readText()
            ?: throw GradleException("Patched YARA-X DEX parser is missing.")
        val dexProto = patchedYaraXDirectory.resolve("lib/src/modules/protos/dex.proto")
            .takeIf { it.isFile }?.readText()
            ?: throw GradleException("Patched YARA-X DEX protobuf schema is missing.")
        check(
            dexParser.contains("item.set_interfaces_off(interfaces_off)") &&
                dexParser.contains("result.set_string_ids_size(header.string_ids_size)") &&
                dexParser.contains("let string_ids = Self::parse_string_ids(data, &header)") &&
                dexProto.contains("repeated StringId string_ids = 10;") &&
                dexProto.contains("message StringId")
        ) {
            "Pinned YARA-X DEX patch set did not apply completely."
        }
    }
}

val buildYaraXNative = tasks.register<Exec>("buildYaraXNative") {
    group = "build"
    description = "Build the pinned YARA-X JNI library for supported Android ABIs."
    dependsOn(prepareYaraXPatches)
    workingDir = yaraXSourceDirectory.get().asFile
    inputs.dir(yaraXSourceDirectory)
    inputs.property("androidAbis", yaraXAndroidAbis)
    outputs.dir(yaraXGeneratedJniDirectory)
    doFirst {
        val outputDirectory = yaraXGeneratedJniDirectory.get().asFile
        outputDirectory.deleteRecursively()
        check(outputDirectory.mkdirs() || outputDirectory.isDirectory) {
            "Could not create generated YARA-X JNI output directory."
        }
        val ndkArguments = yaraXAndroidAbis.flatMap { listOf("-t", it) }
        commandLine(
            listOf("cargo", "ndk") + ndkArguments +
                listOf("-o", outputDirectory.absolutePath, "build", "--release")
        )
    }
}

android.sourceSets.getByName("main").jniLibs.srcDir(yaraXGeneratedJniDirectory)
tasks.matching {
    it.name.startsWith("merge") && it.name.endsWith("JniLibFolders")
}.configureEach {
    dependsOn(buildYaraXNative)
}

// Keep readable rule/definition sources under src/main/raw_assets for review and tests.
// Only the generated compressed copies are registered as Android application assets.
val protectedSecurityAssetDirectory = layout.buildDirectory.dir("generated/protected-security-assets-v2/assets")
val protectedSecurityAssetInputs = listOf(
    layout.projectDirectory.file("src/main/raw_assets/yara/safemobile_android_dex.yar").asFile,
    layout.projectDirectory.file("src/main/raw_assets/offline-threat-definitions.json").asFile,
    layout.projectDirectory.file("src/main/raw_assets/signatures/mock_signatures.hsb").asFile
)
val packageProtectedSecurityAssets = tasks.register("packageProtectedSecurityAssets") {
    group = "build setup"
    description = "GZIP bundled threat signatures and definitions before APK/AAB packaging."
    inputs.files(protectedSecurityAssetInputs)
    outputs.dir(protectedSecurityAssetDirectory)
    doLast {
        val outputRoot = protectedSecurityAssetDirectory.get().asFile
        outputRoot.deleteRecursively()
        check(outputRoot.mkdirs() || outputRoot.isDirectory) {
            "Could not create protected security asset output directory."
        }
        val relativeOutputs = listOf(
            "yara/safemobile_android_dex.yar.dat",
            "offline-threat-definitions.json.dat",
            "signatures/mock_signatures.hsb.dat"
        )
        protectedSecurityAssetInputs.zip(relativeOutputs).forEach { (source, relativePath) ->
            check(source.isFile) { "Required security asset source is missing: ${source.path}" }
            val target = outputRoot.resolve(relativePath)
            check(target.parentFile.mkdirs() || target.parentFile.isDirectory) {
                "Could not create protected security asset directory: ${target.parent}"
            }
            GZIPOutputStream(target.outputStream().buffered()).use { gzip ->
                source.inputStream().use { input -> input.copyTo(gzip) }
            }
            check(target.length() > 0L) { "Protected security asset is empty: $relativePath" }
        }
    }
}
val mainAssetSources = android.sourceSets.getByName("main").assets
mainAssetSources.exclude(
    "**/yara/safemobile_android_dex.yar",
    "**/offline-threat-definitions.json",
    "**/signatures/mock_signatures.hsb"
)
// Register the producing task itself as the asset source. Gradle then binds the
// generated output directory to the producer and cannot reuse an unrelated/stale
// source snapshot when the checked-in files move between source directories.
mainAssetSources.srcDir(packageProtectedSecurityAssets)

// docs/BENCHMARK_REPORT.md is canonical: the hidden card reads its build-time asset copy.
// Generated assets are not committed and never contain APK samples.
val benchmarkAssetDirectory = layout.buildDirectory.dir("generated/benchmark-report/assets")
val stageBenchmarkReport = tasks.register<Copy>("stageBenchmarkReport") {
    from(rootProject.file("docs/BENCHMARK_REPORT.md"))
    into(benchmarkAssetDirectory)
    rename { "benchmark-report.md" }
}
// Register the producing TaskProvider, not just its build/ path. This propagates
// Gradle's builtBy dependency to lint model writers and all variant asset consumers.
android.sourceSets.getByName("main").assets.srcDir(stageBenchmarkReport)
// AGP's vital lint tasks inspect assets separately from merge<Variant>Assets.
// Keep an explicit dependency as a belt-and-braces guard across AGP upgrades.

// Fetch the immutable, publisher-approved research release from the separate ML repository.
// The assets live only in the local build workspace (ignored by Git); they are never committed
// to this application repository. The model file is renamed to model.tflite for the Android app.
val mlModelUrl = "https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/download/v1.0.1-model/malware_model.tflite"
val mlSchemaUrl = "https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/download/v1.0.1-model/feature_schema.json"
val mlModelSha256 = "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"
val mlSchemaSha256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
val mlModelSize = 18_584L
val mlSchemaSize = 6_856L

val downloadMlAssets = tasks.register("downloadMlAssets") {
    group = "build setup"
    description = "Download and SHA-256 verify the approved v1.0.1-model assets from the ML repository."
    val modelFile = layout.projectDirectory.file("src/main/assets/model.tflite").asFile
    val schemaFile = layout.projectDirectory.file("src/main/assets/feature_schema.json").asFile
    inputs.property("mlRelease", "v1.0.1-model")
    inputs.property("modelUrl", mlModelUrl)
    inputs.property("schemaUrl", mlSchemaUrl)
    inputs.property("modelSha256", mlModelSha256)
    inputs.property("schemaSha256", mlSchemaSha256)
    outputs.files(modelFile, schemaFile)

    fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    fun isValid(asset: File, expectedSize: Long, expectedSha: String): Boolean =
        asset.isFile && asset.length() == expectedSize &&
            runCatching { sha256(asset.readBytes()) == expectedSha }.getOrDefault(false)

    outputs.upToDateWhen {
        isValid(modelFile, mlModelSize, mlModelSha256) &&
            isValid(schemaFile, mlSchemaSize, mlSchemaSha256)
    }

    doLast {
        fun downloadAndVerify(
            sourceUrl: String,
            destination: File,
            expectedSize: Long,
            expectedSha: String,
            maxBytes: Long
        ) {
            check(destination.parentFile.mkdirs() || destination.parentFile.isDirectory) {
                "Could not create ML asset directory: ${destination.parentFile}"
            }
            val temporary = File(destination.parentFile, destination.name + ".download")
            temporary.delete()
            try {
                val connection = URL(sourceUrl).openConnection().apply {
                    connectTimeout = 20_000
                    readTimeout = 45_000
                    useCaches = false
                    setRequestProperty("User-Agent", "SafeMobile-Gradle-ML-Bridge")
                }
                connection.getInputStream().buffered().use { input ->
                    temporary.outputStream().buffered().use { output ->
                        val buffer = ByteArray(8 * 1024)
                        var total = 0L
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (count == 0) continue
                            total += count
                            require(total <= maxBytes) {
                                "ML release asset exceeded its download size limit: $sourceUrl"
                            }
                            output.write(buffer, 0, count)
                        }
                    }
                }

                val bytes = temporary.readBytes()
                require(bytes.size.toLong() == expectedSize) {
                    "Unexpected ML asset size for ${destination.name}: ${bytes.size}"
                }
                require(sha256(bytes) == expectedSha) {
                    "SHA-256 mismatch for ML asset ${destination.name}; refusing to package it."
                }
                if (destination.exists()) destination.delete()
                try {
                    Files.move(
                        temporary.toPath(),
                        destination.toPath(),
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                    )
                } catch (_: AtomicMoveNotSupportedException) {
                    Files.move(temporary.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                temporary.delete()
            }
        }

        downloadAndVerify(
            mlModelUrl,
            modelFile,
            mlModelSize,
            mlModelSha256,
            20L * 1024 * 1024
        )
        require(String(modelFile.readBytes(), 4, 4, Charsets.US_ASCII) == "TFL3") {
            "Downloaded ML model is not a TensorFlow Lite flatbuffer."
        }
        downloadAndVerify(
            mlSchemaUrl,
            schemaFile,
            mlSchemaSize,
            mlSchemaSha256,
            32L * 1024
        )
        logger.lifecycle("Downloaded and verified ML release v1.0.1-model into app/src/main/assets/.")
    }
}

// The standard Android preBuild lifecycle cannot start until both verified ML assets exist.
tasks.named("preBuild").configure {
    dependsOn(downloadMlAssets)
}

// All AGP model writers, analyzers, lint report and asset merger tasks must
// wait for generated inputs; never disable Android lint or Gradle validation.
tasks.matching {
    (it.name.startsWith("merge") && it.name.endsWith("Assets")) ||
        it.name.contains("Lint") || it.name.startsWith("lint")
}.configureEach {
    dependsOn(stageBenchmarkReport, downloadMlAssets, packageProtectedSecurityAssets)
}

kapt { correctErrorTypes = true }
dependencies {
 implementation("androidx.core:core-ktx:1.16.0")
 implementation("androidx.core:core-splashscreen:1.2.0")
 implementation("androidx.datastore:datastore-preferences:1.3.0")
 implementation("androidx.documentfile:documentfile:1.0.1")
 implementation("androidx.activity:activity-compose:1.10.1")
 implementation("androidx.navigation:navigation-compose:2.9.8")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
 implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.1")
 implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.1")
 implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.1")
 implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.1")
 implementation(platform("androidx.compose:compose-bom:2025.05.01"))
 implementation("androidx.compose.ui:ui")
 implementation("androidx.compose.ui:ui-tooling-preview")
 implementation("androidx.compose.foundation:foundation")
 implementation("androidx.compose.material3:material3")
 implementation("androidx.compose.material:material-icons-extended")
 debugImplementation("androidx.compose.ui:ui-tooling")
 debugImplementation("androidx.compose.ui:ui-test-manifest")
 implementation("androidx.room:room-runtime:2.7.2")
 implementation("androidx.room:room-ktx:2.7.2")
 kapt("androidx.room:room-compiler:2.7.2")
 implementation("androidx.work:work-runtime-ktx:2.10.2")
 implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
 implementation("com.google.crypto.tink:tink-android:1.16.0")
 // Google Android SDK License: Play Billing is only for explicit checkout, never scanning.
 implementation("com.android.billingclient:billing-ktx:8.3.0")
 implementation("com.google.android.play:app-update-ktx:2.1.0")
 // Google Mobile Ads Next-Gen SDK and UMP consent platform.
 implementation("com.google.android.libraries.ads.mobile.sdk:ads-mobile-sdk:1.6.0")
 implementation("com.google.android.ump:user-messaging-platform:4.0.0")
 // Apache-2.0: KeyStore-backed encrypted local device-bound entitlement.
 implementation("androidx.security:security-crypto:1.1.0")
 // TensorFlow Lite 2.17.0 is local inference only; no model training or network calls.
 implementation("org.tensorflow:tensorflow-lite:2.14.0")
 implementation("org.tensorflow:tensorflow-lite-support:0.4.4")
 // Apache-2.0 OkHttp is confined to the opt-in weekly model download worker.
 implementation("com.squareup.okhttp3:okhttp:4.12.0")
 // BSD-3-Clause: structured read-only DEX parsing of 215 research features.
 implementation("org.smali:dexlib2:2.5.2")
 implementation("com.google.guava:guava:33.4.8-android")
 implementation("org.bouncycastle:bcprov-jdk18on:1.86")
 // The instrumentation APK is separate from the app APK and must carry its own Kotlin runtime.
 androidTestImplementation(kotlin("stdlib"))
 androidTestImplementation("androidx.test:runner:1.6.2")
 androidTestImplementation("androidx.test.ext:junit:1.2.1")
 androidTestImplementation(platform("androidx.compose:compose-bom:2025.05.01"))
 androidTestImplementation("androidx.compose.ui:ui-test-junit4")
 androidTestImplementation("androidx.compose.ui:ui-test")
 androidTestImplementation("androidx.test:core:1.6.1")
 androidTestImplementation("androidx.room:room-testing:2.7.2")
 testImplementation("org.json:json:20240303")
 testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
 testImplementation("junit:junit:4.13.2")
 testImplementation(platform("androidx.compose:compose-bom:2025.05.01"))
 testImplementation("androidx.compose.ui:ui-test-junit4")
 testImplementation("com.google.testparameterinjector:test-parameter-injector:1.25")
 testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}

