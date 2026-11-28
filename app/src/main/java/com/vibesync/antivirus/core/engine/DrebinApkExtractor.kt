internal object DrebinApkExtractor {
    sealed interface Outcome {
        data class Features(val vector: FloatArray, val apkCount: Int, val dexCount: Int) : Outcome
        data class Unscannable(val reason: Reason) : Outcome
    }
    enum class Reason {
        UNREADABLE_APK, APK_INVALID, LIMIT_EXCEEDED, MANIFEST_INVALID,
        DEX_MISSING, DEX_INVALID, SCHEMA_INVALID
    }

    private const val MAX_APK_COUNT = 129
    private const val MAX_APK_BYTES = 512L * 1024 * 1024
    private const val MAX_ENTRIES_PER_APK = 1800
    private const val MAX_TOTAL_ENTRIES = 12_000
    private const val MAX_MANIFEST = 2 * 1024 * 1024
    private const val MAX_DEX_ENTRY = 4 * 1024 * 1024
    private const val MAX_TOTAL_DEX = 12 * 1024 * 1024
    private const val MAX_DEX_FILES = 30
    private const val MAX_STRINGS = 300_000
    private const val MAX_METHODS = 150_000
    private const val MAX_INSTRUCTIONS = 1_500_000
    private const val BUDGET_MS = 5_000L

    suspend fun extract(apk: File, schema: List<String>): Outcome = extract(listOf(apk), schema)

    /** Extract an ordered base APK + split APK set atomically; no partial vectors. */
    suspend fun extract(apks: List<File>, schema: List<String>): Outcome {
        if (schema.size != DrebinFeatureContract.COUNT ||
            schema.distinct().size != DrebinFeatureContract.COUNT ||
            schema.any { it.isBlank() }) return Outcome.Unscannable(Reason.SCHEMA_INVALID)

        val components = apks.distinctBy { it.absolutePath }
        if (components.isEmpty()) return Outcome.Unscannable(Reason.UNREADABLE_APK)
        if (components.size > MAX_APK_COUNT) return Outcome.Unscannable(Reason.LIMIT_EXCEEDED)
        var totalApkBytes = 0L
        for (apk in components) {
            val readable = try { apk.isFile && apk.canRead() } catch (_: SecurityException) { false }
            if (!readable) return Outcome.Unscannable(Reason.UNREADABLE_APK)
            val size = try { apk.length() } catch (_: SecurityException) {
                return Outcome.Unscannable(Reason.UNREADABLE_APK)
            }
            if (size <= 0L) return Outcome.Unscannable(Reason.UNREADABLE_APK)
            if (size > MAX_APK_BYTES || totalApkBytes > MAX_APK_BYTES - size) {
                return Outcome.Unscannable(Reason.LIMIT_EXCEEDED)
            }
            totalApkBytes += size
        }

        val start = SystemClock.elapsedRealtime()
        val permissions = mutableSetOf<String>()
        val actions = mutableSetOf<String>()
        val classes = mutableSetOf<String>()
        val calls = mutableSetOf<Pair<String, String>>()
        val callbacks = mutableSetOf<String>()
        val literals = mutableSetOf<String>()
        var dexCount = 0
        var totalDex = 0
        var totalEntries = 0
        var methods = 0
        var instructions = 0

        suspend fun heartbeat() {
            currentCoroutineContext().ensureActive()
            if (SystemClock.elapsedRealtime() - start > BUDGET_MS) throw BudgetExceeded()
        }

        return try {
            for (apk in components) {
                heartbeat()
                ZipFile(apk).use { archive ->
                    val archiveEntries = archive.size()
                    if (archiveEntries > MAX_ENTRIES_PER_APK) throw BudgetExceeded()
                    totalEntries += archiveEntries
                    if (totalEntries > MAX_TOTAL_ENTRIES) throw BudgetExceeded()

                    val manifest = archive.getEntry("AndroidManifest.xml")
                        ?: return Outcome.Unscannable(Reason.MANIFEST_INVALID)
                    if (manifest.size < 8L) return Outcome.Unscannable(Reason.MANIFEST_INVALID)
                    if (manifest.size > MAX_MANIFEST) throw BudgetExceeded()
                    val xml = archive.getInputStream(manifest).use { readBounded(it, MAX_MANIFEST) }
                    if (manifest.size >= 0L && manifest.size != xml.size.toLong()) {
                        return Outcome.Unscannable(Reason.MANIFEST_INVALID)
                    }
                    val parsed = BinaryAndroidManifest.parse(xml)
                        ?: return Outcome.Unscannable(Reason.MANIFEST_INVALID)
                    permissions.addAll(parsed.permissions)
                    actions.addAll(parsed.actions)

                    val entries = archive.entries()
                    while (entries.hasMoreElements()) {
                        heartbeat()
                        val entry = entries.nextElement()
                        if (!Regex("classes[0-9]*\\.dex").matches(entry.name)) continue
                        if (entry.size < 64L) throw InvalidDex()
                        if (entry.size > MAX_DEX_ENTRY) throw BudgetExceeded()
                        if (entry.size > MAX_TOTAL_DEX - totalDex) throw BudgetExceeded()
                        val bytes = archive.getInputStream(entry).use { readBounded(it, MAX_DEX_ENTRY) }
                        if (entry.size >= 0L && entry.size != bytes.size.toLong()) throw InvalidDex()
                        if (bytes.size < 64) throw InvalidDex()
                        totalDex += bytes.size
                        dexCount++
                        if (dexCount > MAX_DEX_FILES) throw BudgetExceeded()
                        try {
                            val dex = DexBackedDexFile(Opcodes.getDefault(), bytes)
                            if (dex.stringReferences.size > MAX_STRINGS) throw BudgetExceeded()
                            for (reference in dex.stringReferences) {
                                if (literals.size > MAX_STRINGS) throw BudgetExceeded()
                                literals.add(reference.string)
                            }
                            for (defined in dex.classes) {
                                heartbeat()
                                classes.add(defined.type)
                                for (method in defined.methods) {
                                    if (++methods > MAX_METHODS) throw BudgetExceeded()
                                    if (method.name == "onBind" || method.name == "onServiceConnected") {
                                        callbacks.add(method.name)
                                    }
                                    val implementation = method.implementation ?: continue
                                    for (instruction in implementation.instructions) {
                                        if (++instructions > MAX_INSTRUCTIONS) throw BudgetExceeded()
                                        if (instruction.opcode.name.startsWith("INVOKE_") &&
                                            instruction is ReferenceInstruction) {
                                            val invoked = instruction.reference as? MethodReference ?: continue
                                            calls.add(invoked.definingClass to invoked.name)
                                            classes.add(invoked.definingClass)
                                        }
                                    }
                                }
                            }
                        } catch (limit: BudgetExceeded) {
                            throw limit
                        } catch (invalid: InvalidDex) {
                            throw invalid
                        } catch (_: Exception) {
                            throw InvalidDex()
                        } catch (_: LinkageError) {
                            throw InvalidDex()
                        }
                    }
                }
            }
            if (dexCount == 0) Outcome.Unscannable(Reason.DEX_MISSING)
            else Outcome.Features(
                DrebinFeatureContract.vector(
                    schema,
                    DrebinFeatureContract.Observed(permissions, actions, classes, calls, callbacks, literals)
                ),
                apkCount = components.size,
                dexCount = dexCount
            )
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: BudgetExceeded) {
            Outcome.Unscannable(Reason.LIMIT_EXCEEDED)
        } catch (_: InvalidDex) {
            Outcome.Unscannable(Reason.DEX_INVALID)
        } catch (_: java.io.FileNotFoundException) {
            Outcome.Unscannable(Reason.UNREADABLE_APK)
        } catch (_: SecurityException) {
            Outcome.Unscannable(Reason.UNREADABLE_APK)
        } catch (_: java.util.zip.ZipException) {
            Outcome.Unscannable(Reason.APK_INVALID)
        } catch (_: java.io.IOException) {
            Outcome.Unscannable(Reason.APK_INVALID)
        } catch (_: Exception) {
            Outcome.Unscannable(Reason.DEX_INVALID)
        } catch (_: LinkageError) {
            Outcome.Unscannable(Reason.DEX_INVALID)
        }
    }

    private fun readBounded(stream: java.io.InputStream, max: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        while (true) {
            val count = stream.read(chunk)
            if (count < 0) break
            if (output.size() + count > max) throw BudgetExceeded()
            output.write(chunk, 0, count)
        }
        return output.toByteArray()
    }

    private class BudgetExceeded : RuntimeException()
    private class InvalidDex(cause: Throwable? = null) : RuntimeException(cause)
}

/** Parses Android binary XML chunks, reading typed manifest permission and <action> name
 * attributes, not simply searching a manifest's string pool for suspicious tokens.
 */
internal object BinaryAndroidManifest {
    data class Manifest(val permissions: Set<String>, val actions: Set<String>)

    fun parse(bytes: ByteArray): Manifest? {
        return try {
        if (bytes.size < 16) return null
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        if (u16(b, 0) != 0x0003 || u16(b, 2) != 8 ||
            b.getInt(4) != bytes.size) return null
        var offset = 8
        var strings: List<String>? = null
        val permissions = mutableSetOf<String>()
        val actions = mutableSetOf<String>()
        var elements = 0
        while (offset + 8 <= bytes.size) {
            val type = u16(b, offset)
            val header = u16(b, offset + 2)
            val size = b.getInt(offset + 4)
            if (header < 8 || size < header || offset.toLong() + size > bytes.size)
                return null
            if (type == 0x0001) {
                strings = parseStrings(b, offset, header, size) ?: return null
            } else if (type == 0x0102) {
                if (++elements > 80_000 || header < 36) return null
                val pool = strings ?: return null
                val tag = pool.getOrNull(b.getInt(offset + 20)) ?: return null
                val attributeStart = u16(b, offset + 24)
                val attributeSize = u16(b, offset + 26)
                val count = u16(b, offset + 28)
                if (attributeSize < 20 || count > 500) return null
                val begin = offset + 16 + attributeStart
                if (begin < offset + 36 ||
                    begin.toLong() + count.toLong() * attributeSize > offset + size) return null
                for (index in 0 until count) {
                    val at = begin + index * attributeSize
                    val name = pool.getOrNull(b.getInt(at + 4)) ?: continue
                    if (name != "name") continue
                    val rawIndex = b.getInt(at + 8)
                    val typeCode = b.get(at + 15).toInt() and 0xff
                    val valueIndex = if (rawIndex >= 0) rawIndex
                        else if (typeCode == 0x03) b.getInt(at + 16) else -1
                    val value = pool.getOrNull(valueIndex) ?: continue
                    when {
                        tag == "action" -> actions.add(value)
                        tag == "uses-permission" || tag == "uses-permission-sdk-23" ||
                            tag == "uses-permission-sdk-m" -> permissions.add(value)
                    }
                }
            }
            offset += size
        }
        if (strings == null || elements == 0 || offset != bytes.size) null
        else Manifest(permissions, actions)
        } catch (_: Exception) { null }
    }

    private fun parseStrings(b: ByteBuffer, offset: Int, header: Int, chunkSize: Int): List<String>? {
        if (header < 28) return null
        val count = b.getInt(offset + 8)
        val flags = b.getInt(offset + 16)
        val stringsStart = b.getInt(offset + 20)
        if (count < 1 || count > 80_000 || stringsStart < header ||
            count.toLong() * 4 + header > chunkSize) return null
        val utf8 = (flags and 0x100) != 0
        return List(count) { index ->
            val relative = b.getInt(offset + header + index * 4)
            val pos = offset.toLong() + stringsStart + relative
            if (relative < 0 || pos < offset || pos >= offset + chunkSize) error("string offset")
            val cursor = intArrayOf(pos.toInt())
            if (utf8) {
                readUtf8Length(b, cursor)
                val length = readUtf8Length(b, cursor)
                if (length < 0 || cursor[0].toLong() + length >= offset + chunkSize) error("utf8 length")
                val raw = ByteArray(length)
                for (i in 0 until length) raw[i] = b.get(cursor[0] + i)
                String(raw, Charsets.UTF_8)
            } else {
                val length = readUtf16Length(b, cursor)
                val bytes = length.toLong() * 2
                if (length < 0 || cursor[0].toLong() + bytes + 2 > offset + chunkSize) error("utf16 length")
                val raw = ByteArray(bytes.toInt())
                for (i in raw.indices) raw[i] = b.get(cursor[0] + i)
                String(raw, Charsets.UTF_16LE)
            }
        }
    }
    private fun u16(b: ByteBuffer, at: Int) = b.getShort(at).toInt() and 0xffff
    private fun readUtf8Length(b: ByteBuffer, cursor: IntArray): Int {
        val first = b.get(cursor[0]++).toInt() and 255
        if (first and 0x80 == 0) return first
        return ((first and 0x7f) shl 8) or (b.get(cursor[0]++).toInt() and 255)
    }
    private fun readUtf16Length(b: ByteBuffer, cursor: IntArray): Int {
        val first = u16(b, cursor[0]); cursor[0] += 2
        if (first and 0x8000 == 0) return first
        val next = u16(b, cursor[0]); cursor[0] += 2
        return ((first and 0x7fff) shl 16) or next
    }
}
