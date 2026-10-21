package com.vibesync.antivirus.core.worker

import android.util.JsonReader
import android.util.JsonToken
import com.vibesync.antivirus.data.local.MalwareHashEntity
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.PushbackReader
import java.io.Reader
import java.nio.charset.StandardCharsets
import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

internal data class ThreatFeedRecord(
    val sha256: String? = null,
    val md5: String? = null,
    val genericHash: String? = null,
    val iocValue: String? = null,
    val iocType: String? = null,
    val threatName: String? = null,
    val firstSeenAt: Long? = null,
    val lastSeenAt: Long? = null
)

internal object ThreatFeedIndicatorValidator {
    private val SHA256 = Regex("^[a-fA-F0-9]{64}$")
    private val MD5 = Regex("^[a-fA-F0-9]{32}$")

    fun normalize(record: ThreatFeedRecord, source: String): MalwareHashEntity? {
        val rawHash = record.genericHash?.trim()
        val sha = record.sha256?.trim()?.lowercase(Locale.ROOT)?.takeIf(SHA256::matches)
            ?: rawHash?.lowercase(Locale.ROOT)?.takeIf(SHA256::matches)
        val md5 = record.md5?.trim()?.lowercase(Locale.ROOT)?.takeIf(MD5::matches)
            ?: rawHash?.lowercase(Locale.ROOT)?.takeIf(MD5::matches)
        val type = record.iocType?.trim()?.lowercase(Locale.ROOT)?.takeIf { it.isNotBlank() && it.length <= 80 }
        val ioc = record.iocValue?.trim()?.takeIf {
            it.isNotEmpty() && it.length <= 2048 && it.none(Char::isISOControl)
        }?.let { raw ->
            if (type == "domain" || type == "hostname" || type == "fqdn") raw.lowercase(Locale.ROOT).trimEnd('.')
            else if (type?.startsWith("ip") == true) raw.lowercase(Locale.ROOT)
            else raw
        }
        if (sha == null && md5 == null && ioc == null) return null
        val primary = when {
            sha != null -> "sha256:$sha"
            md5 != null -> "md5:$md5"
            else -> "ioc:" + type.orEmpty() + ":" + ioc.orEmpty()
        }
        val safeName = record.threatName?.trim()?.takeIf {
            it.isNotEmpty() && it.length <= 180 && it.none(Char::isISOControl)
        } ?: "Unlabelled threat indicator"
        val safeSource = source.trim().take(253).ifBlank { "custom-feed" }
        return MalwareHashEntity(
            indicatorKey = "$safeSource:$primary",
            sha256Hash = sha,
            md5Hash = md5,
            iocValue = ioc,
            iocType = type,
            threatName = safeName,
            source = safeSource,
            firstSeenAt = record.firstSeenAt,
            lastSeenAt = record.lastSeenAt,
            updatedAt = System.currentTimeMillis()
        )
    }
}

class ThreatFeedParser(private val batchSize: Int = DEFAULT_BATCH_SIZE) {
    suspend fun parse(
        input: InputStream,
        format: ThreatFeedFormat,
        source: String,
        onBatch: suspend (List<MalwareHashEntity>) -> Unit
    ): Long {
        require(batchSize in 1..MAX_BATCH_SIZE) { "Unsupported batch size." }
        val sink = BatchSink(source, batchSize, onBatch)
        input.use { stream ->
            when (resolveFormat(format, source)) {
                ThreatFeedFormat.JSON -> parseJson(stream.buffered(BUFFER_SIZE), sink)
                ThreatFeedFormat.CSV -> parseCsv(stream.buffered(BUFFER_SIZE), sink)
                ThreatFeedFormat.AUTO -> throw FeedParseException("Could not determine feed format.")
            }
        }
        sink.flush()
        return sink.total
    }

    private suspend fun parseJson(input: InputStream, sink: BatchSink) {
        JsonReader(InputStreamReader(input, StandardCharsets.UTF_8)).use { reader ->
            reader.isLenient = false
            when (reader.peek()) {
                JsonToken.BEGIN_ARRAY -> readRows(reader, sink)
                JsonToken.BEGIN_OBJECT -> {
                    reader.beginObject()
                    val rootFields = LinkedHashMap<String, String>()
                    var foundContainer = false
                    while (reader.hasNext()) {
                        val name = normalizeField(reader.nextName())
                        when {
                            name in JSON_ARRAY_KEYS && reader.peek() == JsonToken.BEGIN_ARRAY -> {
                                readRows(reader, sink)
                                foundContainer = true
                            }
                            name == "querystatus" && reader.peek() in PRIMITIVE_TOKENS -> {
                                val status = readPrimitive(reader)
                                if (status !in ACCEPTED_QUERY_STATUSES) {
                                    throw FeedParseException("The threat provider rejected the request (query status: " + status.take(48) + ").")
                                }
                                rootFields[name] = status
                            }
                            reader.peek() in PRIMITIVE_TOKENS -> rootFields[name] = readPrimitive(reader).take(MAX_FIELD_LENGTH)
                            else -> reader.skipValue()
                        }
                    }
                    reader.endObject()
                    if (!foundContainer && rootFields.keys.any { it in HASH_OR_IOC_KEYS }) {
                        sink.add(recordFromFields(rootFields))
                    } else if (!foundContainer && rootFields["querystatus"] != "no_results") {
                        throw FeedParseException("JSON response has no supported data array or indicator fields.")
                    }
                }
                else -> throw FeedParseException("The JSON feed root must be an object or array.")
            }
        }
    }

    private suspend fun readRows(reader: JsonReader, sink: BatchSink) {
        reader.beginArray()
        while (reader.hasNext()) {
            when (reader.peek()) {
                JsonToken.BEGIN_OBJECT -> readRow(reader, sink)
                JsonToken.NULL -> reader.nextNull()
                else -> reader.skipValue()
            }
        }
        reader.endArray()
    }

    private suspend fun readRow(reader: JsonReader, sink: BatchSink) {
        var sha: String? = null
        var md5: String? = null
        var genericHash: String? = null
        var ioc: String? = null
        var iocType: String? = null
        var threat: String? = null
        var firstSeen: Long? = null
        var lastSeen: Long? = null
        reader.beginObject()
        while (reader.hasNext()) {
            val name = normalizeField(reader.nextName())
            when {
                name in SHA256_KEYS -> sha = readOptionalPrimitive(reader)
                name in MD5_KEYS -> md5 = readOptionalPrimitive(reader)
                name == "hash" -> genericHash = readOptionalPrimitive(reader)
                name in IOC_KEYS -> ioc = readOptionalPrimitive(reader)
                name in IOC_TYPE_KEYS -> iocType = readOptionalPrimitive(reader)
                name in THREAT_NAME_KEYS -> threat = readOptionalPrimitive(reader)
                name in FIRST_SEEN_KEYS -> firstSeen = parseTimestamp(readOptionalPrimitive(reader))
                name in LAST_SEEN_KEYS -> lastSeen = parseTimestamp(readOptionalPrimitive(reader))
                name == "malwaresamples" && reader.peek() == JsonToken.BEGIN_ARRAY -> {
                    reader.beginArray()
                    while (reader.hasNext()) {
                        if (reader.peek() == JsonToken.BEGIN_OBJECT) {
                            val sample = readSample(reader)
                            sink.add(sample.copy(
                                threatName = threat ?: sample.threatName ?: "Associated malware sample",
                                firstSeenAt = sample.firstSeenAt ?: firstSeen,
                                lastSeenAt = sample.lastSeenAt ?: lastSeen
                            ))
                        } else {
                            reader.skipValue()
                        }
                    }
                    reader.endArray()
                }
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        sink.add(ThreatFeedRecord(sha, md5, genericHash, ioc, iocType, threat, firstSeen, lastSeen))
    }

    private fun readSample(reader: JsonReader): ThreatFeedRecord {
        var sha: String? = null
        var md5: String? = null
        var genericHash: String? = null
        var threat: String? = null
        var firstSeen: Long? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (val name = normalizeField(reader.nextName())) {
                in SHA256_KEYS -> sha = readOptionalPrimitive(reader)
                in MD5_KEYS -> md5 = readOptionalPrimitive(reader)
                "hash" -> genericHash = readOptionalPrimitive(reader)
                in THREAT_NAME_KEYS -> threat = readOptionalPrimitive(reader)
                in FIRST_SEEN_KEYS -> firstSeen = parseTimestamp(readOptionalPrimitive(reader))
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return ThreatFeedRecord(sha256 = sha, md5 = md5, genericHash = genericHash, threatName = threat, firstSeenAt = firstSeen)
    }

    private suspend fun parseCsv(input: InputStream, sink: BatchSink) {
        val csv = CsvRecordReader(InputStreamReader(input, StandardCharsets.UTF_8))
        var header: List<String>? = null
        while (true) {
            val row = csv.readRecord() ?: break
            if (row.isEmpty() || row.all(String::isBlank) || row.firstOrNull()?.trim()?.startsWith("#") == true) continue
            val candidate = row.map(::normalizeField)
            if (candidate.any { it in SHA256_KEYS || it in MD5_KEYS || it == "hash" || it in IOC_KEYS }) {
                header = candidate
                break
            }
        }
        val columns = header ?: throw FeedParseException("CSV feed has no recognized hash or IOC header.")
        val indexes = columns.mapIndexed { index, key -> key to index }.toMap()
        while (true) {
            val row = csv.readRecord() ?: break
            if (row.isEmpty() || row.all(String::isBlank)) continue
            fun value(keys: Set<String>): String? {
                val index = keys.firstNotNullOfOrNull(indexes::get) ?: return null
                return row.getOrNull(index)?.trim()?.takeIf(String::isNotBlank)?.take(MAX_FIELD_LENGTH)
            }
            sink.add(ThreatFeedRecord(
                sha256 = value(SHA256_KEYS),
                md5 = value(MD5_KEYS),
                genericHash = value(setOf("hash")),
                iocValue = value(IOC_KEYS),
                iocType = value(IOC_TYPE_KEYS),
                threatName = value(THREAT_NAME_KEYS),
                firstSeenAt = parseTimestamp(value(FIRST_SEEN_KEYS)),
                lastSeenAt = parseTimestamp(value(LAST_SEEN_KEYS))
            ))
        }
    }

    private fun recordFromFields(fields: Map<String, String>) = ThreatFeedRecord(
        sha256 = fields.value(SHA256_KEYS),
        md5 = fields.value(MD5_KEYS),
        genericHash = fields["hash"],
        iocValue = fields.value(IOC_KEYS),
        iocType = fields.value(IOC_TYPE_KEYS),
        threatName = fields.value(THREAT_NAME_KEYS),
        firstSeenAt = parseTimestamp(fields.value(FIRST_SEEN_KEYS)),
        lastSeenAt = parseTimestamp(fields.value(LAST_SEEN_KEYS))
    )

    private fun Map<String, String>.value(keys: Set<String>): String? =
        keys.firstNotNullOfOrNull { this[it] }?.takeIf(String::isNotBlank)

    private fun readOptionalPrimitive(reader: JsonReader): String? =
        if (reader.peek() == JsonToken.NULL) {
            reader.nextNull()
            null
        } else if (reader.peek() in PRIMITIVE_TOKENS) {
            readPrimitive(reader).take(MAX_FIELD_LENGTH)
        } else {
            reader.skipValue()
            null
        }

    private fun readPrimitive(reader: JsonReader): String = when (reader.peek()) {
        JsonToken.STRING, JsonToken.NUMBER, JsonToken.BOOLEAN -> reader.nextString()
        JsonToken.NULL -> { reader.nextNull(); "" }
        else -> { reader.skipValue(); "" }
    }

    private fun normalizeField(raw: String): String =
        raw.trim().removePrefix("\uFEFF").lowercase(Locale.ROOT).replace(Regex("[^a-z0-9]"), "")

    private fun resolveFormat(format: ThreatFeedFormat, source: String): ThreatFeedFormat =
        if (format != ThreatFeedFormat.AUTO) format else when {
            source.substringBefore('?').endsWith(".csv", ignoreCase = true) -> ThreatFeedFormat.CSV
            else -> ThreatFeedFormat.JSON
        }

    private fun parseTimestamp(raw: String?): Long? {
        val value = raw?.trim()?.takeIf(String::isNotBlank) ?: return null
        value.toLongOrNull()?.let { numeric ->
            if (numeric <= 0) return null
            return if (numeric < 10_000_000_000L) numeric * 1000L else numeric
        }
        val patterns = listOf(
            "yyyy-MM-dd HH:mm:ss 'UTC'",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd"
        )
        for (pattern in patterns) {
            val parser = SimpleDateFormat(pattern, Locale.US).apply {
                timeZone = TimeZone.getTimeZone("UTC")
                isLenient = false
            }
            val position = ParsePosition(0)
            val date: Date? = parser.parse(value, position)
            if (date != null && position.index == value.length) return date.time
        }
        return null
    }

    private class BatchSink(
        private val source: String,
        private val batchSize: Int,
        private val onBatch: suspend (List<MalwareHashEntity>) -> Unit
    ) {
        private val batch = ArrayList<MalwareHashEntity>(batchSize)
        var total: Long = 0
            private set

        suspend fun add(record: ThreatFeedRecord) {
            val normalized = ThreatFeedIndicatorValidator.normalize(record, source) ?: return
            batch += normalized
            total++
            if (batch.size >= batchSize) flush()
        }

        suspend fun flush() {
            if (batch.isEmpty()) return
            onBatch(batch.toList())
            batch.clear()
        }
    }

    private class CsvRecordReader(reader: Reader) {
        private val input = PushbackReader(BufferedReader(reader, BUFFER_SIZE), 1)

        fun readRecord(): List<String>? {
            val fields = ArrayList<String>()
            val cell = StringBuilder()
            var quoted = false
            var seen = false
            var rowChars = 0
            while (true) {
                val raw = input.read()
                if (raw < 0) {
                    if (!seen && fields.isEmpty() && cell.isEmpty()) return null
                    if (quoted) throw FeedParseException("CSV contains an unterminated quoted field.")
                    fields += cell.toString()
                    return fields
                }
                seen = true
                rowChars++
                if (rowChars > MAX_CSV_RECORD_CHARS) throw FeedParseException("CSV row exceeds the supported size limit.")
                val ch = raw.toChar()
                if (quoted) {
                    if (ch == '"') {
                        val next = input.read()
                        if (next == '"'.code) {
                            cell.append('"')
                            rowChars++
                        } else {
                            quoted = false
                            if (next >= 0) input.unread(next)
                        }
                    } else {
                        cell.append(ch)
                    }
                } else {
                    when (ch) {
                        '"' -> if (cell.isEmpty()) quoted = true else cell.append(ch)
                        ',' -> { fields += cell.toString(); cell.setLength(0) }
                        '\n' -> { fields += cell.toString(); return fields }
                        '\r' -> {
                            val next = input.read()
                            if (next >= 0 && next != '\n'.code) input.unread(next)
                            fields += cell.toString()
                            return fields
                        }
                        else -> cell.append(ch)
                    }
                }
                if (cell.length > MAX_FIELD_LENGTH) throw FeedParseException("CSV field exceeds the supported size limit.")
            }
        }
    }

    companion object {
        private const val DEFAULT_BATCH_SIZE = 500
        private const val MAX_BATCH_SIZE = 1000
        private const val BUFFER_SIZE = 64 * 1024
        private const val MAX_FIELD_LENGTH = 4096
        private const val MAX_CSV_RECORD_CHARS = 64 * 1024
        private val JSON_ARRAY_KEYS = setOf("data", "results", "iocs", "indicators", "definitions", "items")
        private val SHA256_KEYS = setOf("sha256", "sha256hash", "hashsha256")
        private val MD5_KEYS = setOf("md5", "md5hash", "hashmd5")
        private val IOC_KEYS = setOf("ioc", "iocvalue", "domain", "hostname", "fqdn", "ip", "ipaddress", "ipport", "url", "indicator")
        private val IOC_TYPE_KEYS = setOf("ioctype", "indicatortype", "type")
        private val THREAT_NAME_KEYS = setOf("malware", "malwareprintable", "malwarefamily", "threatname", "family", "signature", "threat")
        private val FIRST_SEEN_KEYS = setOf("firstseen", "firstseenat", "timestamp", "timestampfirstseen", "time", "timestamputc")
        private val LAST_SEEN_KEYS = setOf("lastseen", "lastseenat", "updated", "lastupdated", "timestampupdated")
        private val HASH_OR_IOC_KEYS = SHA256_KEYS + MD5_KEYS + IOC_KEYS + setOf("hash")
        private val ACCEPTED_QUERY_STATUSES = setOf("ok", "success", "no_results", "not_found")
        private val PRIMITIVE_TOKENS = setOf(JsonToken.STRING, JsonToken.NUMBER, JsonToken.BOOLEAN, JsonToken.NULL)
    }
}

class FeedParseException(message: String) : Exception(message)
