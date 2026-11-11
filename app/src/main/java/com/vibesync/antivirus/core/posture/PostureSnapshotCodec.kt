package com.vibesync.antivirus.core.posture

import org.json.JSONArray
import org.json.JSONObject

internal object PostureSnapshotCodec {
    private const val MAX_ENTRIES = 10_000
    fun encode(snapshot: PostureSnapshot): ByteArray {
        val root = JSONObject().put("schema", 1).put("last_complete_check_at", snapshot.lastCompleteCheckAt)
        root.put("initialized", JSONArray(snapshot.initialized.map { it.name }))
        root.put("grants", JSONArray(snapshot.grants.map { grant(it) }))
        root.put("pending", JSONArray(snapshot.pending.map { grant(it.capability).put("observed_at", it.observedAt) }))
        return root.toString().toByteArray(Charsets.UTF_8)
    }
    fun decode(bytes: ByteArray): PostureSnapshot {
        val root = JSONObject(String(bytes, Charsets.UTF_8))
        require(root.getInt("schema") == 1) { "Unsupported encrypted posture schema" }
        val initialized = root.getJSONArray("initialized").let { array ->
            require(array.length() <= PostureSnapshotComparison.monitored.size)
            (0 until array.length()).map { PostureAccess.valueOf(array.getString(it)) }.toSet()
        }
        require(PostureSnapshotComparison.monitored.containsAll(initialized))
        fun entries(key: String): List<JSONObject> = root.getJSONArray(key).let { array ->
            require(array.length() <= MAX_ENTRIES) { "Posture snapshot is too large" }
            (0 until array.length()).map(array::getJSONObject)
        }
        val grants = entries("grants").map(::readGrant).toSet()
        val pending = entries("pending").map { item ->
            val observedAt = item.getLong("observed_at")
            require(observedAt > 0)
            PostureChange(readGrant(item), observedAt)
        }.toSet()
        require(grants.all { it.access in initialized } && pending.all { it.capability in grants })
        require(pending.map { it.capability }.distinct().size == pending.size)
        return PostureSnapshot(initialized, grants, pending, root.getLong("last_complete_check_at").also { require(it >= 0) })
    }
    private fun grant(value: PostureCapability) = JSONObject().put("access", value.access.name).put("package", value.packageName)
    private fun readGrant(item: JSONObject): PostureCapability {
        val access = PostureAccess.valueOf(item.getString("access"))
        val name = item.getString("package")
        require(access in PostureSnapshotComparison.monitored)
        require(name.length in 1..255 && name.matches(Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*")))
        return PostureCapability(access, name)
    }
}
