package com.vibesync.antivirus.core.engine
import java.io.File
import java.util.Locale
import java.util.zip.ZipFile
/** Bounded DEX string triage; not a full YARA engine and not proof of malicious execution. */
class DexPatternScanner(private val maxBytesPerDex: Long = 24L*1024L*1024L, private val maxBytesPerApk: Long = 48L*1024L*1024L) {
 fun scan(apk: File): List<String> {
  if (!apk.isFile || !apk.canRead()) return emptyList()
  val found = linkedSetOf<String>(); var total = 0L
  return try {
   ZipFile(apk).use { zip ->
    val entries = zip.entries()
    while (entries.hasMoreElements() && total < maxBytesPerApk && found.size < PATTERNS.size) {
     val entry = entries.nextElement()
     if (!DEX_ENTRY.matches(entry.name)) continue
     var perDex = 0L; var tail = ""
     zip.getInputStream(entry).buffered().use { input ->
      val buffer = ByteArray(8192)
      while (true) {
       val count = input.read(buffer); if (count < 0) break; if (count == 0) continue
       perDex += count.toLong(); total += count.toLong()
       if (perDex > maxBytesPerDex || total > maxBytesPerApk) break
       val chunk = tail + String(buffer,0,count,Charsets.ISO_8859_1).lowercase(Locale.ROOT)
       PATTERNS.forEach { if (chunk.contains(it.first)) found += it.second }
       tail = chunk.takeLast(39)
      }
     }
    }
   }
   found.toList()
  } catch (_: Exception) { emptyList() }
 }
 companion object {
  private val DEX_ENTRY = Regex("classes([0-9]*)\\.dex")
  private val PATTERNS = listOf("getdeviceid" to "TelephonyManager.getDeviceId string","getsubscriberid" to "TelephonyManager.getSubscriberId string","dexclassloader" to "DexClassLoader string","runtime.exec" to "Runtime.exec string","xposedbridge" to "Xposed framework string","accessibilityservice" to "AccessibilityService string")
 }
}
