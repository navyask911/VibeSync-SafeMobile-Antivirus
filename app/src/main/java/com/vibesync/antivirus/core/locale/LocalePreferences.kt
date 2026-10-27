package com.vibesync.antivirus.core.locale

import android.content.Context
import android.content.res.Configuration
import com.vibesync.antivirus.R
import java.util.Locale

/**
 * App-level locale override for the languages whose resources are currently shipped.
 * An empty override respects the Android system/app language.
 */
object LocalePreferences {
    const val PREFS_NAME = "safe_mobile_language"
    const val OVERRIDE_KEY = "locale_override"

    data class Choice(val tag: String, val labelResource: Int)

    val choices = listOf(
        Choice("en", R.string.locale_english),
        Choice("ar", R.string.locale_arabic),
        Choice("de", R.string.locale_german),
        Choice("es", R.string.locale_spanish),
        Choice("fr", R.string.locale_french),
        Choice("hi", R.string.locale_hindi),
        Choice("ja", R.string.locale_japanese),
        Choice("pt", R.string.locale_portuguese),
        Choice("ru", R.string.locale_russian),
        Choice("zh-CN", R.string.locale_chinese),
        Choice("ko", R.string.locale_korean),
        Choice("tr", R.string.locale_turkish),
        Choice("id", R.string.locale_indonesian),
        Choice("vi", R.string.locale_vietnamese),
        Choice("it", R.string.locale_italian),
        Choice("kn", R.string.locale_kannada),
        Choice("ta", R.string.locale_tamil),
        Choice("te", R.string.locale_telugu),
        Choice("bn", R.string.locale_bengali),
        Choice("mr", R.string.locale_marathi),
        Choice("ur", R.string.locale_urdu),
        Choice("he", R.string.locale_hebrew),
        Choice("af", R.string.locale_af),
        Choice("az", R.string.locale_az),
        Choice("bg", R.string.locale_bg),
        Choice("ca", R.string.locale_ca),
        Choice("cs", R.string.locale_cs),
        Choice("da", R.string.locale_da),
        Choice("el", R.string.locale_el),
        Choice("et", R.string.locale_et),
        Choice("fa", R.string.locale_fa),
        Choice("fi", R.string.locale_fi),
        Choice("fil", R.string.locale_fil),
        Choice("gu", R.string.locale_gu),
        Choice("hr", R.string.locale_hr),
        Choice("hu", R.string.locale_hu),
        Choice("ka", R.string.locale_ka),
        Choice("kk", R.string.locale_kk),
        Choice("lt", R.string.locale_lt),
        Choice("lv", R.string.locale_lv),
        Choice("ml", R.string.locale_ml),
        Choice("ms", R.string.locale_ms),
        Choice("ne", R.string.locale_ne),
        Choice("nl", R.string.locale_nl),
        Choice("nb", R.string.locale_nb),
        Choice("pa", R.string.locale_pa),
        Choice("pl", R.string.locale_pl),
        Choice("ro", R.string.locale_ro),
        Choice("sk", R.string.locale_sk),
        Choice("sv", R.string.locale_sv),
        Choice("th", R.string.locale_th),
        Choice("uk", R.string.locale_uk)
    )

    fun overrideTag(context: Context): String =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(OVERRIDE_KEY, "")
            .orEmpty()

    fun saveOverride(context: Context, tag: String) {
        require(tag.isEmpty() || choices.any { it.tag == tag }) {
            "Unsupported in-app locale override."
        }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(OVERRIDE_KEY, tag)
            .apply()
    }

    fun labelResource(tag: String): Int =
        choices.firstOrNull { it.tag == tag }?.labelResource ?: R.string.language_system_default

    fun wrap(base: Context): Context {
        val tag = overrideTag(base)
        if (tag.isBlank()) return base
        val locale = Locale.forLanguageTag(tag)
        if (locale.language.isBlank()) return base
        val configuration = Configuration(base.resources.configuration).apply {
            setLocale(locale)
            setLayoutDirection(locale)
        }
        return base.createConfigurationContext(configuration)
    }
}
