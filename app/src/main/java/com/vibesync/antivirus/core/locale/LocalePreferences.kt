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
        Choice("ja", R.string.locale_japanese)
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
