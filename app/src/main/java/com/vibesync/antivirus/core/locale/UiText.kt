package com.vibesync.antivirus.core.locale

import android.content.Context
import java.text.NumberFormat

data class UiNumber(val value: Number)

/** Resolve at the display boundary, so retained ViewModel data follows a new app locale. */
data class UiText(val resource: Int, val arguments: List<Any> = emptyList(), val quantity: Int? = null) {
    fun resolve(context: Context): String {
        val values = arguments.map { when (it) {
            is UiText -> it.resolve(context)
            is UiNumber -> NumberFormat.getIntegerInstance(context.resources.configuration.locales[0]).format(it.value)
            else -> it
        } }.toTypedArray()
        return if (quantity == null) context.getString(resource, *values)
        else context.resources.getQuantityString(resource, quantity, *values)
    }
}
