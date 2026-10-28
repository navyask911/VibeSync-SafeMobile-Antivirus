package com.vibesync.antivirus.presentation

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

@Composable
internal fun localizedNumber(value: Number): String =
    NumberFormat.getIntegerInstance(LocalConfiguration.current.locales[0]).format(value)

@Composable
internal fun localizedDate(timestamp: Long, timeOnly: Boolean = false): String {
    val locale = LocalConfiguration.current.locales[0]
    val format = if (timeOnly) DateFormat.getTimeInstance(DateFormat.SHORT, locale)
        else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, locale)
    return format.format(Date(timestamp))
}
