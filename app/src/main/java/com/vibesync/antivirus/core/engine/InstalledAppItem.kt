package com.vibesync.antivirus.core.engine

/** Lightweight installed app inventory separate from potentially slow deep APK scanning. */
data class InstalledAppItem(val packageName: String, val displayName: String)
