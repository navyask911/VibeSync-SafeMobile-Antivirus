rule Takopii_Overlay_Banker_DEX {
 meta:
  description = "Accessibility, notification and overlay banker capability combination (advisory)"
  severity = "high"
  mitre = "T1626"
 strings:
  $a11y = "AccessibilityService" ascii
  $a11y_event = "onAccessibilityEvent" ascii
  $nls = "NotificationListenerService" ascii
  $overlay = "WindowManager" ascii
  $sms = "SMS_RECEIVED" ascii
 condition:
  $a11y and $a11y_event and $overlay and ($nls or $sms)
}

rule Takopii_DCL_AntiForensics_DEX {
 meta:
  description = "Dynamic DEX loader with reflection and cleanup markers (advisory)"
  severity = "high"
  mitre = "T1407"
 strings:
  $dcl = "DexClassLoader" ascii
  $method = "getDeclaredMethod" ascii
  $classforname = "Class.forName" ascii
  $cache1 = ".cache_data" ascii
  $cache2 = ".update_cache" ascii
 condition:
  $dcl and ($method or $classforname) and ($cache1 or $cache2)
}

rule Takopii_RAT_Composite_DEX {
 meta:
  description = "Multiple remote-access capabilities in one DEX (generic heuristic)"
  severity = "medium"
  mitre = "T1512"
 strings:
  $camera = "CameraDevice" ascii
  $audio = "AudioRecord" ascii
  $screen = "VirtualDisplay" ascii
  $shell = "getRuntime" ascii
  $keylog = "AccessibilityEvent" ascii
 condition:
  $camera and $audio and ($screen or $shell) and $keylog
}

rule Takopii_TOTP_Scraping_DEX {
 meta:
  description = "Authenticator targeting plus TOTP extraction markers (advisory)"
  severity = "high"
  mitre = "T1517"
 strings:
  $google_auth = "com.google.android.apps.authenticator2" ascii
  $ms_auth = "com.azure.authenticator" ascii
  $authy = "com.authy.authy" ascii
  $a11y = "AccessibilityService" ascii
 condition:
  ($google_auth or $ms_auth or $authy) and $a11y
}

rule Takopii_Dropper_Config_DEX {
 meta:
  description = "Config-then-download dropper indicators (generic heuristic)"
  severity = "medium"
  mitre = "T1437"
 strings:
  $check = "/api/v1/check" ascii
  $config = "config_url" ascii
  $connection = "HttpURLConnection" ascii
  $fetch = "fetchBytes" ascii
  $write = "writeBytes" ascii
 condition:
  ($check or $config) and $connection and ($fetch or $write)
}
