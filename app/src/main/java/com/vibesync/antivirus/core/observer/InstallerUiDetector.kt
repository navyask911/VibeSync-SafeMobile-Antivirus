package com.vibesync.antivirus.core.observer
import java.io.File
import java.util.Locale
object InstallerUiDetector {
 private val apkToken=Regex("""(?i)[^\s"'<>]*\.apk(?:$|[\s"'<>),;:])""")
 private val nonApk=Regex("""(?i)[^\s"'<>]*\.(?:exe|msi|bat|cmd|sh)(?:$|[\s"'<>),;:])""")
 private val installers=setOf("com.android.packageinstaller","com.google.android.packageinstaller","com.samsung.android.packageinstaller","com.sec.android.packageinstaller","com.miui.packageinstaller","com.miui.global.packageinstaller","com.oneplus.packageinstaller","com.oplus.packageinstaller","com.coloros.packageinstaller","com.vivo.packageinstaller","com.hihonor.packageinstaller","com.transsion.packageinstaller")
 fun isInstallerPackage(pkg:String?):Boolean { val p=pkg?.trim()?.lowercase(Locale.ROOT).orEmpty();return p.isNotBlank()&&(p in installers||(p.contains("packageinstaller")&&p.matches(Regex("^[a-z0-9_.]+$")))) }
 fun containsApkFilename(value:CharSequence?):Boolean=!value.isNullOrEmpty()&&apkToken.containsMatchIn(value)
 fun extractApkFilename(value:CharSequence?):String? { if(value.isNullOrEmpty())return null;val m=apkToken.find(value)?:return null;val n=File(m.value.trimEnd(',', ';', ':', ')', ']', '}')).name.take(120);return n.takeIf{it.endsWith(".apk",true)} }
 fun isCancelControl(value:CharSequence?,viewId:String?=null):Boolean { val t=norm(value?.toString().orEmpty());val id=norm(viewId.orEmpty());if(id.contains("cancel_button")||id.contains("negative_button")||id.endsWith(":id/cancel")||id.endsWith("/cancel"))return true;return t in setOf("cancel","cancelar","annuler","abbrechen","отмена","не устанавливать","dont install","not now","取消","キャンセル","취소","रद्द करें","ರದ್ದು") }
 fun isApkInstallUi(values:Iterable<String>):Boolean { val v=values.filter{it.isNotBlank()};if(v.any{nonApk.containsMatchIn(it)&&!apkToken.containsMatchIn(it)})return false;if(v.any{containsApkFilename(it)})return true;val joined=norm(v.joinToString(" "));return joined.contains(".apk")&&(joined.contains("install")||joined.contains("установ")||joined.contains("インストール")||joined.contains("安装")) }
 private fun norm(s:String)=s.lowercase(Locale.ROOT).replace('’','\'').replace(Regex("\\s+")," ").trim()
}
