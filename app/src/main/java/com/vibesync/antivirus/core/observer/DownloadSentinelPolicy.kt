package com.vibesync.antivirus.core.observer
import com.vibesync.antivirus.core.engine.ScanVerdict
object DownloadSentinelPolicy {
 fun isConfirmedMalicious(verdict:ScanVerdict)=verdict==ScanVerdict.THREAT
 fun shouldQuarantine(verdict:ScanVerdict,strictMode:Boolean)=isConfirmedMalicious(verdict)||strictMode
}
