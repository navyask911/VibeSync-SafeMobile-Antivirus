package com.vibesync.antivirus.presentation
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class UninstallHandlerInstrumentedTest{
 @Test fun deleteIntentUsesPackageUriAndNewTask(){val i=UninstallHandler.buildDeleteIntent("com.example.userapp");assertEquals(Intent.ACTION_DELETE,i.action);assertEquals(Uri.parse("package:com.example.userapp"),i.data);assertTrue(i.flags and Intent.FLAG_ACTIVITY_NEW_TASK!=0)}
 @Test fun actionDeleteFallbackOpensAppInfo(){var info:Intent?=null;val r=UninstallHandler.launchWithFallback("com.example.userapp",{throw ActivityNotFoundException("OEM test")},{info=it});assertEquals(UninstallResult.OpenedAppInfo,r);assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,info?.action);assertEquals(Uri.parse("package:com.example.userapp"),info?.data)}
}
