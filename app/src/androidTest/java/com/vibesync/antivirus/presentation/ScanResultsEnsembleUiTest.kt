package com.vibesync.antivirus.presentation

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Rule
import org.junit.Test

class ScanResultsEnsembleUiTest {
    @get:Rule
    val composeRule = createComposeRule()

    private fun flaggedEnsembleResult() = ScanResult(
        packageOrPath = "samples/ensemble-threat.apk",
        displayName = "Ensemble sample",
        sha256 = null,
        md5 = null,
        verdict = ScanVerdict.THREAT,
        reasons = listOf("Combined YARA and ML signal"),
        durationMs = 12L,
        detectionSource = DetectionSource.ENSEMBLE,
        confidence = 0.85f
    )

    private fun renderAndAssert(theme: AppTheme) {
        composeRule.setContent {
            SafeMobileTheme(theme = theme) {
                ScanResultsScreen(
                    results = listOf(flaggedEnsembleResult()),
                    onUninstall = {},
                    onAppInfo = {},
                    onQuarantine = {},
                    onTrust = {},
                    onRemoveTrust = {}
                )
            }
        }
        composeRule.onNodeWithText("Detected by: ENSEMBLE (85%)").assertIsDisplayed()
    }

    @Test
    fun ensembleSourceAndConfidenceRenderInLightTheme() {
        renderAndAssert(AppTheme.LIGHT)
    }

    @Test
    fun ensembleSourceAndConfidenceRenderInMidnightTheme() {
        renderAndAssert(AppTheme.MIDNIGHT)
    }

    @Test
    fun ensembleSourceAndConfidenceRenderInOledTheme() {
        renderAndAssert(AppTheme.OLED)
    }
}
