package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets

class YaraScannerTest {
    private fun validDex(vararg strings: String): ByteArray =
        "dex\n035\u0000".toByteArray(StandardCharsets.ISO_8859_1) +
            strings.joinToString("::").toByteArray(StandardCharsets.US_ASCII)

    private fun bundle(): YaraScanner {
        val paths = listOf(
            File("src/main/assets/yara/safemobile_android_dex.yar"),
            File("app/src/main/assets/yara/safemobile_android_dex.yar")
        )
        val source = paths.firstOrNull { it.isFile } ?: error("Missing checked-in DEX rule asset.")
        return YaraScanner.fromRules(source.readText(Charsets.UTF_8))
    }

    @Test fun checkedInMitPackLoadsAndHasFiveBoundedRules() {
        assertEquals(5, bundle().ruleCount)
    }

    @Test fun matchingBankerPatternReportsRuleAndAuthoredEvidence() {
        val result = bundle().scanDex(validDex(
            "AccessibilityService", "onAccessibilityEvent", "WindowManager", "SMS_RECEIVED"
        ))
        assertEquals(YaraScanState.MATCHES, result.state)
        val hit = result.matches.first { it.ruleName == "Takopii_Overlay_Banker_DEX" }
        assertEquals(RiskSeverity.HIGH, hit.severity)
        assertEquals("T1626", hit.mitreTechnique)
        assertTrue(hit.matchedPatterns.any { it.contains("AccessibilityService") })
    }

    @Test fun oneCommonMarkerDoesNotTriggerCompositeHeuristics() {
        val result = bundle().scanDex(validDex("AccessibilityService", "WindowManager"))
        assertEquals(YaraScanState.NO_MATCH, result.state)
        assertTrue(result.matchedRules.isEmpty())
    }

    @Test fun invalidDexDoesNotClaimCleanScan() {
        assertEquals(YaraScanState.NOT_SCANNED, bundle().scanDex("not a dex".toByteArray()).state)
    }

    @Test fun unsupportedRegexMustRejectEntirePack() {
        val sample = "rule Reject {\n meta:\n description = \"reject\"\n severity = \"high\"" +
            "\n strings:\n" + '$' + "a = /regex/ ascii\n condition:\n" + '$' + "a\n}\n"
        assertTrue(runCatching { YaraScanner.fromRules(sample) }.isFailure)
    }

    @Test fun undefinedConditionIdentifierMustRejectEntirePack() {
        val sample = "rule Reject {\n meta:\n description = \"reject\"\n severity = \"medium\"" +
            "\n strings:\n" + '$' + "a = \"some-pattern\" ascii\n condition:\n" +
            '$' + "other\n}\n"
        assertTrue(runCatching { YaraScanner.fromRules(sample) }.isFailure)
    }

    @Test fun oversizedRulePackFailsClosed() {
        assertTrue(runCatching { YaraScanner.fromRules("a".repeat(YaraScanner.MAX_RULE_BYTES + 1)) }.isFailure)
    }

    @Test fun readableFileWithoutActiveRulesReportsDisabledRatherThanNoMatch() {
        val file = File.createTempFile("yara-disabled", ".dex")
        try {
            file.writeBytes(validDex("something"))
            val result = YaraScanner().scan(file)
            assertEquals(YaraScanState.DISABLED, result.state)
            assertFalse(result.reason.isNullOrBlank())
        } finally { file.delete() }
    }

    @Test fun absentFileIsNotScanned() {
        assertEquals(YaraScanState.NOT_SCANNED,
            YaraScanner().scan(File("/this/path/does/not/exist/sample.dex")).state)
    }
}
