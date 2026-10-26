package com.vibesync.antivirus.core.observer

import org.junit.Assert.*
import org.junit.Test

class IncidentSirenControllerTest {
    private class Harness {
        var playing = false
        var starts = 0
        var released = 0
        val scheduled = linkedMapOf<Runnable, Long>()
        val controller = IncidentSirenController(
            stopPlayback = { if (playing) { released++; playing = false } },
            schedule = { task, delay -> scheduled[task] = delay },
            cancel = { scheduled.remove(it) }
        )
        fun start() = controller.start { playing = true; starts++ }
    }

    @Test fun alarmStopsAndReleasesAtFiveSeconds() {
        val h = Harness()
        h.start()
        assertTrue(h.playing)
        assertEquals(5_000L, h.scheduled.values.single())
        h.scheduled.keys.single().run()
        assertFalse(h.playing)
        assertEquals(1, h.released)
        assertTrue(h.scheduled.isEmpty())
    }

    @Test fun dismissalOrAppResumeCancelsTheStopTimerImmediately() {
        val h = Harness()
        h.start()
        val oldTimer = h.scheduled.keys.single()
        h.controller.stop()
        assertFalse(h.playing)
        assertTrue(h.scheduled.isEmpty())
        oldTimer.run()
        assertEquals(1, h.released)
    }

    @Test fun aRepeatedIncidentAlwaysGetsANewAlarmAndOldTimerCannotStopIt() {
        val h = Harness()
        h.start()
        val first = h.scheduled.keys.single()
        h.controller.stop() // Previous incident dismissed.
        h.start()
        val second = h.scheduled.keys.single()
        assertNotSame(first, second)
        assertEquals(2, h.starts)
        first.run()
        assertTrue(h.playing)
        second.run()
        assertFalse(h.playing)
        assertEquals(2, h.released)
    }

    @Test fun playbackFailureStillReleasesResourcesAndLeavesNoTimer() {
        val h = Harness()
        try {
            h.controller.start { h.playing = true; throw SecurityException("Audio unavailable") }
            fail("Expected playback failure")
        } catch (_: SecurityException) { }
        assertFalse(h.playing)
        assertTrue(h.scheduled.isEmpty())
        assertEquals(1, h.released)
    }
}
