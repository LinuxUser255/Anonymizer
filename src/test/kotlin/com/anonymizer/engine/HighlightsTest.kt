package com.anonymizer.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HighlightsTest {
    @Test
    fun `placeholders are located exactly, longest first`() {
        val m = Mapping()
        val a = Anonymizer(Settings.FIXTURE_DEFAULTS, m)
        val out = a.anonymize("GET / HTTP/1.1\nHost: api.corp.io\nCookie: sid=abc123def\n\n")
        val spans = Highlights.placeholders(out, m.snapshot())
        val tokens = spans.map { out.substring(it.start, it.end) }
        assertEquals(listOf("target1.example", "[COOKIE_1]"), tokens)
        assertTrue(spans.all { it.kind == Highlights.Kind.PLACEHOLDER })
    }

    @Test
    fun `warnings flag what a disabled detector would have caught`() {
        val s = Settings.FIXTURE_DEFAULTS.copy(detect = Settings.FIXTURE_DEFAULTS.detect +mapOf("blob" to false, "phone" to false))
        val m = Mapping()
        val out = Anonymizer(s, m).anonymize("token a9F3kLm2Qx8ZpR7tWv1BnY4c call +1 555-123-4567")
        val w = Highlights.warnings(out, s, m.snapshot())
        assertEquals(listOf("a9F3kLm2Qx8ZpR7tWv1BnY4c", "+1 555-123-4567"), w.map { out.substring(it.start, it.end) })
        assertTrue(Highlights.warnings(out, Settings.FIXTURE_DEFAULTS,m.snapshot()).isEmpty())
    }
}
