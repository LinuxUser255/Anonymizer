package com.anonymizer.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class MarkdownTest {
    @Test
    fun `bundle fences each item and normalises line endings`() {
        val a = Item(1, "POST /login", "x", null, true)
        val b = Item(2, "200 ← POST /login", "y", null, false)
        val md = Markdown.bundle(listOf(a to "POST /login HTTP/1.1\r\nHost: target1.example\r\n\r\n", b to "HTTP/1.1 200 OK\n\n{}"))
        assertEquals(
            "### #1 POST /login\n\n```http\nPOST /login HTTP/1.1\nHost: target1.example\n```\n\n" +
                "### #2 200 ← POST /login\n\n```http\nHTTP/1.1 200 OK\n\n{}\n```\n",
            md,
        )
    }

    @Test
    fun `a body containing a fence gets a longer fence`() {
        val md = Markdown.bundle(listOf(Item(1, "GET /", "x", null, true) to "```\n"))
        assertEquals("### #1 GET /\n\n````http\n```\n````\n", md)
    }
}
