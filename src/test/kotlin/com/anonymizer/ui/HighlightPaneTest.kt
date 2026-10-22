package com.anonymizer.ui

import com.anonymizer.engine.Highlights
import com.anonymizer.engine.Restorer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.awt.Color
import javax.swing.text.StyleConstants

/** Engine spans index the raw text; the Swing document stores CRLF as LF. */
class HighlightPaneTest {
    private fun bg(pane: HighlightPane, docOffset: Int): Color? =
        StyleConstants.getBackground(pane.styledDocument.getCharacterElement(docOffset).attributes)
            .takeIf { it.alpha > 0 }

    @Test
    fun anonymizeSpansLandOnTheSameCharactersAfterCrlf() {
        val text = "GET / HTTP/1.1\r\nCookie: a=b\r\nX: [COOKIE_1]\r\n"
        val pane = HighlightPane(editable = false)
        pane.setContent(text)
        val start = text.indexOf("[COOKIE_1]")
        pane.showAnonymizeSpans(listOf(Highlights.Span(start, start + 10, Highlights.Kind.PLACEHOLDER, "")))
        val doc = pane.styledDocument.getText(0, pane.styledDocument.length)
        val docStart = doc.indexOf("[COOKIE_1]")
        assertEquals(null, bg(pane, docStart - 1), "char before the placeholder")
        assertEquals(HighlightPane.PLACEHOLDER, bg(pane, docStart))
        assertEquals(HighlightPane.PLACEHOLDER, bg(pane, docStart + 9))
        assertEquals(null, bg(pane, docStart + 10), "char after the placeholder")
    }

    @Test
    fun restoreSpansOnLfTextAreUnchanged() {
        val text = "a\nb\n[X_9]\n"
        val pane = HighlightPane(editable = true)
        pane.setContent(text)
        val start = text.indexOf("[X_9]")
        pane.showRestoreSpans(listOf(Restorer.Span(start, start + 5, Restorer.Kind.UNKNOWN, "[X_9]", 3)))
        assertEquals(null, bg(pane, start - 1))
        assertEquals(HighlightPane.UNKNOWN, bg(pane, start))
        assertEquals(HighlightPane.UNKNOWN, bg(pane, start + 4))
    }
}
