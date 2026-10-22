package com.anonymizer.ui

import com.anonymizer.engine.Highlights
import com.anonymizer.engine.Restorer
import java.awt.Color
import java.awt.Font
import javax.swing.JTextPane
import javax.swing.text.DefaultStyledDocument
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants

/** A monospace text pane with background highlights; colours are translucent so themes stay readable. */
public class HighlightPane(editable: Boolean) : JTextPane() {
    private val doc = DefaultStyledDocument()

    /**
     * Ascending indices, in the last [setContent] text, of each `\r` the editor kit dropped: it
     * stores CRLF as LF, so engine offsets past one are one too far into the document.
     */
    private var droppedCr: IntArray = IntArray(0)

    init {
        styledDocument = doc
        isEditable = editable
        font = Font(Font.MONOSPACED, Font.PLAIN, 12)
    }

    /** Replaces the content and clears all highlights. */
    public fun setContent(text: String) {
        var n = 0
        val crs = IntArray(text.length)
        for (i in 0 until text.length - 1) if (text[i] == '\r' && text[i + 1] == '\n') crs[n++] = i
        droppedCr = crs.copyOf(n)
        this.text = text
        clearHighlights()
        caretPosition = 0
    }

    /** Maps an offset in the [setContent] text to the document offset of the same character. */
    private fun toDoc(offset: Int): Int {
        var lo = 0
        var hi = droppedCr.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (droppedCr[mid] < offset) lo = mid + 1 else hi = mid
        }
        return offset - lo
    }

    public fun clearHighlights() {
        val plain = SimpleAttributeSet()
        StyleConstants.setBackground(plain, Color(0, 0, 0, 0))
        doc.setCharacterAttributes(0, doc.length, plain, true)
    }

    public fun highlight(start: Int, end: Int, color: Color) {
        if (start < 0 || end <= start || start >= doc.length) return
        val attr = SimpleAttributeSet()
        StyleConstants.setBackground(attr, color)
        doc.setCharacterAttributes(start, minOf(end, doc.length) - start, attr, false)
    }

    public fun showAnonymizeSpans(spans: List<Highlights.Span>) {
        clearHighlights()
        for (s in spans) {
            highlight(toDoc(s.start), toDoc(s.end), if (s.kind == Highlights.Kind.PLACEHOLDER) PLACEHOLDER else WARNING)
        }
    }

    public fun showRestoreSpans(spans: List<Restorer.Span>) {
        clearHighlights()
        for (s in spans) {
            highlight(
                toDoc(s.start),
                toDoc(s.end),
                when (s.kind) {
                    Restorer.Kind.LENIENT -> LENIENT
                    Restorer.Kind.UNKNOWN -> UNKNOWN
                    Restorer.Kind.MODIFIED_JWT -> UNKNOWN
                },
            )
        }
    }

    public companion object {
        public val PLACEHOLDER: Color = Color(80, 150, 255, 90)
        public val WARNING: Color = Color(255, 210, 0, 110)
        public val LENIENT: Color = Color(255, 150, 0, 120)
        public val UNKNOWN: Color = Color(255, 70, 70, 120)
    }
}
