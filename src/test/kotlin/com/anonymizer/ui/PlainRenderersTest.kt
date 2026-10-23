package com.anonymizer.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import javax.swing.JComponent
import javax.swing.JList
import javax.swing.JTable
import javax.swing.plaf.basic.BasicHTML

/**
 * A value lifted from HTTP traffic must never be rendered as HTML. `BasicHTML` stores its view
 * under the client property named by [BasicHTML.propertyKey] when it decides to render HTML, so
 * its absence after rendering `<html>…` is the assertion. The mutant (a stock renderer) fails it.
 */
class PlainRenderersTest {
    private val hostile = "<html><img src=\"http://attacker.example/x\"><b>bold</b>"

    @Test
    fun listRendererDoesNotInterpretHtml() {
        val c = PlainRenderers.list().getListCellRendererComponent(JList<Any>(), hostile, 0, false, false) as JComponent
        assertNull(c.getClientProperty(BasicHTML.propertyKey), "list renderer created an HTML view")
    }

    @Test
    fun tableRendererDoesNotInterpretHtml() {
        val c = PlainRenderers.table().getTableCellRendererComponent(JTable(), hostile, false, false, 0, 0) as JComponent
        assertNull(c.getClientProperty(BasicHTML.propertyKey), "table renderer created an HTML view")
    }

    @Test
    fun stockRendererWouldHaveInterpretedIt() {
        // Documents why the helpers exist: the default renderer does build an HTML view.
        val c = javax.swing.DefaultListCellRenderer().getListCellRendererComponent(JList<Any>(), hostile, 0, false, false) as JComponent
        assertEquals(true, c.getClientProperty(BasicHTML.propertyKey) != null)
    }
}
