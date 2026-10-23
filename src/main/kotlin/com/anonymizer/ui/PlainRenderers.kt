package com.anonymizer.ui

import javax.swing.DefaultListCellRenderer
import javax.swing.ListCellRenderer
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableCellRenderer

/**
 * Swing's default list and table renderers are `JLabel`s, and a `JLabel` renders any text that
 * starts with `<html>` as HTML, including `<img src="http://…">`, which would make Burp fetch a
 * URL chosen by the site under test. Everything the tab shows in a label comes from HTTP traffic
 * (BApp criterion 3: treat message content as untrusted), so these renderers switch HTML off.
 */
public object PlainRenderers {
    private const val HTML_DISABLE = "html.disable"

    public fun list(): ListCellRenderer<Any> = DefaultListCellRenderer().apply { putClientProperty(HTML_DISABLE, true) }

    public fun table(): TableCellRenderer = DefaultTableCellRenderer().apply { putClientProperty(HTML_DISABLE, true) }
}
