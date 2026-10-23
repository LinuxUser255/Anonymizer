package com.anonymizer.burp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext
import com.anonymizer.ui.AnonymizerTab
import com.anonymizer.ui.ServiceInfo
import java.awt.Component
import javax.swing.JMenuItem
import javax.swing.SwingUtilities

/**
 * "Send to Anonymizer" on any request or response (Proxy, Repeater, Site map, Logger, Intruder…)
 * and "Add selection as client term" when text is selected in a message editor.
 */
public class ContextMenu(private val api: MontoyaApi, private val tab: AnonymizerTab) : ContextMenuItemsProvider {
    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val items = ArrayList<Component>()
        val editor = event.messageEditorRequestResponse()
        if (editor != null && editor.isPresent) {
            val e = editor.get()
            items.add(JMenuItem("Send to Anonymizer").apply { addActionListener { addFromEditor(e) } })
            val sel = e.selectionOffsets()
            if (sel != null && sel.isPresent) {
                items.add(JMenuItem("Add selection as client term").apply { addActionListener { addTermFromEditor(e) } })
            }
            return items
        }
        val selected = event.selectedRequestResponses()
        if (selected != null && selected.isNotEmpty()) {
            val label = if (selected.size == 1) "Send to Anonymizer" else "Send ${selected.size} items to Anonymizer"
            items.add(JMenuItem(label).apply {
                addActionListener { for (rr in selected) addRequestResponse(rr, bothSides = true) }
            })
        }
        return items
    }

    private fun addFromEditor(e: MessageEditorHttpRequestResponse) {
        val rr = e.requestResponse() ?: return
        val context = e.selectionContext()
        if (context == SelectionContext.RESPONSE) addResponse(rr) else addRequest(rr)
    }

    private fun addRequestResponse(rr: HttpRequestResponse, bothSides: Boolean) {
        addRequest(rr)
        if (bothSides) addResponse(rr)
    }

    private fun addRequest(rr: HttpRequestResponse) {
        val req = rr.request() ?: return
        val bytes = req.toByteArray()?.bytes ?: return
        // method()/path() throw MalformedRequestException on a half-edited request; the item is still useful.
        val title = runCatching { "${req.method()} ${req.path()}" }.getOrDefault("request")
        val service = req.httpService()?.let { ServiceInfo(it.host(), it.port(), it.secure()) }
        onEdt { tab.addItem(title, decodeCapped(bytes), service, isRequest = true) }
    }

    private fun addResponse(rr: HttpRequestResponse) {
        val res = rr.response() ?: return
        val req = rr.request()
        val bytes = res.toByteArray()?.bytes ?: return
        val reqLine = runCatching { "${req?.method() ?: ""} ${req?.path() ?: ""}" }.getOrDefault("")
        val title = "${res.statusCode()} ← $reqLine".trim()
        val service = req?.httpService()?.let { ServiceInfo(it.host(), it.port(), it.secure()) }
        onEdt { tab.addItem(title, decodeCapped(bytes), service, isRequest = false) }
    }

    /**
     * Menu actions run on the EDT, so a message over the engine's body cap is cut before it is
     * decoded or held by the tab (BApp criterion 5). The engine's own cap then reports the cut.
     */
    private fun decodeCapped(bytes: ByteArray): String {
        if (bytes.size <= EngineService.BODY_CAP) return String(bytes, Charsets.UTF_8)
        val head = String(bytes, 0, EngineService.BODY_CAP, Charsets.UTF_8)
        return head + "\n[truncated: ${bytes.size - EngineService.BODY_CAP} bytes beyond the ${EngineService.BODY_CAP / 1_000_000} MB cap]"
    }

    private fun addTermFromEditor(e: MessageEditorHttpRequestResponse) {
        val range = e.selectionOffsets()?.orElse(null) ?: return
        val rr = e.requestResponse() ?: return
        val bytes = when (e.selectionContext()) {
            SelectionContext.RESPONSE -> rr.response()?.toByteArray()?.bytes
            else -> rr.request()?.toByteArray()?.bytes
        } ?: return
        val start = range.startIndexInclusive().coerceIn(0, bytes.size)
        val end = range.endIndexExclusive().coerceIn(start, bytes.size)
        if (end <= start) return
        val term = String(bytes.copyOfRange(start, end), Charsets.UTF_8).trim()
        if (term.isEmpty()) return
        onEdt { tab.addTerm(term) }
    }

    private fun onEdt(block: () -> Unit) {
        if (SwingUtilities.isEventDispatchThread()) block() else SwingUtilities.invokeLater(block)
    }
}
