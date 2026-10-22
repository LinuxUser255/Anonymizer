package com.anonymizer.ui

import com.anonymizer.engine.AnonymizeResult
import com.anonymizer.engine.MappingSnapshot
import com.anonymizer.engine.Restorer
import com.anonymizer.engine.Settings
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.table.DefaultTableModel

/**
 * The Anonymizer suite tab (docs/PLAN.md, "UI sketch"). Pure Swing; talks to the extension only
 * through [TabHost]. Everything here runs on the EDT; engine work is asynchronous and re-renders
 * are coalesced through a short [Timer].
 */
public class AnonymizerTab(private val host: TabHost) : JPanel(BorderLayout()) {
    private val itemsModel = DefaultListModel<Item>()
    private val itemList = JList(itemsModel)
    private val originalPane = HighlightPane(editable = false)
    private val anonymizedPane = HighlightPane(editable = false)
    private val summaryLabel = JLabel(" ")
    private val toggles = LinkedHashMap<String, JCheckBox>()
    private val privateIpsBox = JCheckBox("Private IPs")
    private val termsField = JTextField()
    private val restorePane = HighlightPane(editable = true)
    private val lenientBox = JCheckBox("Lenient")
    private val restoreStatus = JLabel(" ")
    private val mappingLabel = JLabel("Mapping: 0 entries")
    private var nextId = 1
    private var settingsVersion = 0
    private var loadingSettings = false
    private var shown: Item? = null
    private val rerenderTimer = Timer(150) { renderSelected(force = true) }.apply { isRepeats = false }

    init {
        add(buildItemsBar(), BorderLayout.NORTH)
        val top = JPanel(BorderLayout()).apply {
            add(buildPanes(), BorderLayout.CENTER)
            add(buildToggles(), BorderLayout.SOUTH)
        }
        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top, buildRestore()).apply {
            resizeWeight = 0.65
            isOneTouchExpandable = true
        }
        add(split, BorderLayout.CENTER)
        add(buildMappingBar(), BorderLayout.SOUTH)
        applySettings(host.currentSettings())
    }

    // ------------------------------------------------------------ public API

    /** Adds a message and selects it. Called by the context menu (on the EDT). */
    public fun addItem(title: String, original: String, service: ServiceInfo?, isRequest: Boolean) {
        val item = Item(nextId++, title, original, service, isRequest)
        itemsModel.addElement(item)
        itemList.selectedIndex = itemsModel.size() - 1
        itemList.ensureIndexIsVisible(itemsModel.size() - 1)
    }

    /** Adds a client term (from "Add selection as client term") and re-renders. */
    public fun addTerm(term: String) {
        val t = term.trim()
        if (t.isEmpty()) return
        val current = parseTerms(termsField.text)
        if (current.any { it.equals(t, ignoreCase = true) }) return
        termsField.text = (current + t).joinToString(", ")
        settingsFromUi()
    }

    /** Pushes stored settings into the controls without firing change handlers. */
    public fun applySettings(s: Settings) {
        loadingSettings = true
        try {
            for ((key, box) in toggles) box.isSelected = s.isOn(key)
            privateIpsBox.isSelected = !s.keepPrivateIps
            termsField.text = s.terms.joinToString(", ")
        } finally {
            loadingSettings = false
        }
    }

    public fun updateMapping(snapshot: MappingSnapshot) {
        mappingLabel.text = "Mapping: ${snapshot.size} entries"
    }

    /** Services of all items, for Send to Repeater's host lookup. */
    public fun knownServices(): List<ServiceInfo> =
        (0 until itemsModel.size()).mapNotNull { itemsModel.get(it).service }.distinct()

    /** Stops timers; part of `extensionUnloaded()`. */
    public fun dispose() {
        rerenderTimer.stop()
    }

    // ------------------------------------------------------------ layout

    private fun buildItemsBar(): JPanel {
        itemList.selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        itemList.visibleRowCount = 4
        itemList.addListSelectionListener { e -> if (!e.valueIsAdjusting) renderSelected(force = false) }
        val buttons = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(JButton("Copy all as Markdown").apply { addActionListener { copyMarkdown() } })
            add(JButton("Remove").apply { addActionListener { removeSelected() } })
            add(JButton("Clear items").apply { addActionListener { clearItems() } })
        }
        return JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Items (right-click a message → Send to Anonymizer)")
            add(JScrollPane(itemList).apply { preferredSize = Dimension(100, 90) }, BorderLayout.CENTER)
            add(buttons, BorderLayout.EAST)
        }
    }

    private fun buildPanes(): JSplitPane {
        val left = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Original (read-only)")
            add(JScrollPane(originalPane), BorderLayout.CENTER)
        }
        val copy = JButton("Copy").apply { addActionListener { shown?.result?.let { host.copy(it.text) } } }
        val rightTop = JPanel(BorderLayout()).apply {
            add(summaryLabel, BorderLayout.CENTER)
            add(copy, BorderLayout.EAST)
        }
        val right = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Anonymized (blue = placeholder, yellow = check this)")
            add(rightTop, BorderLayout.NORTH)
            add(JScrollPane(anonymizedPane), BorderLayout.CENTER)
        }
        return JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right).apply { resizeWeight = 0.5 }
    }

    private fun buildToggles(): JPanel {
        val row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        for ((label, keys) in TOGGLES) {
            val box = JCheckBox(label, true)
            box.toolTipText = "detect: ${keys.joinToString(", ")}"
            box.addActionListener { settingsFromUi() }
            for (k in keys) toggles[k] = box
            row.add(box)
        }
        privateIpsBox.toolTipText = "Off keeps 10.x / 192.168.x topology visible to the LLM"
        privateIpsBox.addActionListener { settingsFromUi() }
        row.add(privateIpsBox)
        val termsRow = JPanel(BorderLayout(6, 0)).apply {
            add(JLabel("Client terms (comma-separated):"), BorderLayout.WEST)
            add(termsField, BorderLayout.CENTER)
            add(JButton("+").apply {
                toolTipText = "Add a client term"
                addActionListener {
                    val t = JOptionPane.showInputDialog(dialogParent(), "Client term (company name, product codename…):", "Add client term", JOptionPane.PLAIN_MESSAGE)
                    if (t != null) addTerm(t)
                }
            }, BorderLayout.EAST)
        }
        termsField.addActionListener { settingsFromUi() }
        termsField.addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) {
                settingsFromUi()
            }
        })
        return JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(row)
            add(termsRow)
        }
    }

    private fun buildRestore(): JPanel {
        restorePane.toolTipText = "Paste the LLM's reply here, then Restore"
        val buttons = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
            add(JButton("Restore").apply { addActionListener { restore() } })
            add(lenientBox.apply { toolTipText = "Also accept COOKIE_1 without brackets and -/_ confusion; every lenient match is highlighted" })
            add(JButton("Send to Repeater").apply { addActionListener { host.sendToRepeater(restorePane.text, knownServices(), dialogParent()) } })
            add(JButton("Copy").apply { addActionListener { host.copy(restorePane.text) } })
            add(JButton("Clear").apply { addActionListener { restorePane.setContent(""); restoreStatus.text = " " } })
        }
        return JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Restore (orange = lenient match, red = unknown or modified)")
            add(buttons, BorderLayout.NORTH)
            add(JScrollPane(restorePane), BorderLayout.CENTER)
            add(restoreStatus.apply { font = font.deriveFont(Font.BOLD) }, BorderLayout.SOUTH)
        }
    }

    private fun buildMappingBar(): JPanel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
        add(mappingLabel)
        add(JButton("Show").apply { addActionListener { showMapping() } })
        add(JButton("Clear").apply { addActionListener { clearMapping() } })
        add(JButton("Export…").apply { addActionListener { host.exportMap(dialogParent()) } })
        add(JButton("Import…").apply {
            addActionListener {
                host.importMap(dialogParent()) { snap ->
                    updateMapping(snap)
                    invalidateAll()
                }
            }
        })
        add(Box.createHorizontalStrut(12))
        add(JLabel("Session = this Burp project. Temporary projects lose the map on close: Export first."))
    }

    // ------------------------------------------------------------ behaviour

    private fun settingsFromUi() {
        if (loadingSettings) return
        val detect = LinkedHashMap<String, Boolean>(host.currentSettings().detect)
        for ((key, box) in toggles) detect[key] = box.isSelected
        val s = host.currentSettings().copy(
            detect = detect,
            keepPrivateIps = !privateIpsBox.isSelected,
            terms = parseTerms(termsField.text),
        )
        host.settingsChanged(s)
        invalidateAll()
    }

    private fun dialogParent(): java.awt.Component = host.suiteFrame() ?: this

    private fun parseTerms(text: String): List<String> =
        text.split(",").map { it.trim() }.filter { it.isNotEmpty() }.distinct()

    private fun invalidateAll() {
        settingsVersion++
        rerenderTimer.restart()
    }

    private fun renderSelected(force: Boolean) {
        val selected = itemList.selectedValuesList
        if (selected.size != 1) {
            if (selected.isEmpty()) {
                shown = null
                originalPane.setContent("")
                anonymizedPane.setContent("")
                summaryLabel.text = " "
            } else {
                summaryLabel.text = "${selected.size} items selected — Copy all as Markdown bundles them"
            }
            return
        }
        val item = selected[0]
        if (shown !== item || force) {
            shown = item
            originalPane.setContent(item.original)
        }
        val r = item.result
        if (r != null && item.version == settingsVersion) {
            show(item, r)
            return
        }
        summaryLabel.text = "anonymizing…"
        val version = settingsVersion
        host.anonymize(item.original, { result ->
            item.result = result
            item.version = version
            updateMapping(result.snapshot)
            if (shown === item) show(item, result)
        }, { e ->
            summaryLabel.text = "failed: ${e.message}"
            host.log("Anonymizer: anonymize failed for #${item.id}: $e")
        })
    }

    private fun show(item: Item, r: AnonymizeResult) {
        anonymizedPane.setContent(r.text)
        anonymizedPane.showAnonymizeSpans(r.spans)
        val warnings = r.spans.count { it.kind == com.anonymizer.engine.Highlights.Kind.WARNING }
        val summary = if (r.summary.isEmpty()) "nothing replaced" else r.summary.entries.sortedBy { it.key }.joinToString(", ") { "${it.key} x${it.value}" }
        summaryLabel.text = "#${item.id}: $summary" + (if (warnings > 0) " — $warnings value(s) to check" else "")
    }

    private fun ensureFresh(items: List<Item>, done: () -> Unit) {
        val version = settingsVersion
        val stale = items.firstOrNull { it.result == null || it.version != version }
        if (stale == null) {
            done()
            return
        }
        host.anonymize(stale.original, { result ->
            stale.result = result
            stale.version = version
            updateMapping(result.snapshot)
            ensureFresh(items, done)
        }, { e ->
            host.log("Anonymizer: anonymize failed for #${stale.id}: $e")
            summaryLabel.text = "failed: ${e.message}"
        })
    }

    private fun copyMarkdown() {
        val selected = itemList.selectedValuesList
        val items = if (selected.isEmpty()) (0 until itemsModel.size()).map { itemsModel.get(it) } else selected
        if (items.isEmpty()) return
        ensureFresh(items) {
            val text = Markdown.bundle(items.map { it to (it.result?.text ?: "") })
            host.copy(text)
            summaryLabel.text = "copied ${items.size} item(s) as Markdown"
        }
    }

    private fun removeSelected() {
        val idx = itemList.selectedIndices.sortedDescending()
        for (i in idx) itemsModel.remove(i)
    }

    private fun clearItems() {
        itemsModel.clear()
        shown = null
        originalPane.setContent("")
        anonymizedPane.setContent("")
        summaryLabel.text = " "
    }

    private fun restore() {
        val text = restorePane.text
        if (text.isBlank()) return
        restoreStatus.text = "restoring…"
        host.restore(text, lenientBox.isSelected, { r ->
            restorePane.setContent(r.text)
            restorePane.showRestoreSpans(r.spans)
            restoreStatus.text = describe(r)
        }, { e ->
            restoreStatus.text = "failed: ${e.message}"
            host.log("Anonymizer: restore failed: $e")
        })
    }

    private fun describe(r: Restorer.Result): String {
        val parts = ArrayList<String>()
        if (r.unknown.isNotEmpty()) {
            parts.add("⚠ ${r.unknown.size} unknown placeholder(s): " + r.unknown.take(3).joinToString(", ") { "${it.token} (line ${it.line})" } + (if (r.unknown.size > 3) ", …" else ""))
        }
        if (r.modifiedJwts.isNotEmpty()) parts.add("⚠ ${r.modifiedJwts.size} modified JWT(s) not restored (re-sign after editing claims)")
        if (r.lenient.isNotEmpty()) parts.add("${r.lenient.size} lenient match(es) highlighted")
        if (parts.isEmpty()) return "Restored; every placeholder matched exactly."
        return "Restored. " + parts.joinToString("; ")
    }

    private fun showMapping() {
        host.mapSnapshot { snap ->
            val model = DefaultTableModel(arrayOf("Category", "Placeholder", "Original"), 0)
            for (e in snap.entries()) model.addRow(arrayOf(e.category, e.placeholder, e.original))
            val table = JTable(model).apply { autoCreateRowSorter = true }
            val owner: java.awt.Window? = host.suiteFrame() ?: SwingUtilities.getWindowAncestor(this)
            val dialog = JDialog(owner, "Anonymizer mapping (${snap.size} entries)")
            dialog.contentPane.add(JScrollPane(table))
            dialog.setSize(800, 500)
            dialog.setLocationRelativeTo(owner)
            dialog.isVisible = true
        }
    }

    private fun clearMapping() {
        val ok = JOptionPane.showConfirmDialog(
            dialogParent(),
            "Clear the session map? Placeholder numbering restarts and nothing already copied can be restored.",
            "Clear mapping",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.WARNING_MESSAGE,
        )
        if (ok != JOptionPane.OK_OPTION) return
        host.clearMap { snap ->
            updateMapping(snap)
            invalidateAll()
        }
    }

    private companion object {
        val TOGGLES: List<Pair<String, List<String>>> = listOf(
            "Hosts" to listOf("host"),
            "IPs" to listOf("ipv4", "ipv6"),
            "Emails" to listOf("email"),
            "Auth header" to listOf("auth"),
            "Cookies" to listOf("cookies"),
            "JWT" to listOf("jwt"),
            "Sensitive headers" to listOf("headers"),
            "Sensitive fields" to listOf("fields"),
            "Secrets" to listOf("secrets"),
            "UUID" to listOf("uuid"),
            "Hex" to listOf("hex"),
            "Blobs" to listOf("blob"),
            "Cards/SSN" to listOf("card", "ssn"),
            "Phone" to listOf("phone"),
            "Terms" to listOf("terms"),
        )
    }
}
