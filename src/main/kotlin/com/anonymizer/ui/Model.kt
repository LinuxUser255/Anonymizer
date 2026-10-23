package com.anonymizer.ui

import com.anonymizer.engine.AnonymizeResult
import com.anonymizer.engine.MappingSnapshot
import com.anonymizer.engine.Restorer
import com.anonymizer.engine.Settings
import java.awt.Component

/** Where a message came from, enough to rebuild its target for Repeater. Montoya-free on purpose. */
public data class ServiceInfo(val host: String, val port: Int, val secure: Boolean)

/** One entry in the tab's item list. */
public class Item(
    public val id: Int,
    public val title: String,
    public val original: String,
    public val service: ServiceInfo?,
    public val isRequest: Boolean,
) {
    /** Last anonymised output, or null when not yet computed. Stale when [version] is behind. */
    @Volatile
    public var result: AnonymizeResult? = null

    /** The settings version [result] was computed with; the tab bumps its version on every change. */
    @Volatile
    public var version: Int = -1

    override fun toString(): String = "#$id $title"
}

/**
 * Everything the Swing tab needs from the extension. Implemented in `burp/`; the UI package
 * imports nothing from Montoya. All callbacks are delivered on the EDT.
 */
public interface TabHost {
    public fun currentSettings(): Settings
    public fun settingsChanged(settings: Settings)
    public fun anonymize(text: String, done: (AnonymizeResult) -> Unit, failed: (Throwable) -> Unit)
    public fun restore(text: String, lenient: Boolean, done: (Restorer.Result) -> Unit, failed: (Throwable) -> Unit)
    public fun mapSnapshot(done: (MappingSnapshot) -> Unit)
    public fun clearMap(done: (MappingSnapshot) -> Unit)
    public fun exportMap(parent: Component)
    public fun importMap(parent: Component, done: (MappingSnapshot) -> Unit)
    public fun copy(text: String)
    public fun sendToRepeater(text: String, known: List<ServiceInfo>, parent: Component)
    public fun log(message: String)

    /** Writes [message] and the stack trace of [error] to the extension's error stream. */
    public fun logError(message: String, error: Throwable)

    /** Burp's main window, the parent for every dialog (CLAUDE.md house rule). */
    public fun suiteFrame(): java.awt.Frame?
}
