package com.anonymizer.burp

import burp.api.montoya.MontoyaApi
import com.anonymizer.engine.AnonymizeResult
import com.anonymizer.engine.MappingSnapshot
import com.anonymizer.engine.Restorer
import com.anonymizer.engine.Settings
import com.anonymizer.ui.ServiceInfo
import com.anonymizer.ui.TabHost
import java.awt.Component
import java.util.concurrent.CompletableFuture
import javax.swing.SwingUtilities

/** Bridges the Swing tab to the engine thread, persistence, clipboard and Repeater. */
public class TabController(
    private val api: MontoyaApi,
    private val engine: EngineService,
    private val persistence: Persistence,
) : TabHost {
    private val repeater = RepeaterBridge(api)

    override fun currentSettings(): Settings = engine.settings

    override fun settingsChanged(settings: Settings) {
        engine.settings = settings
        persistence.saveSettings(settings)
    }

    override fun anonymize(text: String, done: (AnonymizeResult) -> Unit, failed: (Throwable) -> Unit) {
        deliver(engine.anonymize(text), done, failed)
    }

    override fun restore(text: String, lenient: Boolean, done: (Restorer.Result) -> Unit, failed: (Throwable) -> Unit) {
        deliver(engine.restore(text, lenient), done, failed)
    }

    override fun mapSnapshot(done: (MappingSnapshot) -> Unit) {
        deliver(engine.snapshot(), done) { logError("Anonymizer: snapshot failed", it) }
    }

    override fun clearMap(done: (MappingSnapshot) -> Unit) {
        deliver(engine.clear(), done) { logError("Anonymizer: clear failed", it) }
    }

    override fun exportMap(parent: Component) {
        deliver(engine.snapshot(), { snap ->
            if (MapFile.export(parent, snap)) log("Anonymizer: exported ${snap.size} map entries")
        }) { logError("Anonymizer: export failed", it) }
    }

    override fun importMap(parent: Component, done: (MappingSnapshot) -> Unit) {
        val snap = MapFile.import(parent) ?: return
        deliver(engine.load(snap), { loaded ->
            log("Anonymizer: imported ${loaded.size} map entries")
            done(loaded)
        }) { logError("Anonymizer: import failed", it) }
    }

    override fun copy(text: String) {
        ClipboardCopy.copy(text)
    }

    override fun sendToRepeater(text: String, known: List<ServiceInfo>, parent: Component) {
        repeater.send(text, known, parent)
    }

    override fun log(message: String) {
        api.logging().logToOutput(message)
    }

    /** Burp does not catch exceptions from extension threads (BApp criterion 5): stack trace to the error stream. */
    override fun logError(message: String, error: Throwable) {
        api.logging().logToError(message, error)
    }

    override fun suiteFrame(): java.awt.Frame? = api.userInterface().swingUtils().suiteFrame()

    /** Completes [done] or [failed] on the EDT. */
    private fun <T> deliver(future: CompletableFuture<T>, done: (T) -> Unit, failed: (Throwable) -> Unit) {
        future.whenComplete { value, error ->
            SwingUtilities.invokeLater {
                if (error != null) failed(error.cause ?: error) else done(value)
            }
        }
    }
}
