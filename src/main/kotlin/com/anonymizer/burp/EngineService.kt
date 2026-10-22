package com.anonymizer.burp

import com.anonymizer.engine.AnonymizeResult
import com.anonymizer.engine.Anonymizer
import com.anonymizer.engine.Highlights
import com.anonymizer.engine.Mapping
import com.anonymizer.engine.MappingSnapshot
import com.anonymizer.engine.Restorer
import com.anonymizer.engine.Settings
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The one engine thread. Every anonymise/restore/map mutation runs on this single-threaded executor,
 * so placeholder numbering is deterministic without locks; callers get [CompletableFuture]s that
 * complete with immutable results. Never block the EDT on these futures: use `thenAccept` and hop
 * back with `SwingUtilities.invokeLater`.
 */
public class EngineService(initialSettings: Settings) {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "anonymizer-engine").also { it.isDaemon = true }
    }
    private val mapping: Mapping = Mapping()

    /** Current settings; swapped atomically, read by the next engine task. */
    @Volatile
    public var settings: Settings = initialSettings

    /** Invoked on the engine thread after the map changed (persist it from here). */
    @Volatile
    public var onMapChanged: ((MappingSnapshot) -> Unit)? = null

    public fun anonymize(text: String): CompletableFuture<AnonymizeResult> = submit {
        val s = settings
        val capped = capBody(text)
        val anonymizer = Anonymizer(s, mapping)
        val before = mapping.size
        val out = anonymizer.anonymize(capped)
        val snap = mapping.snapshot()
        if (mapping.size != before) onMapChanged?.invoke(snap)
        AnonymizeResult(out, anonymizer.summary, snap, Highlights.placeholders(out, snap) + Highlights.warnings(out, s, snap))
    }

    public fun restore(text: String, lenient: Boolean): CompletableFuture<Restorer.Result> = submit {
        Restorer(mapping.snapshot(), settings.updateContentLength).restore(text, lenient)
    }

    public fun snapshot(): CompletableFuture<MappingSnapshot> = submit { mapping.snapshot() }

    public fun clear(): CompletableFuture<MappingSnapshot> = submit {
        mapping.clear()
        mapping.snapshot().also { onMapChanged?.invoke(it) }
    }

    public fun load(snapshot: MappingSnapshot): CompletableFuture<MappingSnapshot> = submit {
        mapping.replaceWith(snapshot)
        mapping.snapshot().also { onMapChanged?.invoke(it) }
    }

    /** Releases the engine thread; part of `extensionUnloaded()`. */
    public fun shutdown() {
        executor.shutdown()
        if (!executor.awaitTermination(2, TimeUnit.SECONDS)) executor.shutdownNow()
    }

    private fun <T> submit(block: () -> T): CompletableFuture<T> {
        val future = CompletableFuture<T>()
        try {
            executor.execute {
                try {
                    future.complete(block())
                } catch (e: Throwable) {
                    future.completeExceptionally(e)
                }
            }
        } catch (e: java.util.concurrent.RejectedExecutionException) {
            future.completeExceptionally(e)
        }
        return future
    }

    /** Bodies over the cap are replaced by a marker so a huge response never stalls the engine. */
    private fun capBody(text: String): String {
        if (text.length <= BODY_CAP) return text
        val sep = text.indexOf("\r\n\r\n").takeIf { it >= 0 } ?: text.indexOf("\n\n")
        if (sep < 0 || sep > BODY_CAP) return "[message omitted: ${text.length} chars exceeds the ${BODY_CAP / 1_000_000} MB cap]"
        val sepLen = if (text.startsWith("\r\n\r\n", sep)) 4 else 2
        val head = text.substring(0, sep + sepLen)
        return head + "[body omitted: ${text.length - head.length} chars exceeds the ${BODY_CAP / 1_000_000} MB cap]"
    }

    public companion object {
        public const val BODY_CAP: Int = 2_000_000
    }
}
