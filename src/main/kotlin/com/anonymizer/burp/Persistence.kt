package com.anonymizer.burp

import burp.api.montoya.MontoyaApi
import com.anonymizer.engine.JsonParser
import com.anonymizer.engine.JsonWriter
import com.anonymizer.engine.MappingSnapshot
import com.anonymizer.engine.Settings
import com.anonymizer.engine.toValue

/**
 * Montoya persistence only (docs/PLAN.md, design point 2). Detector toggles follow the user
 * (`preferences()`); client terms, keep-lists and the session map follow the project
 * (`extensionData()`). Temporary projects lose `extensionData()` on close by design; Export is the
 * Community answer.
 */
public class Persistence(private val api: MontoyaApi) {
    private val log = api.logging()

    public fun loadSettings(): Settings {
        var s = Settings.EXTENSION_DEFAULTS
        api.persistence().preferences().getString(KEY_GLOBAL)?.let { json ->
            s = parse(json)?.let { Settings.fromJson(it, s) } ?: s
        }
        api.persistence().extensionData().getString(KEY_PROJECT)?.let { json ->
            s = parse(json)?.let { Settings.fromJson(it, s) } ?: s
        }
        return s
    }

    public fun saveSettings(s: Settings) {
        val all = s.toJson()
        val project = LinkedHashMap<String, Any?>()
        val global = LinkedHashMap<String, Any?>()
        for ((k, v) in all) if (k in PROJECT_KEYS) project[k] = v else global[k] = v
        api.persistence().preferences().setString(KEY_GLOBAL, JsonWriter.compact(global))
        api.persistence().extensionData().setString(KEY_PROJECT, JsonWriter.compact(project))
    }

    public fun loadMap(): MappingSnapshot? {
        val json = api.persistence().extensionData().getString(KEY_MAP) ?: return null
        return try {
            MappingSnapshot.fromJson(json)
        } catch (e: IllegalArgumentException) {
            log.logToError("Anonymizer: stored map is unreadable and was ignored: ${e.message}")
            null
        }
    }

    /** Safe to call from the engine thread; Montoya persistence is thread-safe. */
    public fun saveMap(snapshot: MappingSnapshot) {
        api.persistence().extensionData().setString(KEY_MAP, JsonWriter.compact(linkedMapOf("forward" to snapshot.forward, "counters" to snapshot.counters)))
    }

    @Suppress("UNCHECKED_CAST")
    private fun parse(json: String): Map<String, Any?>? = JsonParser.parseOrNull(json)?.toValue() as? Map<String, Any?>

    public companion object {
        public const val KEY_GLOBAL: String = "anonymizer.settings"
        public const val KEY_PROJECT: String = "anonymizer.project"
        public const val KEY_MAP: String = "anonymizer.map"
        public val PROJECT_KEYS: Set<String> = setOf("terms", "keep_hosts", "keep_base_hosts", "keep_cookies")
    }
}
