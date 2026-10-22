package com.anonymizer.engine

/**
 * Consistent, reversible pseudonym store: `category -> original -> placeholder` plus a per-category
 * counter that never reuses a number for the lifetime of the map.
 *
 * Mutable, and deliberately not thread-safe: the extension mutates it only on its single engine
 * thread (see CLAUDE.md) and hands [snapshot]s to the UI. The JSON form (Export/Import) is
 * `{"forward": {category: {original: placeholder}}, "counters": {category: lastNumber}}`.
 */
public class Mapping {
    private val forward: LinkedHashMap<String, LinkedHashMap<String, String>> = LinkedHashMap()
    private val reverse: LinkedHashMap<String, String> = LinkedHashMap()
    private val counters: LinkedHashMap<String, Int> = LinkedHashMap()

    /** Number of placeholders issued. */
    public val size: Int
        get() = reverse.size

    /** True when [value] is a placeholder this map issued. */
    public fun isPlaceholder(value: String): Boolean = reverse.containsKey(value)

    /** The original behind [placeholder], or `null`. */
    public fun originalOf(placeholder: String): String? = reverse[placeholder]

    /**
     * Returns the placeholder for [original] in [category], creating it with [make] on first sight.
     * A value that is itself a known placeholder is returned unchanged (idempotency).
     * The counter is bumped *before* [make] runs so nested lookups (a JWT whose claims are
     * anonymised while its own placeholder is being built) get later numbers than the outer value.
     */
    public fun get(category: String, original: String, make: (Int) -> String): String {
        if (reverse.containsKey(original)) return original
        val cat = forward.getOrPut(category) { LinkedHashMap() }
        cat[original]?.let { return it }
        val n = (counters[category] ?: 0) + 1
        counters[category] = n
        val placeholder = make(n)
        cat[original] = placeholder
        reverse[placeholder] = original
        return placeholder
    }

    /** Current counter for [category] (0 when unused). */
    public fun counter(category: String): Int = counters[category] ?: 0

    /** Forgets everything and resets every counter. The only way numbering restarts. */
    public fun clear() {
        forward.clear()
        reverse.clear()
        counters.clear()
    }

    /** Immutable copy for the UI and for restore. */
    public fun snapshot(): MappingSnapshot = MappingSnapshot(
        forward = forward.mapValues { (_, v) -> LinkedHashMap(v).toMap() }.toMap(),
        counters = counters.toMap(),
    )

    /** Serialises in the map-file format (indent 2). */
    public fun toJson(): String = JsonWriter.pretty(linkedMapOf("forward" to forward, "counters" to counters))

    /** Replaces the whole content with [other]'s. */
    public fun replaceWith(other: MappingSnapshot) {
        clear()
        for ((cat, pairs) in other.forward) {
            val m = LinkedHashMap<String, String>()
            for ((orig, ph) in pairs) {
                m[orig] = ph
                reverse[ph] = orig
            }
            forward[cat] = m
        }
        counters.putAll(other.counters)
    }

    public companion object {
        /** Parses the map-file format; throws [IllegalArgumentException] on bad input. */
        public fun fromJson(text: String): Mapping {
            val snap = MappingSnapshot.fromJson(text)
            return Mapping().also { it.replaceWith(snap) }
        }
    }
}

/** A single map entry, for display. */
public data class MappingEntry(val category: String, val original: String, val placeholder: String)

/** Immutable view of a [Mapping]. */
public data class MappingSnapshot(
    val forward: Map<String, Map<String, String>>,
    val counters: Map<String, Int>,
) {
    /** placeholder -> original, computed once. */
    public val reverse: Map<String, String> by lazy {
        LinkedHashMap<String, String>().also { r ->
            for ((_, pairs) in forward) for ((orig, ph) in pairs) r[ph] = orig
        }
    }

    public val size: Int
        get() = reverse.size

    /** Entries sorted by category, in insertion order within a category. */
    public fun entries(): List<MappingEntry> =
        forward.entries.sortedBy { it.key }.flatMap { (cat, pairs) -> pairs.map { (o, p) -> MappingEntry(cat, o, p) } }

    public fun toJson(): String = JsonWriter.pretty(linkedMapOf("forward" to forward, "counters" to counters))

    public companion object {
        public val EMPTY: MappingSnapshot = MappingSnapshot(emptyMap(), emptyMap())

        public fun fromJson(text: String): MappingSnapshot {
            val root = JsonParser.parseOrNull(text)?.toValue() as? Map<*, *>
                ?: throw IllegalArgumentException("map file is not a JSON object")
            val forward = LinkedHashMap<String, Map<String, String>>()
            val fw = root["forward"] as? Map<*, *> ?: emptyMap<Any, Any>()
            for ((cat, pairs) in fw) {
                val p = pairs as? Map<*, *> ?: throw IllegalArgumentException("forward[$cat] is not an object")
                val m = LinkedHashMap<String, String>()
                for ((orig, ph) in p) {
                    if (ph !is String) throw IllegalArgumentException("forward[$cat][$orig] is not a string")
                    m[orig.toString()] = ph
                }
                forward[cat.toString()] = m
            }
            val counters = LinkedHashMap<String, Int>()
            val ct = root["counters"] as? Map<*, *> ?: emptyMap<Any, Any>()
            for ((cat, n) in ct) {
                val v = (n as? JsonNumber)?.raw?.toIntOrNull()
                    ?: throw IllegalArgumentException("counters[$cat] is not an integer")
                counters[cat.toString()] = v
            }
            return MappingSnapshot(forward, counters)
        }
    }
}
