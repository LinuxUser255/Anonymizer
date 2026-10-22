package com.anonymizer.engine

/**
 * Spans to highlight in anonymised output: every placeholder the map knows, plus "check this"
 * warnings for values a disabled detector would have caught (docs/PLAN.md: warn, don't redact).
 */
public object Highlights {
    public enum class Kind { PLACEHOLDER, WARNING }

    /** `[start, end)` in the text; [note] is shown as a tooltip / status hint. */
    public data class Span(val start: Int, val end: Int, val kind: Kind, val note: String)

    /** Regex matching every placeholder in [snapshot] exactly, longest first, with alnum boundaries. */
    public fun exactPattern(snapshot: MappingSnapshot): Regex? {
        val keys = snapshot.reverse.keys.sortedByDescending { it.length }
        if (keys.isEmpty()) return null
        return Regex(keys.joinToString("|") { boundedLiteral(it) })
    }

    internal fun boundedLiteral(lit: String): String {
        var p = Regex.escape(lit)
        if (lit.first().isLetterOrDigit()) p = "(?<![A-Za-z0-9])$p"
        if (lit.last().isLetterOrDigit()) p = "$p(?![A-Za-z0-9])"
        return p
    }

    public fun placeholders(text: String, snapshot: MappingSnapshot): List<Span> {
        val rx = exactPattern(snapshot) ?: return emptyList()
        return rx.findAll(text).map { m ->
            Span(m.range.first, m.range.last + 1, Kind.PLACEHOLDER, categoryOf(snapshot, m.value))
        }.toList()
    }

    private fun categoryOf(snapshot: MappingSnapshot, placeholder: String): String {
        for ((cat, pairs) in snapshot.forward) if (pairs.containsValue(placeholder)) return cat
        return "placeholder"
    }

    private val TOKEN = Regex("[A-Za-z0-9+/=_\\-.]{20,}")

    /**
     * Values left in the output that a currently disabled detector would have replaced. Nothing is
     * changed; the user decides. Known placeholders are never warned about.
     */
    public fun warnings(text: String, settings: Settings, snapshot: MappingSnapshot): List<Span> {
        val out = ArrayList<Span>()
        if (!settings.isOn("blob")) {
            for (m in TOKEN.findAll(text)) {
                if (snapshot.reverse.containsKey(m.value)) continue
                if (Detectors.looksLikeBlob(m.value)) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "high-entropy value (blob detector is off)"))
            }
        }
        if (!settings.isOn("phone")) {
            for (m in Detectors.RE_PHONE.findAll(text)) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "looks like a phone number (phone detector is off)"))
        }
        if (!settings.isOn("card")) {
            for (m in Detectors.RE_CARD.findAll(text)) {
                val digits = m.value.filter { it in '0'..'9' }
                if (digits.length in 13..19 && Detectors.luhnOk(digits)) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "Luhn-valid card number (card detector is off)"))
            }
        }
        if (!settings.isOn("ssn")) {
            for (m in Detectors.RE_SSN.findAll(text)) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "looks like an SSN (SSN detector is off)"))
        }
        if (!settings.isOn("hex")) {
            val rx = Regex("(?<![0-9A-Za-z])[0-9a-fA-F]{${settings.minHexLen},}(?![0-9A-Za-z])")
            for (m in rx.findAll(text)) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "long hex string (hex detector is off)"))
        }
        if (!settings.isOn("uuid")) {
            for (m in Detectors.RE_UUID.findAll(text)) {
                if (!m.value.lowercase().startsWith("00000000-0000-4000-8000-")) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "UUID (UUID detector is off)"))
            }
        }
        if (!settings.isOn("email")) {
            for (m in Detectors.RE_EMAIL.findAll(text)) {
                if (!snapshot.reverse.containsKey(m.value)) out.add(Span(m.range.first, m.range.last + 1, Kind.WARNING, "email address (email detector is off)"))
            }
        }
        return out.sortedBy { it.start }
    }
}

/** What the engine hands back for one anonymise call. */
public data class AnonymizeResult(
    val text: String,
    /** Replacement counts by label (`HOST x2, COOKIE x1`). */
    val summary: Map<String, Int>,
    /** The map after this call. */
    val snapshot: MappingSnapshot,
    val spans: List<Highlights.Span>,
)
