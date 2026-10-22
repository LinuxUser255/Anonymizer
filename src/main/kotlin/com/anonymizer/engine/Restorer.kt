package com.anonymizer.engine

/**
 * Turns LLM output back into real values using a [MappingSnapshot].
 *
 * Rules (docs/PLAN.md, "Restore rules"): an exact placeholder is replaced silently; a known shape
 * that is not in the map is left in place and flagged; mangled placeholders (case, markdown,
 * percent-encoding, and with [restore]'s `lenient` flag also missing brackets and `-`/`_`/space
 * confusion) are restored and highlighted; a synthetic JWT whose claims were edited is flagged and
 * not restored. Restore never invents a value. `Content-Length` is recomputed only for messages
 * that parse as HTTP and whose body changed.
 */
public class Restorer(
    private val snapshot: MappingSnapshot,
    private val updateContentLength: Boolean = true,
) {
    public enum class Kind { LENIENT, UNKNOWN, MODIFIED_JWT }

    /** A highlighted range `[start, end)` in the restored text. */
    public data class Span(val start: Int, val end: Int, val kind: Kind, val token: String, val line: Int)

    public data class Result(val text: String, val spans: List<Span>) {
        public val unknown: List<Span> get() = spans.filter { it.kind == Kind.UNKNOWN }
        public val lenient: List<Span> get() = spans.filter { it.kind == Kind.LENIENT }
        public val modifiedJwts: List<Span> get() = spans.filter { it.kind == Kind.MODIFIED_JWT }
    }

    private class Variant(val original: String, val exact: Boolean)

    private val reverse: Map<String, String> = snapshot.reverse

    /** literal text -> what to emit; exact placeholders and their percent-encoded forms. */
    private val literals: LinkedHashMap<String, Variant> = LinkedHashMap<String, Variant>().also { m ->
        for (ph in reverse.keys.sortedByDescending { it.length }) {
            val orig = reverse.getValue(ph)
            m.putIfAbsent(ph, Variant(orig, exact = true))
            // Percent-encoded forms are faithful encodings, not manglings, so they count as exact.
            val encBrackets = Urls.quotePlus(ph, "[]")
            if (encBrackets != ph) m.putIfAbsent(encBrackets, Variant(Urls.quotePlus(orig, "[]"), exact = true))
            val encAll = Urls.quotePlus(ph, "")
            if (encAll != ph && encAll != encBrackets) m.putIfAbsent(encAll, Variant(Urls.quotePlus(orig, ""), exact = true))
        }
    }

    /** Upper-cased bracket placeholders, for case-insensitive matching. */
    private val upper: Map<String, String> = reverse.keys.filter { it.startsWith("[") }
        .associate { it.uppercase() to reverse.getValue(it) }

    /** Loosely normalised placeholders, for lenient matching. */
    private val loose: Map<String, String> = LinkedHashMap<String, String>().also { m ->
        for ((ph, orig) in reverse) m.putIfAbsent(looseKey(ph), orig)
    }

    private val knownSignatures: Set<String> = reverse.keys
        .filter { it.contains(".REDACTED_SIGNATURE_") }
        .map { it.substringAfterLast('.') }
        .toSet()

    private fun pattern(lenient: Boolean): Regex? {
        val parts = ArrayList<String>()
        for (lit in literals.keys) {
            var p = Regex.escape(lit)
            if (lit[0].isLetterOrDigit()) p = "(?<![A-Za-z0-9])$p"
            if (lit.last().isLetterOrDigit()) p = "$p(?![A-Za-z0-9])"
            parts.add(p)
        }
        if (upper.isNotEmpty()) parts.add(BRACKET_TOKEN)
        if (lenient) {
            parts.add(BARE_TOKEN)
            parts.add(LOOSE_HOST)
        }
        if (parts.isEmpty()) return null
        return Regex(parts.joinToString("|"))
    }

    public fun restore(text: String, lenient: Boolean = false): Result {
        val spans = ArrayList<Span>()
        val rx = pattern(lenient)
        val guarded = protectedRanges(text)
        val sb = StringBuilder(text.length)
        var pos = 0
        if (rx != null) {
            for (m in rx.findAll(text)) {
                // An unknown shaped placeholder (user7@target1.example) is left whole and flagged
                // later rather than having its known part restored into a half-invented value.
                if (guarded.any { m.range.first >= it.first && m.range.last <= it.last }) continue
                val hit = m.value
                val resolved: Pair<String, Boolean>? = literals[hit]?.let { it.original to it.exact }
                    ?: upper[hit.uppercase()]?.let { it to false }
                    ?: if (lenient) loose[looseKey(hit)]?.let { it to false } else null
                if (resolved == null) continue
                sb.append(text, pos, m.range.first)
                val start = sb.length
                sb.append(resolved.first)
                if (!resolved.second) spans.add(Span(start, sb.length, Kind.LENIENT, hit, -1))
                pos = m.range.last + 1
            }
        }
        sb.append(text, pos, text.length)
        var out = sb.toString()
        if (updateContentLength) {
            val fixed = fixContentLength(text, out)
            if (fixed.first != out) {
                out = fixed.first
                for ((offset, delta) in fixed.second) {
                    for (i in spans.indices) {
                        val s = spans[i]
                        if (s.start >= offset) spans[i] = s.copy(start = s.start + delta, end = s.end + delta)
                    }
                }
            }
        }
        spans.addAll(scanLeftovers(out))
        val withLines = spans.map { it.copy(line = lineOf(out, it.start)) }.sortedBy { it.start }
        return Result(out, withLines)
    }

    /** Ranges of shaped placeholders (emails, hosts) that are not known as a whole. */
    private fun protectedRanges(text: String): List<IntRange> {
        val out = ArrayList<IntRange>()
        for (m in PROTECT_EMAIL.findAll(text)) {
            if (!reverse.containsKey(m.value)) out.add(m.range)
        }
        for (m in PROTECT_HOST.findAll(text)) {
            if (out.any { m.range.first in it }) continue
            val labels = m.value.split(".")
            val tail = labels.takeLast(2).joinToString(".")
            val unknownSub = labels.dropLast(2).any { SUB_LABEL.matches(it) && !reverse.containsKey(it) }
            if (unknownSub || !reverse.containsKey(tail)) out.add(m.range)
        }
        return out
    }

    /** Placeholder-shaped tokens still present after substitution. */
    private fun scanLeftovers(out: String): List<Span> {
        val spans = ArrayList<Span>()
        for (m in Detectors.RE_JWT.findAll(out)) {
            val sig = m.value.substringAfterLast('.')
            if (sig.startsWith("REDACTED_SIGNATURE_")) {
                val kind = if (sig in knownSignatures) Kind.MODIFIED_JWT else Kind.UNKNOWN
                spans.add(Span(m.range.first, m.range.last + 1, kind, m.value, -1))
            }
        }
        for (rx in LEFTOVER_SHAPES) {
            for (m in rx.findAll(out)) {
                if (spans.any { it.start <= m.range.first && m.range.last < it.end }) continue
                spans.add(Span(m.range.first, m.range.last + 1, Kind.UNKNOWN, m.value, -1))
            }
        }
        return spans
    }

    /**
     * Recomputes `Content-Length` on messages whose body changed between [before] and [after].
     * Returns the new text and the (offset, delta) of every edit, in order.
     */
    private fun fixContentLength(before: String, after: String): Pair<String, List<Pair<Int, Int>>> {
        val pb = HttpText.parse(before)
        val pa = HttpText.parse(after)
        if (pa.messages.isEmpty() || pa.messages.size != pb.messages.size) return after to emptyList()
        val newLengths = HashMap<Int, Int>()
        for ((i, m) in pa.messages.withIndex()) {
            val coreAfter = m.body.trimEnd('\r', '\n')
            val coreBefore = pb.messages[i].body.trimEnd('\r', '\n')
            if (coreAfter != coreBefore && coreAfter.isNotBlank()) newLengths[i] = HttpText.utf8Length(coreAfter)
        }
        if (newLengths.isEmpty()) return after to emptyList()
        // Walk the raw text line by line with the same state machine, editing header lines in place.
        val edits = ArrayList<Pair<Int, Int>>()
        val sb = StringBuilder(after.length)
        var msgIndex = -1
        var state: String? = null
        var prevBlank = true
        var offset = 0
        val lines = after.split("\n")
        for ((li, rawLine) in lines.withIndex()) {
            val line = rawLine.removeSuffix("\r")
            val cr = rawLine.length != line.length
            var emit = rawLine
            if (HttpText.isStartLine(line) && (msgIndex < 0 || state == "headers" || prevBlank)) {
                msgIndex++
                state = "headers"
                prevBlank = false
            } else if (msgIndex >= 0 && state == "headers") {
                if (line.isBlank()) {
                    state = "body"
                } else if (line.lowercase().startsWith("content-length:") && newLengths.containsKey(msgIndex)) {
                    emit = "Content-Length: ${newLengths.getValue(msgIndex)}" + (if (cr) "\r" else "")
                }
                prevBlank = line.isBlank()
            } else {
                prevBlank = line.isBlank()
            }
            if (emit != rawLine) edits.add(offset to (emit.length - rawLine.length))
            sb.append(emit)
            if (li < lines.size - 1) sb.append('\n')
            offset += emit.length + 1
        }
        return sb.toString() to edits
    }

    private fun lineOf(text: String, offset: Int): Int {
        var line = 1
        var i = 0
        val end = minOf(offset, text.length)
        while (i < end) {
            if (text[i] == '\n') line++
            i++
        }
        return line
    }

    private companion object {
        /** `[COOKIE_1]` in any case, with `-`, `_` or space between the parts. */
        const val BRACKET_TOKEN: String = "\\[[A-Za-z][A-Za-z0-9]*(?:[-_ ][A-Za-z0-9]+)*[-_ ]\\d+\\]"
        /** Lenient only: the same token without brackets. */
        const val BARE_TOKEN: String = "(?<![A-Za-z0-9\\[])[A-Z][A-Z0-9]*(?:[-_ ][A-Z0-9]+)*[-_ ]\\d+(?![A-Za-z0-9\\]])"
        /** Lenient only: `target1-example`, `sub2_target1.example`. */
        const val LOOSE_HOST: String = "(?<![A-Za-z0-9.-])(?:sub\\d+[-_.])*target\\d+[-_]example(?![A-Za-z0-9-])"

        val PROTECT_EMAIL: Regex = Regex("(?<![A-Za-z0-9.@-])user\\d+@(?:[a-z0-9-]+\\.)*target\\d+\\.example(?![A-Za-z0-9-])", RegexOption.IGNORE_CASE)
        val PROTECT_HOST: Regex = Regex("(?<![A-Za-z0-9.@-])(?:[a-z0-9-]+\\.)*target\\d+\\.example(?![A-Za-z0-9-])", RegexOption.IGNORE_CASE)
        val SUB_LABEL: Regex = Regex("sub\\d+", RegexOption.IGNORE_CASE)

        val LEFTOVER_SHAPES: List<Regex> = listOf(
            Regex("\\[[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*_\\d+\\]"),
            PROTECT_EMAIL,
            PROTECT_HOST,
            Regex("(?<![0-9a-fA-F])00000000-0000-4000-8000-\\d{12}(?![0-9a-fA-F])"),
            Regex("(?<![:\\w])2001:db8::[0-9a-f]+(?![:\\w])", RegexOption.IGNORE_CASE),
        )

        private val LOOSE_SEPARATORS: Regex = Regex("[-_ .]+")

        fun looseKey(s: String): String = s.trim('[', ']').uppercase().replace(LOOSE_SEPARATORS, "_")
    }
}
