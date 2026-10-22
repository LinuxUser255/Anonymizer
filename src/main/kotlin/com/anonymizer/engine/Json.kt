package com.anonymizer.engine

import java.math.BigDecimal
import java.math.BigInteger

/**
 * A JSON number kept as its source text. The engine never needs numeric arithmetic; it needs to
 * leave numbers byte-identical and, when a number sits under a sensitive key, to turn it into one
 * canonical string ([canonicalStr]) so `1E5` and `100000.0` map to the same placeholder.
 */
public data class JsonNumber(val raw: String) {
    /** True for integer literals (no fraction, no exponent, not NaN/Infinity). */
    public val isIntegral: Boolean
        get() = raw != "NaN" && !raw.endsWith("Infinity") && raw.none { it == '.' || it == 'e' || it == 'E' }

    /** Canonical text of the parsed value: `-0` → `0`, `1E5` → `100000.0`, `NaN` → `nan`. */
    public fun canonicalStr(): String = when {
        raw == "NaN" -> "nan"
        raw == "Infinity" -> "inf"
        raw == "-Infinity" -> "-inf"
        isIntegral -> BigInteger(raw).toString()
        else -> FloatText.format(raw.toDouble())
    }
}

/** A parsed JSON value with its half-open source range `[start, end)`. */
public sealed class JsonNode {
    public abstract val start: Int
    public abstract val end: Int
}

public class JObject(override val start: Int, override val end: Int, public val members: List<JMember>) : JsonNode()
public class JMember(public val key: JString, public val value: JsonNode)
public class JArray(override val start: Int, override val end: Int, public val items: List<JsonNode>) : JsonNode()
public class JString(override val start: Int, override val end: Int, public val value: String) : JsonNode()
public class JNum(override val start: Int, override val end: Int, public val number: JsonNumber) : JsonNode()
public class JBool(override val start: Int, override val end: Int, public val value: Boolean) : JsonNode()
public class JNull(override val start: Int, override val end: Int) : JsonNode()

/**
 * Converts a node tree to plain Kotlin values: `LinkedHashMap<String, Any?>` (insertion order kept),
 * `List<Any?>`, `String`, [JsonNumber], `Boolean`, `null`.
 */
public fun JsonNode.toValue(): Any? = when (this) {
    is JObject -> LinkedHashMap<String, Any?>().also { m -> members.forEach { m[it.key.value] = it.value.toValue() } }
    is JArray -> items.map { it.toValue() }
    is JString -> value
    is JNum -> number
    is JBool -> value
    is JNull -> null
}

private class JsonParseException(message: String) : RuntimeException(message)

/**
 * Strict JSON reader: RFC 8259 plus the `NaN`, `Infinity` and `-Infinity` literals, raw control
 * characters rejected inside strings. What *fails* to parse matters as much as what parses: a
 * rejected body falls back to the regex rewrite (`detectors/json-fallback-malformed`).
 */
public class JsonParser private constructor(private val s: String) {
    private var i = 0

    public companion object {
        /** Parses a whole document; `null` when it is not valid JSON. */
        public fun parseOrNull(text: String): JsonNode? = try {
            parse(text)
        } catch (e: JsonParseException) {
            null
        } catch (e: StackOverflowError) {
            null
        }

        private fun parse(text: String): JsonNode {
            val p = JsonParser(text)
            p.skipWs()
            val node = p.value()
            p.skipWs()
            if (p.i != text.length) throw JsonParseException("trailing data at ${p.i}")
            return node
        }
    }

    private fun skipWs() {
        while (i < s.length) {
            val c = s[i]
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++ else break
        }
    }

    private fun fail(msg: String): Nothing = throw JsonParseException("$msg at $i")

    private fun value(): JsonNode {
        if (i >= s.length) fail("unexpected end")
        return when (val c = s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> literal("true", JBool(i, i + 4, true))
            'f' -> literal("false", JBool(i, i + 5, false))
            'n' -> literal("null", JNull(i, i + 4))
            'N' -> literal("NaN", JNum(i, i + 3, JsonNumber("NaN")))
            'I' -> literal("Infinity", JNum(i, i + 8, JsonNumber("Infinity")))
            else -> if (c == '-' || c in '0'..'9') num() else fail("unexpected '$c'")
        }
    }

    private fun literal(word: String, node: JsonNode): JsonNode {
        if (!s.startsWith(word, i)) fail("bad literal")
        i += word.length
        return node
    }

    private fun obj(): JObject {
        val start = i
        i++ // {
        val members = ArrayList<JMember>()
        skipWs()
        if (i < s.length && s[i] == '}') {
            i++
            return JObject(start, i, members)
        }
        while (true) {
            skipWs()
            if (i >= s.length || s[i] != '"') fail("expected key")
            val key = str()
            skipWs()
            if (i >= s.length || s[i] != ':') fail("expected ':'")
            i++
            skipWs()
            val v = value()
            members.add(JMember(key, v))
            skipWs()
            if (i >= s.length) fail("unterminated object")
            when (s[i]) {
                ',' -> i++
                '}' -> { i++; return JObject(start, i, members) }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun arr(): JArray {
        val start = i
        i++ // [
        val items = ArrayList<JsonNode>()
        skipWs()
        if (i < s.length && s[i] == ']') {
            i++
            return JArray(start, i, items)
        }
        while (true) {
            skipWs()
            items.add(value())
            skipWs()
            if (i >= s.length) fail("unterminated array")
            when (s[i]) {
                ',' -> i++
                ']' -> { i++; return JArray(start, i, items) }
                else -> fail("expected ',' or ']'")
            }
        }
    }

    private fun str(): JString {
        val start = i
        i++ // opening quote
        val sb = StringBuilder()
        while (true) {
            if (i >= s.length) fail("unterminated string")
            val c = s[i]
            when {
                c == '"' -> { i++; return JString(start, i, sb.toString()) }
                c == '\\' -> {
                    i++
                    if (i >= s.length) fail("bad escape")
                    when (val e = s[i]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            sb.append(hex4(i + 1))
                            i += 4
                        }
                        else -> fail("bad escape '\\$e'")
                    }
                    i++
                }
                c < ' ' -> fail("control character in string")
                else -> { sb.append(c); i++ }
            }
        }
    }

    private fun hex4(at: Int): Char {
        if (at + 4 > s.length) fail("bad \\u escape")
        var v = 0
        for (k in 0 until 4) {
            val d = Character.digit(s[at + k], 16)
            if (d < 0) fail("bad \\u escape")
            v = v * 16 + d
        }
        return v.toChar()
    }

    private fun num(): JNum {
        val start = i
        if (s[i] == '-') {
            i++
            if (s.startsWith("Infinity", i)) {
                i += 8
                return JNum(start, i, JsonNumber("-Infinity"))
            }
        }
        if (i >= s.length) fail("bad number")
        if (s[i] == '0') {
            i++
        } else if (s[i] in '1'..'9') {
            while (i < s.length && s[i] in '0'..'9') i++
        } else {
            fail("bad number")
        }
        if (i < s.length && s[i] == '.') {
            i++
            if (i >= s.length || s[i] !in '0'..'9') fail("bad fraction")
            while (i < s.length && s[i] in '0'..'9') i++
        }
        if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
            i++
            if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
            if (i >= s.length || s[i] !in '0'..'9') fail("bad exponent")
            while (i < s.length && s[i] in '0'..'9') i++
        }
        return JNum(start, i, JsonNumber(s.substring(start, i)))
    }
}

/**
 * JSON writer for the value trees the engine builds itself (JWT claims, map files). Compact form
 * has no spaces after `,` or `:`; pretty form indents by 2. Non-ASCII is written as-is. Request
 * and response bodies never go through here: they are rewritten in place.
 */
public object JsonWriter {
    public fun compact(value: Any?): String = StringBuilder().also { write(it, value, null, 0) }.toString()

    public fun pretty(value: Any?, indent: Int = 2): String =
        StringBuilder().also { write(it, value, indent, 0) }.toString()

    /** A JSON string literal; only `"`, `\` and C0 controls are escaped. */
    public fun encodeString(s: String): String {
        val sb = StringBuilder(s.length + 2)
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c < ' ') sb.append("\\u").append(c.code.toString(16).padStart(4, '0')) else sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    private fun newline(sb: StringBuilder, indent: Int?, level: Int) {
        if (indent != null) {
            sb.append('\n')
            repeat(indent * level) { sb.append(' ') }
        }
    }

    private fun write(sb: StringBuilder, v: Any?, indent: Int?, level: Int) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is String -> sb.append(encodeString(v))
            is JsonNumber -> sb.append(v.raw)
            is Int, is Long, is BigInteger -> sb.append(v.toString())
            is Double -> sb.append(
                when {
                    v.isNaN() -> "NaN"
                    v == Double.POSITIVE_INFINITY -> "Infinity"
                    v == Double.NEGATIVE_INFINITY -> "-Infinity"
                    else -> FloatText.format(v)
                }
            )
            is Map<*, *> -> {
                if (v.isEmpty()) {
                    sb.append("{}")
                    return
                }
                sb.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) sb.append(',')
                    first = false
                    newline(sb, indent, level + 1)
                    sb.append(encodeString(k.toString()))
                    sb.append(if (indent == null) ":" else ": ")
                    write(sb, value, indent, level + 1)
                }
                newline(sb, indent, level)
                sb.append('}')
            }
            is Iterable<*> -> {
                val list = v.toList()
                if (list.isEmpty()) {
                    sb.append("[]")
                    return
                }
                sb.append('[')
                var first = true
                for (item in list) {
                    if (!first) sb.append(',')
                    first = false
                    newline(sb, indent, level + 1)
                    write(sb, item, indent, level + 1)
                }
                newline(sb, indent, level)
                sb.append(']')
            }
            else -> sb.append(encodeString(v.toString()))
        }
    }
}

/** Float text: shortest round-trip digits, fixed notation for 1e-4 <= |x| < 1e16, else `1e+16` form. */
public object FloatText {
    public fun format(d: Double): String {
        if (d.isNaN()) return "nan"
        if (d == Double.POSITIVE_INFINITY) return "inf"
        if (d == Double.NEGATIVE_INFINITY) return "-inf"
        val negative = d < 0 || (d == 0.0 && 1.0 / d < 0)
        val abs = Math.abs(d)
        // JDK 19+ Double.toString yields the shortest digits that round-trip.
        val bd = BigDecimal(java.lang.Double.toString(abs)).stripTrailingZeros()
        val digits = bd.unscaledValue().toString().ifEmpty { "0" }
        val decpt = if (bd.signum() == 0) 1 else digits.length - bd.scale()
        val body = if (decpt > -4 && decpt <= 16) {
            when {
                decpt <= 0 -> "0." + "0".repeat(-decpt) + digits
                decpt >= digits.length -> digits + "0".repeat(decpt - digits.length) + ".0"
                else -> digits.substring(0, decpt) + "." + digits.substring(decpt)
            }
        } else {
            val e = decpt - 1
            val mant = if (digits.length > 1) digits[0] + "." + digits.substring(1) else digits
            val expStr = (if (e < 0) "-" else "+") + Math.abs(e).toString().padStart(2, '0')
            mant + "e" + expStr
        }
        return if (negative) "-$body" else body
    }
}
