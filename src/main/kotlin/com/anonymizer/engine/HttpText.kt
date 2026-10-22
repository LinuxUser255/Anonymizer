package com.anonymizer.engine

/**
 * Splits raw HTTP text (one or more requests/responses, or plain text) into messages. A start line
 * opens a message at the top, after a blank line, or while still in headers. Every line keeps its
 * own ending and bodies stay raw, so
 * concatenating the parts gives back the input byte for byte, mixed line endings included. Shared
 * by anonymize and restore so `Content-Length` handling is identical in both directions.
 */
public object HttpText {
    public val RE_REQ_LINE: Regex = Regex("^([A-Z]{3,12}) (\\S+) (HTTP/\\d(?:\\.\\d)?)\\s*$")
    public val RE_RES_LINE: Regex = Regex("^(HTTP/\\d(?:\\.\\d)?) (\\d{3})(.*)$")

    /** One line without its terminator, and the terminator (`"\r\n"`, `"\n"`, or `""` at end of text). */
    public data class Line(val text: String, val eol: String) {
        val raw: String get() = text + eol
    }

    public class Message(
        public val start: Line,
        public val headers: List<Line>,
        /** The blank line ending the header block, or null if the text ends inside the headers. */
        public val separator: Line?,
        /** Everything after [separator] up to the next message, raw. */
        public val body: String,
    )

    public class Parsed(
        /** Raw text before the first message start (may be empty). */
        public val pre: String,
        public val messages: List<Message>,
    )

    public fun isStartLine(line: String): Boolean =
        RE_REQ_LINE.find(line) != null || RE_RES_LINE.find(line) != null

    /** Splits on `\n`, recording whether each line ended in CRLF, LF, or nothing. */
    public fun lines(text: String): List<Line> {
        val out = ArrayList<Line>()
        var i = 0
        while (i < text.length) {
            val nl = text.indexOf('\n', i)
            if (nl < 0) {
                out.add(Line(text.substring(i), ""))
                break
            }
            val cr = nl > i && text[nl - 1] == '\r'
            out.add(Line(text.substring(i, if (cr) nl - 1 else nl), if (cr) "\r\n" else "\n"))
            i = nl + 1
        }
        return out
    }

    private class Builder(val start: Line) {
        val headers = ArrayList<Line>()
        var separator: Line? = null
        val body = StringBuilder()
        fun build() = Message(start, headers.toList(), separator, body.toString())
    }

    public fun parse(text: String): Parsed {
        val msgs = ArrayList<Builder>()
        val pre = StringBuilder()
        var cur: Builder? = null
        var prevBlank = true
        for (line in lines(text)) {
            val inHeaders = cur != null && cur.separator == null
            if (isStartLine(line.text) && (cur == null || inHeaders || prevBlank)) {
                cur = Builder(line)
                msgs.add(cur)
                prevBlank = false
                continue
            }
            when {
                cur == null -> pre.append(line.raw)
                inHeaders -> if (line.text.isBlank()) cur.separator = line else cur.headers.add(line)
                else -> cur.body.append(line.raw)
            }
            prevBlank = line.text.isBlank()
        }
        return Parsed(pre.toString(), msgs.map { it.build() })
    }

    /**
     * Applies [f] to [s] with LF line endings when every line break in [s] is CRLF, then converts
     * back; otherwise applies [f] to [s] as-is. Detectors written against `\n` work on CRLF text, and
     * mixed line endings survive untouched.
     */
    public fun withLf(s: String, f: (String) -> String): String {
        var lf = 0
        var crlf = 0
        for (i in s.indices) {
            if (s[i] != '\n') continue
            lf++
            if (i > 0 && s[i - 1] == '\r') crlf++
        }
        if (crlf == 0 || crlf != lf) return f(s)
        return f(s.replace("\r\n", "\n")).replace("\n", "\r\n")
    }

    /** UTF-8 byte length, lone surrogates counted as the replacement character (3 bytes). */
    public fun utf8Length(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c.code < 0x80 -> n += 1
                c.code < 0x800 -> n += 2
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                    n += 4
                    i++
                }
                else -> n += 3
            }
            i++
        }
        return n
    }

    /** Rewrites every `Content-Length` header (case-insensitive) to the byte length of [body]. */
    public fun fixContentLength(headers: List<String>, body: String): List<String> {
        val n = utf8Length(body)
        return headers.map { h -> if (h.lowercase().startsWith("content-length:")) "Content-Length: $n" else h }
    }
}
