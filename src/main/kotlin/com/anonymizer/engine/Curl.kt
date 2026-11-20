package com.anonymizer.engine

/**
 * Formats raw HTTP request text as a `curl` command for bash, in the style of Burp's "Copy as curl
 * command (bash)". It is a formatter, not a detector: it is fed text that is already anonymized,
 * so placeholders pass through untouched and Restore turns the command back into the real one.
 *
 * The target URL is built only from what is in the text (an absolute request target, or the `Host`
 * header), never from the item's real service, so a real hostname cannot leak into the command.
 */
public object Curl {
    /**
     * The curl command for the first request in [httpText], or null when the text does not start
     * with a request line or has neither an absolute target nor a `Host` header. [secure] picks
     * `https` over `http` when the target is not absolute.
     *
     * `Content-Length` is dropped (curl computes it, and a pinned length would be wrong once
     * placeholders are restored); `Host` is dropped because the URL carries it.
     */
    public fun fromRequest(httpText: String, secure: Boolean): String? {
        val parsed = HttpText.parse(httpText)
        val m = parsed.messages.firstOrNull() ?: return null
        if (parsed.pre.isNotBlank()) return null
        val line = HttpText.RE_REQ_LINE.find(m.start.text) ?: return null
        val method = line.groupValues[1]
        val target = line.groupValues[2]

        var host: String? = null
        val args = ArrayList<String>()
        for (h in m.headers.map { it.text }) {
            val colon = h.indexOf(':')
            if (colon <= 0) continue // continuation or junk line: not expressible as -H
            val name = h.substring(0, colon).trim()
            val value = h.substring(colon + 1).trim()
            when (name.lowercase()) {
                "host" -> host = host ?: value
                "content-length" -> Unit
                // curl only sends a header with no value when it is written "Name;"
                else -> args.add("-H " + quote(if (value.isEmpty()) "$name;" else "$name: $value"))
            }
        }

        val url = if ("://" in target) {
            target
        } else {
            val h = host?.takeIf { it.isNotEmpty() } ?: return null
            (if (secure) "https://" else "http://") + h + target
        }

        // The body is everything after the header block, even if a later line looks like a start line.
        val sep = m.separator
        val body = if (sep == null) "" else httpText.substring(
            parsed.pre.length + m.start.raw.length + m.headers.sumOf { it.raw.length } + sep.raw.length,
        )
        if (body.isNotEmpty()) args.add("--data-binary " + quote(body))
        args.add(quote(url))

        // -X HEAD makes curl wait for a body that never comes; --head is the working spelling.
        val first = "curl --path-as-is -i -s -k " + (if (method == "HEAD") "--head" else "-X " + quote(method))
        return (listOf(first) + args).joinToString(" \\\n    ")
    }

    /** Bash ANSI-C quoting (`$'...'`): the only form that can carry CR, LF and quotes on one line. */
    public fun quote(s: String): String {
        val sb = StringBuilder(s.length + 8).append("$'")
        for (c in s) {
            when {
                c == '\\' -> sb.append("\\\\")
                c == '\'' -> sb.append("\\'")
                c == '\r' -> sb.append("\\r")
                c == '\n' -> sb.append("\\n")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 || c.code == 0x7F -> sb.append("\\x").append(c.code.toString(16).padStart(2, '0'))
                else -> sb.append(c)
            }
        }
        return sb.append('\'').toString()
    }
}
