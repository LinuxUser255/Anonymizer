package com.anonymizer.engine

import java.io.ByteArrayOutputStream

/**
 * URL split/unsplit and percent-coding used by the URL mapper. Deliberate quirks, fixed by
 * `UrlsTest`: scheme lowercased, empty `?`/`#` dropped on rebuild, percent-decoding per ASCII run.
 */
internal object Urls {
    class Split(val scheme: String, val netloc: String, val path: String, val query: String, val fragment: String)

    private const val SCHEME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-."
    private val USES_NETLOC = setOf(
        "", "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp",
        "snews", "prospero", "rtsp", "rtsps", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git",
        "git+ssh", "ws", "wss", "itms-services",
    )
    private val IPV_FUTURE = Regex("v[a-fA-F0-9]+\\..+", RegexOption.DOT_MATCHES_ALL)
    private const val ALWAYS_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"

    /** Splits into scheme, netloc, path, query, fragment; throws [IllegalArgumentException] on bad brackets. */
    fun split(input: String): Split {
        var url = input.trimStart { it <= ' ' }
        url = url.replace("\t", "").replace("\r", "").replace("\n", "")
        var scheme = ""
        val colon = url.indexOf(':')
        if (colon > 0 && (url[0] in 'a'..'z' || url[0] in 'A'..'Z') && url.substring(0, colon).all { it in SCHEME_CHARS }) {
            scheme = url.substring(0, colon).lowercase()
            url = url.substring(colon + 1)
        }
        var netloc = ""
        if (url.startsWith("//")) {
            var end = url.length
            for (c in "/?#") {
                val k = url.indexOf(c, 2)
                if (k in 0 until end) end = k
            }
            netloc = url.substring(2, end)
            url = url.substring(end)
            val hasOpen = '[' in netloc
            val hasClose = ']' in netloc
            if (hasOpen != hasClose) throw IllegalArgumentException("Invalid IPv6 URL")
            if (hasOpen) {
                val host = netloc.substringAfter('[').substringBefore(']')
                if (host.startsWith("v")) {
                    if (!IPV_FUTURE.matches(host)) throw IllegalArgumentException("IPvFuture address is invalid")
                } else if (Ip.parseV6(host) == null) {
                    throw IllegalArgumentException("An IPv4 address cannot be in brackets")
                }
            }
        }
        var fragment = ""
        var query = ""
        val hash = url.indexOf('#')
        if (hash >= 0) {
            fragment = url.substring(hash + 1)
            url = url.substring(0, hash)
        }
        val q = url.indexOf('?')
        if (q >= 0) {
            query = url.substring(q + 1)
            url = url.substring(0, q)
        }
        return Split(scheme, netloc, url, query, fragment)
    }

    /** `urllib.parse.urlunsplit`. */
    fun unsplit(scheme: String, netloc: String, path: String, query: String, fragment: String): String {
        var url = path
        if (netloc.isNotEmpty()) {
            if (url.isNotEmpty() && !url.startsWith("/")) url = "/$url"
            url = "//$netloc$url"
        } else if (url.startsWith("//")) {
            url = "//$url"
        } else if (scheme.isNotEmpty() && scheme in USES_NETLOC && (url.isEmpty() || url.startsWith("/"))) {
            url = "//$url"
        }
        if (scheme.isNotEmpty()) url = "$scheme:$url"
        if (query.isNotEmpty()) url = "$url?$query"
        if (fragment.isNotEmpty()) url = "$url#$fragment"
        return url
    }

    /** `urllib.parse.unquote_plus` (UTF-8, errors="replace"). */
    fun unquotePlus(s: String): String = unquote(s.replace('+', ' '))

    /** `urllib.parse.unquote`: only ASCII runs are decoded, as bytes, then UTF-8 with replacement. */
    fun unquote(s: String): String {
        if ('%' !in s) return s
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            if (s[i].code >= 0x80) {
                sb.append(s[i])
                i++
                continue
            }
            val bytes = ByteArrayOutputStream()
            while (i < s.length && s[i].code < 0x80) {
                val c = s[i]
                if (c == '%' && i + 2 < s.length) {
                    val hi = Character.digit(s[i + 1], 16)
                    val lo = Character.digit(s[i + 2], 16)
                    if (hi >= 0 && lo >= 0) {
                        bytes.write(hi * 16 + lo)
                        i += 3
                        continue
                    }
                }
                bytes.write(c.code)
                i++
            }
            sb.append(String(bytes.toByteArray(), Charsets.UTF_8))
        }
        return sb.toString()
    }

    /** `urllib.parse.quote_plus(s, safe)`. */
    fun quotePlus(s: String, safe: String): String =
        if (' ' in s) quote(s, "$safe ").replace(' ', '+') else quote(s, safe)

    /** `urllib.parse.quote(s, safe)` with UTF-8 encoding and uppercase hex. */
    fun quote(s: String, safe: String): String {
        val sb = StringBuilder(s.length + 8)
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val v = b.toInt() and 0xFF
            val c = v.toChar()
            if (v < 0x80 && (c in ALWAYS_SAFE || c in safe)) {
                sb.append(c)
            } else {
                sb.append('%')
                sb.append("0123456789ABCDEF"[v shr 4])
                sb.append("0123456789ABCDEF"[v and 0xF])
            }
        }
        return sb.toString()
    }
}
