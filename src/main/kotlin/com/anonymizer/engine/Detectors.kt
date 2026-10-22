package com.anonymizer.engine

import kotlin.math.log2

/**
 * Regexes and small value-shape helpers.
 *
 * `java.util.regex` semantics that matter here: `(?i)`, `\w`, `\d` and `\s` are ASCII-only, so
 * detectors match ASCII shapes; non-ASCII text is left alone. Lookbehinds are all
 * single-character classes. Backtracking review: every repeated
 * group is bounded or anchored by a literal (`.`, `:`, `-`), so no nested unbounded quantifiers.
 */
public object Detectors {
    public val RE_PRIVKEY: Regex = Regex(
        "-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----",
        RegexOption.DOT_MATCHES_ALL,
    )

    /** Well-known credential formats. Each becomes `[SECRET_n]`. */
    public val DEFAULT_SECRET_PATTERNS: List<String> = listOf(
        "(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}(?![A-Za-z0-9])", // AWS key id
        "(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}", // GitHub
        "github_pat_[A-Za-z0-9_]{20,}",
        "(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}", // GitLab
        "xox[abprs]-[A-Za-z0-9-]{10,}", // Slack
        "AIza[0-9A-Za-z_-]{35}", // Google API
        "(?<![A-Za-z0-9])ya29\\.[A-Za-z0-9_-]{20,}", // Google OAuth
        "(?<![A-Za-z0-9])(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{10,}", // Stripe
        "(?<![A-Za-z0-9])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}", // OpenAI/Anthropic
        "(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}",
        "(?<![A-Za-z0-9])SG\\.[A-Za-z0-9_-]{16,}\\.[A-Za-z0-9_-]{16,}", // SendGrid
        "(?<![A-Za-z0-9])sq0(?:atp|csp)-[A-Za-z0-9_-]{20,}", // Square
        "(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])", // Twilio
        "(?<![A-Za-z0-9])\\d{8,10}:AA[A-Za-z0-9_-]{33}", // Telegram bot
        "(?<![A-Za-z0-9])EAACEdEose0cBA[A-Za-z0-9]+", // Facebook
        "(?<![A-Za-z0-9])dapi[0-9a-f]{32}", // Databricks
        "(?<![A-Za-z0-9])hvs\\.[A-Za-z0-9_-]{20,}", // Vault
    )

    public val RE_JWT: Regex = Regex("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]*")
    public val RE_URL: Regex = Regex("(?<![A-Za-z0-9])(?:https?|wss?|ftp)://[^\\s\"'<>\\\\]+", RegexOption.IGNORE_CASE)
    public val RE_EMAIL: Regex = Regex("[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,24}")
    public val RE_HOST: Regex = Regex(
        "(?<![\\w@.\\-])((?:[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.)+([a-z]{2,24}))(?![\\w\\-])",
        RegexOption.IGNORE_CASE,
    )
    public val RE_IPV4: Regex = Regex("(?<![\\d.])((?:\\d{1,3}\\.){3}\\d{1,3})(?!\\.?\\d)")
    public val RE_IPV6: Regex = Regex("(?<![:\\w])((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?![:\\w])")
    public val RE_UUID: Regex = Regex(
        "(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-fA-F])",
    )
    public val RE_CARD: Regex = Regex("(?<![\\d-])(?:\\d[ -]?){12,18}\\d(?![\\d-])")
    public val RE_SSN: Regex = Regex("(?<![\\d-])\\d{3}-\\d{2}-\\d{4}(?![\\d-])")
    public val RE_PHONE: Regex = Regex("(?<![\\w])(?:\\+\\d{1,3}[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]\\d{3}[\\s.-]\\d{4}(?![\\w])")

    /**
     * TLDs accepted when a hostname is found in free text (not in a Host header).
     * Deliberately excludes file-extension look-alikes (js, md, py, sh, pl, rs, so, ps).
     */
    public val KNOWN_TLDS: Set<String> = (
        "com net org io co uk de fr au ca us gov edu mil info biz app dev cloud ai me eu nl se no dk fi ch at " +
            "es it jp cn in br ru be ie nz za mx ar tv cc xyz tech online site store shop local internal corp lan " +
            "home localdomain intra intranet priv private ly to gg ws pro name mobi asia tel travel jobs coop aero " +
            "post bank insurance health law legal finance capital page host space website digital agency solutions " +
            "services systems network media group company global world life live news today link click top vip " +
            "pt gr cz hu ro bg hr sk si lt lv ee ua by kz tr il sa ae qa kw eg ng ke ma tn id my sg th vn ph kr tw " +
            "hk pk bd lk np cl pe ve uy bo ec cr pa do gt cu is lu li mc mt cy int"
        ).split(" ").filter { it.isNotEmpty() }.toSet()

    /** Second-level public suffixes: foo.co.uk -> base is foo.co.uk, not co.uk. */
    public val SECOND_LEVEL: Set<String> = setOf("co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go", "nom", "mil")

    public fun luhnOk(digits: String): Boolean {
        var total = 0
        val parity = digits.length % 2
        for ((i, ch) in digits.withIndex()) {
            var d = ch - '0'
            if (i % 2 == parity) {
                d *= 2
                if (d > 9) d -= 9
            }
            total += d
        }
        return total % 10 == 0
    }

    /**
     * True when [start] in [s] directly follows a product token and slash (`Chrome/`, `Edg/`,
     * `Version/`): a letter then letters, digits, `.`, `-` or `_`, at line start or after
     * whitespace, `(`, `;` or `,`. A dotted quad there is a version, not an IP. Path segments
     * (`/hosts/1.2.3.4`) do not qualify because the token is preceded by `/`.
     */
    public fun followsProductToken(s: String, start: Int): Boolean {
        if (start < 2 || s[start - 1] != '/') return false
        var j = start - 2
        while (j >= 0 && (s[j] in 'A'..'Z' || s[j] in 'a'..'z' || s[j] in '0'..'9' || s[j] in "._-")) j--
        val first = j + 1
        if (first > start - 2) return false
        if (s[first] !in 'A'..'Z' && s[first] !in 'a'..'z') return false
        return j < 0 || s[j].isWhitespace() || s[j] in "(;,"
    }

    /** Every dot-separated part parses as an int in 0..255 (leading zeros allowed). */
    public fun validIpv4(s: String): Boolean {
        for (p in s.split(".")) {
            if (p.isEmpty() || p.length > 10 || p.any { it !in '0'..'9' }) return false
            if (p.toLong() > 255) return false
        }
        return true
    }

    /** [s] is a strictly-formed IP that is private, loopback, link-local, unspecified or multicast. */
    public fun isPrivateIp(s: String): Boolean {
        Ip.parseStrictV4(s)?.let { return Ip.isPrivateV4(it) }
        Ip.parseV6(s)?.let { return Ip.isPrivateV6(it) }
        return false
    }

    public fun validIpv6(s: String): Boolean = Ip.parseV6(s) != null

    public fun entropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>()
        for (ch in s) counts[ch] = (counts[ch] ?: 0) + 1
        val n = s.length.toDouble()
        var sum = 0.0
        for (c in counts.values) {
            val p = c / n
            sum += p * log2(p)
        }
        return -sum
    }

    private val BLOB_CHARS = Regex("^[A-Za-z0-9+/=_\\-.]+$")

    /** Opaque high-entropy value (base64 token, random id) that is not a path/word. */
    public fun looksLikeBlob(s: String, minLen: Int = 20): Boolean {
        if (s.length < minLen || s.startsWith("/") || !BLOB_CHARS.matches(s)) return false
        if (!(s.any { it in '0'..'9' } && s.any { it in 'a'..'z' } && s.any { it in 'A'..'Z' })) return false
        return entropy(s) >= 3.5
    }

    public fun isBinary(text: String): Boolean {
        if ('\u0000' in text) return true
        val sample = if (text.length > 4096) text.substring(0, 4096) else text
        if (sample.isEmpty()) return false
        val bad = sample.count { it < ' ' && it != '\r' && it != '\n' && it != '\t' }
        return bad.toDouble() / sample.length > 0.05
    }
}

/** Strict IP address parsing for the private-range checks (IPv4 parts may not have leading zeros). */
internal object Ip {
    fun parseStrictV4(s: String): IntArray? {
        val parts = s.split(".")
        if (parts.size != 4) return null
        val out = IntArray(4)
        for ((i, p) in parts.withIndex()) {
            if (p.isEmpty() || p.length > 3 || p.any { it !in '0'..'9' }) return null
            if (p.length > 1 && p[0] == '0') return null
            val v = p.toInt()
            if (v > 255) return null
            out[i] = v
        }
        return out
    }

    private fun inV4(a: IntArray, b0: Int, b1: Int, b2: Int, b3: Int, bits: Int): Boolean {
        val v = (a[0].toLong() shl 24) or (a[1].toLong() shl 16) or (a[2].toLong() shl 8) or a[3].toLong()
        val n = (b0.toLong() shl 24) or (b1.toLong() shl 16) or (b2.toLong() shl 8) or b3.toLong()
        val mask = if (bits == 0) 0L else (0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL
        return (v and mask) == (n and mask)
    }

    fun isPrivateV4(a: IntArray): Boolean =
        inV4(a, 0, 0, 0, 0, 8) || inV4(a, 10, 0, 0, 0, 8) || inV4(a, 127, 0, 0, 0, 8) ||
            inV4(a, 169, 254, 0, 0, 16) || inV4(a, 172, 16, 0, 0, 12) || inV4(a, 192, 0, 0, 0, 29) ||
            inV4(a, 192, 0, 0, 170, 31) || inV4(a, 192, 0, 2, 0, 24) || inV4(a, 192, 168, 0, 0, 16) ||
            inV4(a, 198, 18, 0, 0, 15) || inV4(a, 198, 51, 100, 0, 24) || inV4(a, 203, 0, 113, 0, 24) ||
            inV4(a, 224, 0, 0, 0, 4) || inV4(a, 240, 0, 0, 0, 4) || inV4(a, 255, 255, 255, 255, 32)

    /** Returns 8 groups (16-bit each) or null. Accepts `::`, embedded IPv4 and a `%zone` suffix. */
    fun parseV6(input: String): IntArray? {
        var s = input
        val pct = s.indexOf('%')
        if (pct >= 0) {
            if (pct == s.length - 1) return null
            s = s.substring(0, pct)
        }
        if (s.isEmpty() || s.count { it == ':' } < 2) return null
        val dbl = s.indexOf("::")
        if (dbl >= 0 && s.indexOf("::", dbl + 1) >= 0) return null
        val head: List<String>
        val tail: List<String>
        if (dbl >= 0) {
            head = if (dbl == 0) emptyList() else s.substring(0, dbl).split(":")
            val t = s.substring(dbl + 2)
            tail = if (t.isEmpty()) emptyList() else t.split(":")
        } else {
            head = s.split(":")
            tail = emptyList()
        }
        val groups = ArrayList<Int>()
        fun addParts(parts: List<String>, isTail: Boolean): Boolean {
            for ((idx, p) in parts.withIndex()) {
                val last = idx == parts.size - 1
                if (p.contains('.')) {
                    if (!last) return false
                    val v4 = parseStrictV4(p) ?: return false
                    groups.add((v4[0] shl 8) or v4[1])
                    groups.add((v4[2] shl 8) or v4[3])
                    continue
                }
                if (p.isEmpty() || p.length > 4 || p.any { Character.digit(it, 16) < 0 }) return false
                groups.add(p.toInt(16))
            }
            return true
        }
        if (!addParts(head, false)) return null
        val headCount = groups.size
        if (!addParts(tail, true)) return null
        if (dbl >= 0) {
            if (groups.size > 7) return null
            val fill = 8 - groups.size
            val out = IntArray(8)
            for (i in 0 until headCount) out[i] = groups[i]
            for (i in headCount until groups.size) out[i + fill] = groups[i]
            return out
        }
        if (groups.size != 8) return null
        return groups.toIntArray()
    }

    private fun prefix(g: IntArray, bits: Int, vararg want: Int): Boolean {
        var remaining = bits
        var i = 0
        while (remaining > 0 && i < 8) {
            val take = minOf(16, remaining)
            val mask = (0xFFFF shl (16 - take)) and 0xFFFF
            val w = if (i < want.size) want[i] else 0
            if ((g[i] and mask) != (w and mask)) return false
            remaining -= take
            i++
        }
        return true
    }

    fun isPrivateV6(g: IntArray): Boolean {
        if (g.all { it == 0 }) return true // ::
        if (g.sliceArray(0 until 7).all { it == 0 } && g[7] == 1) return true // ::1
        return prefix(g, 96, 0, 0, 0, 0, 0, 0xFFFF) || // ::ffff:0:0/96
            prefix(g, 48, 0x64, 0xFF9B, 1) || // 64:ff9b:1::/48
            prefix(g, 64, 0x100) || // 100::/64
            prefix(g, 23, 0x2001) || // 2001::/23
            prefix(g, 32, 0x2001, 0xDB8) || // 2001:db8::/32
            prefix(g, 16, 0x2002) || // 2002::/16
            prefix(g, 7, 0xFC00) || // fc00::/7
            prefix(g, 10, 0xFE80) || // fe80::/10
            prefix(g, 8, 0xFF00) // ff00::/8
    }
}
