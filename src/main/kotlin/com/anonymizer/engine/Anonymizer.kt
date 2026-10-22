package com.anonymizer.engine

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Base64

/**
 * The pseudonymisation engine.
 *
 * Three layers, applied in order of specificity: structured handlers (request line, headers,
 * cookies, JSON/form/multipart bodies) that know which values are secrets by position or key name;
 * shape-aware mappers (hosts, URLs, emails, IPs, UUIDs, JWTs) that keep the value's shape; and a
 * generic text pass (secret formats, hex, cards, SSNs, phones, client terms) over what is left.
 *
 * Every replacement goes through [Mapping], so a value maps to one placeholder and the output is
 * reversible. Byte-identical except for replacements: JSON bodies are rewritten in place
 * (whitespace, escapes and key order survive) and line endings are kept per line.
 *
 * Not thread-safe; the extension drives one instance per call on its single engine thread.
 */
public class Anonymizer(private val settings: Settings, private val mapping: Mapping) {
    private val stats: LinkedHashMap<String, Int> = LinkedHashMap()
    private val keepHosts: Set<String> = settings.keepHosts.map { it.lowercase() }.toSet()
    private val keepBaseHosts: Set<String> = settings.keepBaseHosts.map { it.lowercase() }.toSet()
    private val genericLabels: Set<String> = settings.genericLabels.toSet()
    private val sensitiveHeaders: Set<String> = settings.sensitiveHeaders.map { it.lowercase() }.toSet()
    private val sensitiveHeaderSubs: List<String> = settings.sensitiveHeaderSubstrings.map { it.lowercase() }
    private val nonsensitiveHeaders: Set<String> = settings.nonsensitiveHeaders.map { it.lowercase() }.toSet()
    private val keySubs: List<String> = settings.sensitiveKeySubstrings.map { normKey(it) }
    private val keyExact: Set<String> = settings.sensitiveKeysExact.map { normKey(it) }.toSet()
    private val keyNonsens: Set<String> = settings.nonsensitiveKeys.map { normKey(it) }.toSet()
    private val keepCookies: Set<String> = settings.keepCookies.map { it.lowercase() }.toSet()
    private val keepPrivateIps: Boolean = settings.keepPrivateIps
    private val reHex: Regex = Regex("(?<![0-9A-Za-z])[0-9a-fA-F]{${settings.minHexLen},}(?![0-9A-Za-z])")
    private val secretRes: List<Regex> = (Detectors.DEFAULT_SECRET_PATTERNS + settings.secretPatterns)
        .mapNotNull { p -> runCatching { Regex(p) }.getOrNull() }
    private val termsRe: Regex? = run {
        val terms = settings.terms.filter { it.isNotBlank() }.distinct().sortedByDescending { it.length }
        if (terms.isEmpty()) null
        else Regex("(?<![A-Za-z0-9])(?:" + terms.joinToString("|") { Regex.escape(it) } + ")(?![A-Za-z0-9])", RegexOption.IGNORE_CASE)
    }

    /** [fn] gets the text being scanned as well as the match, for detectors that look at context. */
    private class Step(val name: String, val regex: Regex, val fn: (String, MatchResult) -> String)

    /** Ordered free-text detector pipeline; order is load-bearing (email before host). */
    private val textPipeline: List<Step> = listOf(
        Step("email", Detectors.RE_EMAIL) { _, m -> email(m.value) },
        Step("host", Detectors.RE_HOST) { _, m -> host(m.value, strict = true) },
        Step("ipv4", Detectors.RE_IPV4) { s, m ->
            if (Detectors.followsProductToken(s, m.range.first)) m.value else ipv4(m.value)
        },
        Step("ipv6", Detectors.RE_IPV6) { _, m -> ipv6(m.value) },
        Step("uuid", Detectors.RE_UUID) { _, m -> uuid(m.value) },
        Step("hex", reHex) { _, m -> ph("hex", m.value, "HEX") },
        Step("card", Detectors.RE_CARD) { _, m -> card(m.value) },
        Step("ssn", Detectors.RE_SSN) { _, m -> ph("ssn", m.value, "SSN") },
        Step("phone", Detectors.RE_PHONE) { _, m -> ph("phone", m.value, "PHONE") },
    )

    /** Replacement counts by label, for a one-line summary. */
    public val summary: Map<String, Int>
        get() = stats.toMap()

    // ------------------------------------------------------------------ utils

    private fun bump(label: String) {
        stats[label] = (stats[label] ?: 0) + 1
    }

    /** Generic bracketed placeholder: `[LABEL_n]`. */
    private fun ph(category: String, value: String, label: String): String {
        val out = mapping.get(category, value) { n -> "[${label}_$n]" }
        if (out != value) bump(label)
        return out
    }

    private fun on(name: String): Boolean = settings.isOn(name)

    public fun isSensitiveKey(key: String): Boolean {
        val k = normKey(key)
        if (k.isEmpty() || k in keyNonsens) return false
        if (k in keyExact || k.endsWith("key")) return true
        return keySubs.any { it in k }
    }

    // ------------------------------------------------------------ shape maps

    /**
     * Pseudonymises a hostname, keeping generic subdomains and the TLD shape.
     * [strict] (free-text context) only maps names with a known TLD.
     */
    public fun host(h: String, strict: Boolean = false): String {
        val raw = h
        val hl = h.lowercase().trimEnd('.')
        if (hl.isEmpty() || mapping.isPlaceholder(hl) || hl.endsWith(".example")) return raw
        if (hl == "localhost" || hl in keepHosts) return raw
        if (keepHosts.any { hl.endsWith(".$it") }) return raw
        val labels = hl.split(".")
        if (labels.size == 1) return if (strict) raw else hostBase(hl)
        val tld = labels.last()
        if (strict && tld !in Detectors.KNOWN_TLDS) return raw
        if (!TLD_SHAPE.matches(tld)) return raw // IPs and the like are handled elsewhere
        var baseN = 2
        if (labels.size >= 3 && labels[labels.size - 2] in Detectors.SECOND_LEVEL && tld.length == 2) baseN = 3
        val base = labels.takeLast(baseN).joinToString(".")
        val subs = labels.dropLast(baseN)
        val basePh = if (base in keepBaseHosts || keepBaseHosts.any { base.endsWith(".$it") }) base else hostBase(base)
        val out = ArrayList<String>(subs.size + 1)
        for (lab in subs) {
            if (lab in genericLabels || GENERIC_SUB.matches(lab)) {
                out.add(lab)
            } else {
                val p = mapping.get("sub", lab) { n -> "sub$n" }
                if (p != lab) bump("SUB")
                out.add(p)
            }
        }
        out.add(basePh)
        return out.joinToString(".")
    }

    private fun hostBase(base: String): String {
        val p = mapping.get("host", base) { n -> "target$n.example" }
        if (p != base) bump("HOST")
        return p
    }

    public fun email(e: String): String {
        if (mapping.isPlaceholder(e)) return e
        val at = e.lastIndexOf('@')
        val dom = if (at >= 0) e.substring(at + 1) else e
        val domPh = host(dom)
        val key = e.lowercase()
        val p = mapping.get("email", key) { n -> "user$n@$domPh" }
        if (p != key) bump("EMAIL")
        return p
    }

    public fun ipv4(ip: String): String {
        if (mapping.isPlaceholder(ip) || !Detectors.validIpv4(ip)) return ip
        if (ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "255.255.255.255") return ip
        if (keepPrivateIps && Detectors.isPrivateIp(ip)) return ip
        if (ip.startsWith("192.0.2.") || ip.startsWith("198.51.100.") || ip.startsWith("203.0.113.")) return ip
        val p = mapping.get("ip", ip) { n ->
            val i = n - 1
            if (i >= 254 * 3) "[IP_$n]" else IP_BLOCKS[i / 254] + (i % 254 + 1)
        }
        if (p != ip) bump("IP")
        return p
    }

    public fun ipv6(ip: String): String {
        if (mapping.isPlaceholder(ip) || !Detectors.validIpv6(ip)) return ip
        val low = ip.lowercase()
        if (low == "::" || low == "::1" || low.startsWith("2001:db8:")) return ip
        if (keepPrivateIps && Detectors.isPrivateIp(ip)) return ip
        val p = mapping.get("ip6", low) { n -> "2001:db8::" + n.toString(16) }
        if (p != low) bump("IP6")
        return p
    }

    public fun uuid(u: String): String {
        val low = u.lowercase()
        if (mapping.isPlaceholder(low) || low.startsWith("00000000-0000-4000-8000-")) return u
        val p = mapping.get("uuid", low) { n -> "00000000-0000-4000-8000-" + n.toString().padStart(12, '0') }
        if (p != low) bump("UUID")
        return p
    }

    /**
     * Replaces a JWT with a synthetic one: header kept (minus `kid`), claims anonymised with the
     * normal rules, signature replaced.
     */
    public fun jwt(tok: String): String {
        if (mapping.isPlaceholder(tok)) return tok
        val p = mapping.get("jwt", tok) { n -> makeJwt(tok, n) }
        if (p != tok) bump("JWT")
        return p
    }

    private fun makeJwt(tok: String, n: Int): String {
        val segs = tok.split(".")
        val hdrNode = decodeJwtSegment(segs.getOrNull(0)) ?: return "[JWT_$n]"
        val payNode = decodeJwtSegment(segs.getOrNull(1)) ?: return "[JWT_$n]"
        val hdr = hdrNode.toValue()
        val pay = payNode.toValue()
        if (hdr is MutableMap<*, *>) {
            @Suppress("UNCHECKED_CAST")
            val h = hdr as MutableMap<String, Any?>
            if (h.containsKey("kid")) h["kid"] = ph("field:KID", scalarStr(h["kid"]), "KID")
            if (h.containsKey("jku")) h["jku"] = text(scalarStr(h["jku"]))
        }
        val newPay = jsonValue(pay, null)
        return b64e(JsonWriter.compact(hdr)) + "." + b64e(JsonWriter.compact(newPay)) + ".REDACTED_SIGNATURE_" + n
    }

    private fun decodeJwtSegment(seg: String?): JsonNode? {
        if (seg == null) return null
        val bytes = try {
            Base64.getUrlDecoder().decode(seg)
        } catch (e: IllegalArgumentException) {
            return null
        }
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (e: CharacterCodingException) {
            return null
        }
        return JsonParser.parseOrNull(text)
    }

    private fun b64e(s: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray(Charsets.UTF_8))

    /** A decoded JSON value as mapping text: strings bare, numbers canonical, the rest as JSON. */
    private fun scalarStr(v: Any?): String = when (v) {
        is String -> v
        is JsonNumber -> v.canonicalStr()
        else -> JsonWriter.compact(v)
    }

    public fun url(input: String): String {
        if (mapping.isPlaceholder(input)) return input
        var u = input
        var trail = ""
        while (u.isNotEmpty() && u.last() in ".,;:)]}'\"") {
            trail = u.last() + trail
            u = u.substring(0, u.length - 1)
        }
        val parts = try {
            Urls.split(u)
        } catch (e: IllegalArgumentException) {
            return textNoUrl(u) + trail
        }
        val netloc = parts.netloc
        val at = netloc.lastIndexOf('@')
        var userinfo = if (at >= 0) netloc.substring(0, at) else ""
        var hostport = if (at >= 0) netloc.substring(at + 1) else netloc
        if (hostport.startsWith("[")) {
            val close = hostport.indexOf(']')
            val host6 = hostport.substring(1, close)
            val rest = hostport.substring(close + 1)
            hostport = "[" + ipv6(host6) + "]" + rest
        } else {
            val colon = hostport.indexOf(':')
            var hostName = if (colon >= 0) hostport.substring(0, colon) else hostport
            val port = if (colon >= 0) hostport.substring(colon + 1) else ""
            if (Detectors.RE_IPV4.matches(hostName)) {
                hostName = ipv4(hostName)
            } else if (hostName.isNotEmpty()) {
                hostName = host(hostName)
            }
            hostport = hostName + (if (port.isNotEmpty()) ":$port" else "")
        }
        if (userinfo.isNotEmpty()) userinfo = ph("userinfo", userinfo, "USERINFO") + "@"
        val path = if (parts.path.isNotEmpty()) textNoUrl(parts.path) else parts.path
        val query = if (parts.query.isNotEmpty()) params(parts.query) else parts.query
        var frag = parts.fragment
        if (frag.isNotEmpty()) frag = if ('=' in frag) params(frag) else textNoUrl(frag)
        return Urls.unsplit(parts.scheme, userinfo + hostport, path, query, frag) + trail
    }

    /** `key=value&key2=value2` (query strings, form bodies, fragments). */
    public fun params(qs: String): String {
        val out = ArrayList<String>()
        for (pair in qs.split("&")) {
            val eq = pair.indexOf('=')
            if (eq < 0) {
                out.add(reencode(pair, value(Urls.unquotePlus(pair))))
                continue
            }
            val k = pair.substring(0, eq)
            val v = pair.substring(eq + 1)
            val kd = Urls.unquotePlus(k)
            val vd = Urls.unquotePlus(v)
            val nv = value(vd, kd)
            out.add(text(k) + "=" + reencode(v, nv))
        }
        return out.joinToString("&")
    }

    private fun reencode(raw: String, new: String): String {
        val decoded = Urls.unquotePlus(raw)
        if (new == decoded) return raw
        if ('%' in raw || '+' in raw) return Urls.quotePlus(new, "[]")
        return new
    }

    // ------------------------------------------------------------ value pass

    /** Exact-shape mappers for a whole value; null if no shape matched. */
    private fun shape(v: String): String? {
        val s = v.trim()
        if (Detectors.RE_JWT.matches(s)) return jwt(s)
        if (Detectors.RE_EMAIL.matches(s)) return email(s)
        if (Detectors.RE_URL.matches(s)) return url(s)
        if (Detectors.RE_IPV4.matches(s)) return ipv4(s)
        if (Detectors.RE_UUID.matches(s)) return uuid(s)
        if (Detectors.validIpv6(s) && ':' in s) return ipv6(s)
        if (Detectors.RE_HOST.matches(s)) return host(s)
        return null
    }

    /** Anonymises a leaf value (JSON string, form field, cookie...). */
    public fun value(v: String, key: String? = null): String {
        if (v.isEmpty() || mapping.isPlaceholder(v)) return v
        if (key != null && on("fields") && isSensitiveKey(key)) {
            val shaped = shape(v)
            if (shaped != null && shaped != v) return shaped
            val lab = label(key)
            return ph("field:$lab", v, lab)
        }
        val out = text(v)
        if (out != v) return out
        if (on("blob") && Detectors.looksLikeBlob(v)) return ph("blob", v, "BLOB")
        return v
    }

    // ------------------------------------------------------------- text pass

    /** Generic detectors over free text. */
    public fun text(input: String): String {
        if (input.isEmpty() || mapping.isPlaceholder(input)) return input
        var s = input
        if (on("secrets")) {
            s = Detectors.RE_PRIVKEY.replace(s) { m -> ph("secret", m.value, "PRIVATE_KEY") }
            for (rx in secretRes) s = rx.replace(s) { m -> ph("secret", m.value, "SECRET") }
        }
        if (on("jwt")) s = Detectors.RE_JWT.replace(s) { m -> jwt(m.value) }
        if (on("url")) s = Detectors.RE_URL.replace(s) { m -> url(m.value) }
        return textNoUrl(s)
    }

    private fun textNoUrl(input: String): String {
        if (input.isEmpty()) return input
        var s = input
        for (step in textPipeline) {
            if (!on(step.name)) continue
            val input = s
            s = step.regex.replace(input) { m -> step.fn(input, m) }
        }
        val tr = termsRe
        if (on("terms") && tr != null) s = tr.replace(s) { m -> term(m.value) }
        return s
    }

    private fun card(match: String): String {
        val digits = match.filter { it in '0'..'9' }
        if (digits.length in 13..19 && Detectors.luhnOk(digits)) return ph("card", match, "CARD")
        return match
    }

    private fun term(word: String): String {
        val low = word.lowercase()
        val p = mapping.get("term", low) { n -> "[CLIENT_$n]" }
        if (p != low) bump("CLIENT")
        return p
    }

    // ----------------------------------------------------------- structured

    /** Field rules over a decoded value tree (used for JWT claims, which are re-encoded). */
    private fun jsonValue(obj: Any?, parentKey: String?): Any? = when (obj) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out ->
            for ((k, v) in obj) {
                val ks = k.toString()
                out[text(ks)] = jsonValue(v, ks)
            }
        }
        is List<*> -> obj.map { jsonValue(it, parentKey) }
        is String -> value(obj, parentKey)
        is Boolean, null -> obj
        is JsonNumber -> if (parentKey != null && isSensitiveKey(parentKey)) value(obj.canonicalStr(), parentKey) else obj
        else -> obj
    }

    private class Edit(val start: Int, val end: Int, val replacement: String)

    /** In-place JSON rewrite: only string/number tokens that change are touched. */
    public fun jsonBody(body: String): String {
        val node = JsonParser.parseOrNull(body) ?: return jsonFallback(body)
        if (node !is JObject && node !is JArray) return text(body)
        val edits = ArrayList<Edit>()
        collectJsonEdits(node, null, edits)
        if (edits.isEmpty()) return body
        val sb = StringBuilder(body.length + 64)
        var pos = 0
        for (e in edits) {
            sb.append(body, pos, e.start)
            sb.append(e.replacement)
            pos = e.end
        }
        sb.append(body, pos, body.length)
        return sb.toString()
    }

    private fun collectJsonEdits(node: JsonNode, parentKey: String?, edits: MutableList<Edit>) {
        when (node) {
            is JObject -> for (m in node.members) {
                val k = m.key.value
                val nk = text(k)
                if (nk != k) edits.add(Edit(m.key.start, m.key.end, JsonWriter.encodeString(nk)))
                collectJsonEdits(m.value, k, edits)
            }
            is JArray -> for (item in node.items) collectJsonEdits(item, parentKey, edits)
            is JString -> {
                val nv = value(node.value, parentKey)
                if (nv != node.value) edits.add(Edit(node.start, node.end, JsonWriter.encodeString(nv)))
            }
            is JNum -> if (parentKey != null && on("fields") && isSensitiveKey(parentKey)) {
                val nv = value(node.number.canonicalStr(), parentKey)
                edits.add(Edit(node.start, node.end, JsonWriter.encodeString(nv)))
            }
            is JBool, is JNull -> Unit
        }
    }

    private fun jsonFallback(body: String): String {
        val rewritten = RE_JSON_KV.replace(body) { m ->
            val key = m.groupValues[1]
            val v = m.groupValues[2]
            if (v.startsWith("\"")) {
                val inner = v.substring(1, v.length - 1)
                val dec = (JsonParser.parseOrNull(v) as? JString)?.value ?: inner
                val nv = value(dec, key)
                if (nv == dec) m.value else "\"" + key + "\":" + JsonWriter.encodeString(nv)
            } else if (on("fields") && isSensitiveKey(key)) {
                "\"" + key + "\":\"" + value(v, key) + "\""
            } else {
                m.value
            }
        }
        return text(rewritten)
    }

    public fun formBody(body: String): String {
        val core = body.trim('\r', '\n')
        val trailing = body.substring(body.trimEnd('\r', '\n').length)
        return params(core) + trailing
    }

    public fun multipartBody(body: String, boundary: String): String {
        val delim = "--$boundary"
        val pieces = body.split(delim).toMutableList()
        if (pieces.size < 3) return textBody(body)
        for (i in 1 until pieces.size - 1) {
            val piece = pieces[i]
            val sep = piece.indexOf("\n\n")
            if (sep < 0) {
                pieces[i] = text(piece)
                continue
            }
            val head = piece.substring(0, sep)
            val content = piece.substring(sep + 2)
            val name = RE_PART_NAME.find(head)?.groupValues?.get(1)
            val isFile = RE_PART_FILENAME.containsMatchIn(head)
            val core = content.trimEnd('\r', '\n')
            val trailing = content.substring(core.length)
            val new = if (isFile) {
                if (Detectors.isBinary(core)) "[binary file content omitted, ${HttpText.utf8Length(core)} bytes]"
                else textBody(core)
            } else {
                if (core.isNotEmpty()) value(core, name) else core
            }
            pieces[i] = text(head) + "\n\n" + new + trailing
        }
        return pieces.joinToString(delim)
    }

    /** Any text body: XML/HTML field rules, then the generic pass. */
    public fun textBody(input: String): String {
        if (Detectors.isBinary(input)) return "[binary body omitted, ${HttpText.utf8Length(input)} bytes]"
        var body = input
        body = RE_XML_ELEM.replace(body) { m ->
            val tag = m.groupValues[1].substringAfterLast(':')
            if (on("fields") && isSensitiveKey(tag)) {
                "<" + m.groupValues[1] + m.groupValues[2] + ">" + value(m.groupValues[3].trim(), tag) + "</" + m.groupValues[1] + ">"
            } else {
                m.value
            }
        }
        body = RE_HTML_INPUT.replace(body) { m ->
            if (on("fields") && isSensitiveKey(m.groupValues[2]) && m.groupValues[3].isNotEmpty()) {
                m.groupValues[1] + value(m.groupValues[3], m.groupValues[2]) + m.groupValues[4]
            } else {
                m.value
            }
        }
        body = RE_HTML_INPUT_REV.replace(body) { m ->
            if (on("fields") && isSensitiveKey(m.groupValues[4]) && m.groupValues[2].isNotEmpty()) {
                m.groupValues[1] + value(m.groupValues[2], m.groupValues[4]) + m.groupValues[3]
            } else {
                m.value
            }
        }
        if ('{' in body) { // inline JSON (script blocks, JSONP, JSON in HTML)
            body = RE_JSON_KV.replace(body) { m -> jsonFallback(m.value) }
        }
        return text(body)
    }

    // --------------------------------------------------------------- headers

    public fun cookieHeader(value: String): String {
        val out = ArrayList<String>()
        for (part in value.split(";")) {
            val eq = part.indexOf('=')
            if (eq < 0) {
                out.add(text(part))
                continue
            }
            val name = part.substring(0, eq)
            val v = part.substring(eq + 1)
            val lead = name.substring(0, name.length - name.trimStart().length)
            val n = name.trim()
            val vs = v.trim()
            if (n.lowercase() in keepCookies || vs.isEmpty() || !on("cookies")) {
                out.add(lead + n + "=" + v)
            } else {
                out.add(lead + text(n) + "=" + cookieValue(vs))
            }
        }
        return out.joinToString(";")
    }

    private fun cookieValue(v: String): String {
        val shaped = shape(v)
        if (shaped != null && shaped != v) return shaped
        return ph("cookie", v, "COOKIE")
    }

    public fun setCookieHeader(value: String): String {
        val semi = value.indexOf(';')
        var first = if (semi >= 0) value.substring(0, semi) else value
        val sep = if (semi >= 0) ";" else ""
        var rest = if (semi >= 0) value.substring(semi + 1) else ""
        val eq = first.indexOf('=')
        if (eq >= 0) {
            val name = first.substring(0, eq)
            val v = first.substring(eq + 1)
            first = if (name.trim().lowercase() in keepCookies || v.isBlank() || !on("cookies")) {
                "$name=$v"
            } else {
                text(name) + "=" + cookieValue(v.trim())
            }
        }
        rest = RE_COOKIE_DOMAIN.replace(rest) { m -> m.groupValues[1] + m.groupValues[2] + host(m.groupValues[3]) }
        return first + sep + text(rest)
    }

    public fun authHeader(value: String): String {
        val stripped = value.trim()
        if (!on("auth")) return text(stripped)
        val sp = stripped.indexOf(' ')
        if (sp < 0) return ph("token", stripped, "TOKEN")
        val scheme = stripped.substring(0, sp)
        val cred = stripped.substring(sp + 1).trim()
        if (Detectors.RE_JWT.matches(cred)) return scheme + " " + jwt(cred)
        if (scheme.lowercase() == "basic") return scheme + " " + ph("basic", cred, "BASIC")
        return scheme + " " + ph("token", cred, "TOKEN")
    }

    public fun header(name: String, value: String): String {
        val n = name.trim().lowercase()
        val v = value.trim()
        val lead = value.substring(0, value.length - value.trimStart().length)
        if (v.isEmpty()) return value
        if (n == "authorization" || n == "proxy-authorization") return lead + authHeader(v)
        if (n == "cookie") return lead + cookieHeader(v)
        if (n == "set-cookie") return lead + setCookieHeader(v)
        if (n == "host") {
            var hostName = v
            var port = ""
            if (RE_PORT_SUFFIX.containsMatchIn(v)) {
                val colon = v.lastIndexOf(':')
                hostName = v.substring(0, colon)
                port = v.substring(colon + 1)
            }
            hostName = if (Detectors.RE_IPV4.matches(hostName)) ipv4(hostName) else host(hostName)
            return lead + hostName + (if (port.isNotEmpty()) ":$port" else "")
        }
        if (on("headers") && (n in sensitiveHeaders || (n !in nonsensitiveHeaders && sensitiveHeaderSubs.any { it in n }))) {
            val shaped = shape(v)
            if (shaped != null && shaped != v) return lead + shaped
            return lead + ph("header:$n", v, label(n))
        }
        return lead + text(v)
    }

    // -------------------------------------------------------------- messages

    /** Anonymises raw HTTP text (one or more requests/responses, or plain text). */
    public fun anonymize(text: String): String {
        val parsed = HttpText.parse(text)
        if (parsed.messages.isEmpty()) return HttpText.withLf(text) { plain(it) }
        val sb = StringBuilder(text.length)
        if (parsed.pre.isNotEmpty()) {
            // pre always ends in the line break before the first start line; keep it out of plain()
            val eol = if (parsed.pre.endsWith("\r\n")) "\r\n" else "\n"
            sb.append(HttpText.withLf(parsed.pre.removeSuffix(eol)) { plain(it) }).append(eol)
        }
        for (m in parsed.messages) sb.append(message(m))
        return sb.toString()
    }

    public fun plain(text: String): String {
        val stripped = text.trim()
        if (looksLikeJson(stripped) && JsonParser.parseOrNull(stripped) != null) {
            val lead = text.substring(0, text.length - text.trimStart().length)
            val trail = text.substring(text.trimEnd().length)
            return lead + jsonBody(stripped) + trail
        }
        return textBody(text)
    }

    private fun looksLikeJson(stripped: String): Boolean =
        stripped.isNotEmpty() && stripped[0] in "{[" && stripped.last() in "}]"

    private fun message(m: HttpText.Message): String {
        var start = m.start.text
        val rm = HttpText.RE_REQ_LINE.find(start)
        if (rm != null) {
            val method = rm.groupValues[1]
            var target = rm.groupValues[2]
            val ver = rm.groupValues[3]
            target = if ("://" in target) {
                url(target)
            } else {
                val q = target.indexOf('?')
                val path = if (q >= 0) target.substring(0, q) else target
                val qs = if (q >= 0) target.substring(q + 1) else ""
                textNoUrl(path) + (if (q >= 0) "?" else "") + (if (qs.isNotEmpty()) params(qs) else "")
            }
            start = "$method $target $ver"
        } else {
            start = text(start)
        }

        var headers = ArrayList<String>(m.headers.size)
        val hdrMap = HashMap<String, String>()
        for (h in m.headers.map { it.text }) {
            if (':' !in h || h[0] == ' ' || h[0] == '\t') {
                headers.add(text(h))
                continue
            }
            val colon = h.indexOf(':')
            val name = h.substring(0, colon)
            val value = h.substring(colon + 1)
            hdrMap[name.trim().lowercase()] = value.trim()
            headers.add(name + ":" + header(name, value))
        }

        val body = m.body
        var newBody = body
        if (body.isNotBlank()) {
            val core = body.trimEnd('\r', '\n')
            val trailing = body.substring(core.length)
            val newCore = HttpText.withLf(core) { bodyOf(it, hdrMap) }
            newBody = newCore + trailing
            if (newCore != core && settings.updateContentLength) {
                headers = ArrayList(HttpText.fixContentLength(headers, newCore))
            }
        }
        val sb = StringBuilder(start).append(m.start.eol)
        for ((i, h) in headers.withIndex()) sb.append(h).append(m.headers[i].eol)
        m.separator?.let { sb.append(it.raw) }
        return sb.append(newBody).toString()
    }

    private fun bodyOf(body: String, hdrMap: Map<String, String>): String {
        val ctype = (hdrMap["content-type"] ?: "").lowercase()
        val stripped = body.trim()
        if ("json" in ctype || (ctype.isEmpty() && looksLikeJson(stripped))) return jsonBody(body)
        if ("x-www-form-urlencoded" in ctype) return formBody(body)
        if ("multipart/" in ctype) {
            val bm = RE_BOUNDARY.find(ctype)
            if (bm != null) return multipartBody(body, bm.groupValues[1])
        }
        if (ctype.isEmpty() && '\n' !in stripped && RE_BARE_FORM.matches(stripped)) return formBody(body)
        if ("json" !in ctype && looksLikeJson(stripped) && JsonParser.parseOrNull(stripped) != null) return jsonBody(body)
        return textBody(body)
    }

    private companion object {
        val RE_JSON_KV: Regex = Regex("\"((?:[^\"\\\\]|\\\\.){1,80})\"\\s*:\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|-?\\d+(?:\\.\\d+)?)")
        val RE_XML_ELEM: Regex = Regex("<([A-Za-z_][\\w:.\\-]*)((?:\\s[^<>]*)?)>([^<]+)</\\1\\s*>")
        val RE_HTML_INPUT: Regex = Regex(
            "(<input\\b[^>]*\\bname\\s*=\\s*[\"']([^\"']+)[\"'][^>]*\\bvalue\\s*=\\s*[\"'])([^\"']*)([\"'])",
            RegexOption.IGNORE_CASE,
        )
        val RE_HTML_INPUT_REV: Regex = Regex(
            "(<input\\b[^>]*\\bvalue\\s*=\\s*[\"'])([^\"']*)([\"'][^>]*\\bname\\s*=\\s*[\"']([^\"']+)[\"'])",
            RegexOption.IGNORE_CASE,
        )
        val RE_COOKIE_DOMAIN: Regex = Regex("(;\\s*domain=)(\\.?)([^;\\s]+)", RegexOption.IGNORE_CASE)
        val RE_PART_NAME: Regex = Regex("name=\"([^\"]*)\"", RegexOption.IGNORE_CASE)
        val RE_PART_FILENAME: Regex = Regex("filename=\"", RegexOption.IGNORE_CASE)
        val RE_BOUNDARY: Regex = Regex("boundary=\"?([^\";,\\s]+)\"?")
        val RE_BARE_FORM: Regex = Regex("[^=&\\s]+=[^&\\s]*(?:&[^=&\\s]+=[^&\\s]*)*")
        val RE_PORT_SUFFIX: Regex = Regex(":\\d+$")
        val TLD_SHAPE: Regex = Regex("[a-z]{2,24}")
        val GENERIC_SUB: Regex = Regex("(?:v\\d+|\\d+|[a-z]{1,2}\\d{0,2})")
        val IP_BLOCKS: List<String> = listOf("192.0.2.", "198.51.100.", "203.0.113.")
        val NON_ALNUM: Regex = Regex("[^a-z0-9]")
        val NON_ALNUM_RUN: Regex = Regex("[^A-Za-z0-9]+")

        fun normKey(key: String): String = NON_ALNUM.replace(key.lowercase(), "")

        fun label(key: String): String {
            val lab = NON_ALNUM_RUN.replace(key, "_").trim('_').uppercase()
            val cut = if (lab.length > 24) lab.substring(0, 24) else lab
            return cut.ifEmpty { "FIELD" }
        }
    }
}
