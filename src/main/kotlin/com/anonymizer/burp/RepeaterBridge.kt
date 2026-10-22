package com.anonymizer.burp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as MontoyaByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import com.anonymizer.ui.ServiceInfo
import java.awt.Component
import javax.swing.JOptionPane

/**
 * Opens a Repeater tab for restored text. The extension never sends traffic; the user does.
 * Handles the two known traps: the target service must be rebuilt from the restored `Host`
 * header (docs/PLAN.md, design point 4), and Repeater mangles non-ASCII punctuation that LLMs like
 * to write (CLAUDE.md, "Known traps").
 */
public class RepeaterBridge(private val api: MontoyaApi) {
    /**
     * [known] are the services of the items in the tab, matched by host so scheme and port come
     * from the real traffic; otherwise the user is asked.
     */
    public fun send(restored: String, known: List<ServiceInfo>, parent: Component) {
        var text = restored
        val nonAscii = text.count { it.code > 0x7E || (it.code < 0x20 && it != '\r' && it != '\n' && it != '\t') }
        if (nonAscii > 0) {
            val sample = text.first { it.code > 0x7E || (it.code < 0x20 && it != '\r' && it != '\n' && it != '\t') }
            val choice = JOptionPane.showOptionDialog(
                parent,
                "The text contains $nonAscii non-ASCII character(s) such as '$sample'.\n" +
                    "Repeater mangles these (an em dash becomes \\x14) and the server will likely answer 400.",
                "Send to Repeater",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,
                arrayOf("Replace with ASCII and send", "Send as-is", "Cancel"),
                "Replace with ASCII and send",
            )
            when (choice) {
                0 -> text = asciiFold(text)
                1 -> Unit
                else -> return
            }
        }
        if ("\r\n" !in text) text = text.replace("\n", "\r\n")
        if (!text.contains("\r\n\r\n")) text = text.trimEnd('\r', '\n') + "\r\n\r\n"

        val hostHeader = HOST_HEADER.find(text)?.groupValues?.get(1)?.trim()
        val service = resolveService(hostHeader, known, parent) ?: return
        // Montoya's byteArray(byte...) is varargs: spread the Kotlin ByteArray.
        val request = HttpRequest.httpRequest(service, MontoyaByteArray.byteArray(*text.toByteArray(Charsets.UTF_8)))
        api.repeater().sendToRepeater(request, "Anonymizer")
    }

    private fun resolveService(hostHeader: String?, known: List<ServiceInfo>, parent: Component): HttpService? {
        var host = hostHeader ?: ""
        var port = -1
        val colon = host.lastIndexOf(':')
        if (colon >= 0 && host.substring(colon + 1).all { it in '0'..'9' } && !host.startsWith("[")) {
            port = host.substring(colon + 1).toInt()
            host = host.substring(0, colon)
        }
        known.firstOrNull { it.host.equals(host, ignoreCase = true) && (port < 0 || it.port == port) }?.let {
            return HttpService.httpService(it.host, it.port, it.secure)
        }
        val guessSecure = port != 80
        val guessPort = if (port > 0) port else 443
        val default = (if (guessSecure) "https://" else "http://") + (if (host.isEmpty()) "target" else host) + ":" + guessPort
        val answer = JOptionPane.showInputDialog(
            parent,
            "No item in the tab matches this Host header, so scheme and port are unknown.\nTarget to send to:",
            "Send to Repeater",
            JOptionPane.QUESTION_MESSAGE,
            null,
            null,
            default,
        ) as? String ?: return null
        val m = TARGET.matchEntire(answer.trim()) ?: run {
            JOptionPane.showMessageDialog(parent, "Expected scheme://host:port, got '$answer'", "Send to Repeater", JOptionPane.ERROR_MESSAGE)
            return null
        }
        val secure = m.groupValues[1].equals("https", ignoreCase = true)
        val p = m.groupValues[3].toIntOrNull() ?: (if (secure) 443 else 80)
        return HttpService.httpService(m.groupValues[2], p, secure)
    }

    private companion object {
        val HOST_HEADER: Regex = Regex("(?im)^Host:[ \\t]*([^\\r\\n]*)$")
        val TARGET: Regex = Regex("(https?)://([^/:\\s]+)(?::(\\d+))?/?", RegexOption.IGNORE_CASE)

        /** Replaces the prose punctuation LLMs write with ASCII; anything else non-ASCII becomes '?'. */
        fun asciiFold(s: String): String {
            val sb = StringBuilder(s.length)
            for (c in s) {
                sb.append(
                    when (c) {
                        '—', '–', '‒', '−' -> "-"
                        '‘', '’', '‚', '′' -> "'"
                        '“', '”', '„', '″' -> "\""
                        '…' -> "..."
                        ' ', ' ', ' ', ' ' -> " "
                        '​', '‌', '‍', '﻿' -> ""
                        else -> if (c.code > 0x7E || (c.code < 0x20 && c != '\r' && c != '\n' && c != '\t')) "?" else c.toString()
                    },
                )
            }
            return sb.toString()
        }
    }
}
