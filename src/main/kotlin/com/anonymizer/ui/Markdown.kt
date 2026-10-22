package com.anonymizer.ui

/** "Copy all as Markdown": one fenced block per item, in list order, ready to paste into an LLM. */
public object Markdown {
    public fun bundle(items: List<Pair<Item, String>>): String {
        val sb = StringBuilder()
        for ((item, text) in items) {
            sb.append("### #").append(item.id).append(' ').append(item.title).append("\n\n")
            val fence = if ("```" in text) "````" else "```"
            sb.append(fence).append("http\n")
            sb.append(text.replace("\r\n", "\n").trimEnd('\n')).append('\n')
            sb.append(fence).append("\n\n")
        }
        return sb.toString().trimEnd('\n') + "\n"
    }
}
