package com.anonymizer.burp

import java.awt.Toolkit
import java.awt.datatransfer.StringSelection

/** The only clipboard access in the extension; copying is the feature (CLAUDE.md). */
public object ClipboardCopy {
    public fun copy(text: String) {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }
}
