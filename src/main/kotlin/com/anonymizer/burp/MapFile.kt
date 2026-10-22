package com.anonymizer.burp

import com.anonymizer.engine.MappingSnapshot
import java.awt.Component
import java.io.File
import java.io.IOException
import javax.swing.JFileChooser
import javax.swing.JOptionPane
import javax.swing.filechooser.FileNameExtensionFilter

/**
 * The single place the extension touches the filesystem: user-driven Export/Import of the session
 * map through a file chooser (CLAUDE.md, "Files"). The map holds client originals; the chooser
 * defaults to the `*.anonymizer-map.json` suffix that `.gitignore` excludes.
 */
public object MapFile {
    private const val SUFFIX = ".anonymizer-map.json"

    public fun export(parent: Component, snapshot: MappingSnapshot): Boolean {
        val chooser = JFileChooser().apply {
            dialogTitle = "Export Anonymizer map"
            fileFilter = FileNameExtensionFilter("Anonymizer map (*$SUFFIX)", "json")
            selectedFile = File("session$SUFFIX")
        }
        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) return false
        var file = chooser.selectedFile ?: return false
        if (!file.name.endsWith(".json")) file = File(file.parentFile, file.name + SUFFIX)
        if (file.exists()) {
            val overwrite = JOptionPane.showConfirmDialog(parent, "${file.name} exists. Overwrite?", "Export map", JOptionPane.YES_NO_OPTION)
            if (overwrite != JOptionPane.YES_OPTION) return false
        }
        return try {
            file.writeText(snapshot.toJson() + "\n", Charsets.UTF_8)
            try {
                file.setReadable(false, false)
                file.setReadable(true, true)
                file.setWritable(false, false)
                file.setWritable(true, true)
            } catch (ignored: SecurityException) {
                // best effort: owner-only (0600); the map holds real client values
            }
            true
        } catch (e: IOException) {
            JOptionPane.showMessageDialog(parent, "Could not write ${file.path}: ${e.message}", "Export map", JOptionPane.ERROR_MESSAGE)
            false
        }
    }

    public fun import(parent: Component): MappingSnapshot? {
        val chooser = JFileChooser().apply {
            dialogTitle = "Import Anonymizer map"
            fileFilter = FileNameExtensionFilter("Anonymizer map (*.json)", "json")
        }
        if (chooser.showOpenDialog(parent) != JFileChooser.APPROVE_OPTION) return null
        val file = chooser.selectedFile ?: return null
        return try {
            MappingSnapshot.fromJson(file.readText(Charsets.UTF_8))
        } catch (e: IOException) {
            JOptionPane.showMessageDialog(parent, "Could not read ${file.path}: ${e.message}", "Import map", JOptionPane.ERROR_MESSAGE)
            null
        } catch (e: IllegalArgumentException) {
            JOptionPane.showMessageDialog(parent, "${file.name} is not an Anonymizer map: ${e.message}", "Import map", JOptionPane.ERROR_MESSAGE)
            null
        }
    }
}
