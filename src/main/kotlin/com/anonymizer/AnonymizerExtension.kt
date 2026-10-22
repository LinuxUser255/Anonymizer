package com.anonymizer

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.anonymizer.burp.ContextMenu
import com.anonymizer.burp.EngineService
import com.anonymizer.burp.Persistence
import com.anonymizer.burp.TabController
import com.anonymizer.ui.AnonymizerTab
import javax.swing.SwingUtilities

/**
 * Entry point. Burp discovers this class because it implements [BurpExtension].
 *
 * Wiring: persistence → engine (one thread) → controller → Swing tab; a context-menu provider feeds
 * the tab. Everything registered here is released in the unloading handler, which is a BApp
 * acceptance criterion.
 */
public class AnonymizerExtension : BurpExtension {
    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Anonymizer")
        val persistence = Persistence(api)
        val engine = EngineService(persistence.loadSettings())
        engine.onMapChanged = { snapshot -> persistence.saveMap(snapshot) }

        val controller = TabController(api, engine, persistence)
        val tab = AnonymizerTab(controller)
        api.userInterface().applyThemeToComponent(tab)

        persistence.loadMap()?.let { stored ->
            engine.load(stored).thenAccept { snap -> SwingUtilities.invokeLater { tab.updateMapping(snap) } }
        }

        api.userInterface().registerSuiteTab("Anonymizer", tab)
        api.userInterface().registerContextMenuItemsProvider(ContextMenu(api, tab))
        api.extension().registerUnloadingHandler {
            tab.dispose()
            engine.shutdown()
            api.logging().logToOutput("Anonymizer unloaded")
        }
        api.logging().logToOutput("Anonymizer loaded. Right-click a request or response → Send to Anonymizer.")
    }
}
