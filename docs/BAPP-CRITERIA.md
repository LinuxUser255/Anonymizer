# BApp Store acceptance criteria: where Anonymizer stands

Audit of 2026-10-23 against the twelve published criteria. "Met" means verified in source or in a
live Burp load; "Open" is work still to do before submission. Re-run this list before each submission.

| # | Criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Unique function | Met, argue it in the issue | Overlaps RequestRedactorX only in gesture. README "How it differs" table: reversible, consistent, shape-preserving, responses, restore. The submission overview leads with this. |
| 2 | Clear name | Met | "Anonymizer"; one-line summary in `docs/SUBMISSION.md`. |
| 3 | Secure operation: treat HTTP content as untrusted | Met (fixed 2026-10-23) | Message text goes into `JTextPane` plain documents only. List and table labels use `PlainRenderers` (HTML disabled) because a value starting with `<html>` would otherwise be rendered, including `<img src>` fetches. `JOptionPane` texts never start with user content. Regexes reviewed for backtracking (`RE_CARD`, `RE_IPV6`, `RE_JSON_KV`). 2 MB cap. |
| 4 | Bundle all dependencies | Met | Shadow JAR bundles Kotlin stdlib; Montoya is `compileOnly`. No other runtime dependency. |
| 5 | Responsiveness, locks, background exceptions | Met (fixed 2026-10-23) | One engine thread, results hopped to the EDT with `invokeLater`; no handlers registered (`HttpHandler`, `ProxyHandler`). Messages over the cap are cut before decoding on the EDT (`ContextMenu.decodeCapped`). Every engine failure reaches `logToError(message, cause)` with its stack trace. |
| 6 | Clean unloading | Met (fixed 2026-10-23) | `registerUnloadingHandler`: re-render timer stopped, mapping dialog disposed, executor shut down (2 s grace, then `shutdownNow`). Verify live after each build: unload, check no `anonymizer-engine` thread remains. |
| 7 | Burp networking | Met | No networking at all, not even `Http.issueHttpRequest`. |
| 8 | Offline working | Met | Nothing fetched. |
| 9 | Large projects | Met | No long-term references to Montoya objects: the context menu copies bytes to a String immediately and never touches `SiteMap` or `Proxy.history()`. |
| 10 | GUI parent = `SwingUtils.suiteFrame()` | Met | `TabHost.suiteFrame()` parents every `JOptionPane`, the file choosers and the mapping `JDialog`. |
| 11 | Montoya via build tool | Met | Gradle, `net.portswigger.burp.extensions:montoya-api` pinned. |
| 12 | Burp AI default for AI features | Not applicable, say so | Anonymizer has no AI feature: it calls no model and holds no API key. The overview states this explicitly so a reviewer does not read "LLM" as "AI extension". |

## Open before submission

- **Public GitHub repository, non-fork.** `origin` is `github.com/LinuxUser255/Anonymizer`; confirm it is public and that `main` is pushed and tagged with the submitted version.
- **PortSwigger builds from source.** Their build machine must manage Kotlin 2.4.21, Gradle 9.8.2 via the wrapper, and JDK 21 (the foojay resolver downloads one if absent). If their pipeline reports a toolchain failure, the fallback is to drop the resolver and state "JDK 21" in the README. `org.gradle.configuration-cache=true` is a second thing to drop if their Gradle invocation objects to it.
- **Community test.** Load the JAR in Burp Community with a temporary project, run the full flow, close, confirm Export/Import recovers the map. Pro is verified; Community is not yet.
- **Unload test on the new build.** Remove in Extensions → Installed; confirm the output pane shows "Anonymizer unloaded" and no error.
- **Version.** `0.1.0` is what the build produces today. If the first public release should read `1.0.0`, bump `build.gradle.kts` and `docs/SUBMISSION.md` together.
- **Screenshots** are not required by the form; a before/after image in the README helps the reviewer and is cheap.
