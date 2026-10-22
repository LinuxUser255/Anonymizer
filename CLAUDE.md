# CLAUDE.md — Anonymizer

Guidance for AI coding agents working on this Burp Suite extension.

## What this is

A Burp extension that **pseudonymizes** HTTP requests and responses so they can be pasted into an
LLM without leaking client data, and **restores** the LLM's answer back into real values for
Repeater. Right-click → "Send to Anonymizer". Two properties define it: the same original value
always becomes the same placeholder within a session (**consistent**), and every replacement is kept
in a session map so the LLM's output can be turned back into real traffic (**reversible**).

It is not a redactor. If a change would make output one-way, or make the same value produce two
placeholders, it is wrong.

**Passive.** It never sends traffic. "Send to Repeater" opens a tab; the user sends.

**Stack-agnostic.** It classifies by wire-format structure (HTTP text, JSON, forms, cookies, JWTs)
and value shape. Nothing application-specific enters its behaviour or docs.

## Current state

**Milestone 1 working:** the engine, Burp layer and UI compile, the tests pass, and the extension
loads in Burp Pro. `docs/PLAN.md` is the design and the record of what is decided, proposed and
open; read it before proposing structure. The repo is the source of truth for code — this file
does not duplicate layout or examples.

**Standalone.** Anonymizer has no companion tool or reference implementation. Its behaviour is
defined by the fixture corpus (`src/test/resources/fixtures`, run by `FixtureTest`) and the unit
tests in this repo, nothing else.

**Build:** Kotlin on JVM 21, Montoya API only (never the legacy Extender API), Montoya as
`compileOnly`, Kotlin stdlib bundled by Shadow, every version pinned exactly and checked on Maven
Central first. No JSON library — the engine rewrites JSON in place with its own tokenizer.
`./gradlew shadowJar` produces `build/libs/anonymizer-<version>-all.jar`.

## Agent command policy (mandatory)

"OS command" = anything run through the Bash tool.

### Pre-approved (run without asking)

- **File tools:** Read, Glob, Grep, Write, Edit on files inside this repo.
- **Gradle (inside this repo):** `./gradlew test`, `build`, `shadowJar`, `clean`, `--version`, and
  `--offline` forms. Gradle may download dependencies.
- **Read-only git:** `status`, `log`, `show`, `diff`, `blame`, `grep`, `shortlog`, `ls-files`,
  `rev-parse`, `cat-file`, `describe`, `reflog`, and `--no-pager` forms.
- **Read-only shell:** `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `wc`, `file`, `tree`, `jq`,
  `command -v`, `which`, `unzip -l`, `xxd` (viewing only), `java -version`.
  - No output redirection (`>`, `>>`, `tee`). Writing a file goes through Write/Edit.
  - `find` is not pre-approved. Use Glob, or ask.
  - **Scoped to this repo.** Do not read, search or list anything else —
    not `$HOME` dotfiles, not other sibling projects. If a referenced document lives elsewhere, say
    you cannot read it and ask.

### Push only on the user's word, in the same message

`git push` runs only when the user's own message in the current turn says to push. Not a plan that
says "commit and push", not approval from an earlier turn, never as the tail of a chain. Push once,
to the configured remote, then report. The user owns every push.

### Needs approval first

Anything not pre-approved, including:

- **git writes:** `add`, `commit`, `rm`, `mv`, `rebase`, `reset`, `revert`, `cherry-pick`, `merge`,
  `checkout`, `switch`, `restore`, `clean`, `stash`, branch/tag changes, `pull`, `fetch`, `remote`
  changes, `config` writes.
- **Filesystem inside the repo:** `rm` (single files, no recursion or force), `mv`, `cp`, `chmod`.
- **Network:** `curl`, `wget`.
- **Toolchain:** `./gradlew wrapper`, other Gradle tasks, any dependency or plugin version change.
- **Processes:** `kill`, `java -jar`, launching Burp, running any shell script.

Approval protocol: show the **exact command**, why, what it reads or modifies, whether it is
reversible; wait for a clear "yes"; approval covers only that command; no chaining (`&&`, `;`,
pipes, `$(...)`) to bundle an unapproved command with an approved one. "Commit" in a plan means
"propose the commit and wait".

### Never run — print it instead

- `sudo` or any privilege escalation.
- Recursive or forced deletes: `rm -r`, `rm -R`, `rm -f`, `rm -rf`.
- Any write outside this repo: `~/.gradle`, `~/.m2`, `~/.BurpSuite`, Burp's install directory,
  shell profiles, global git config.

## Extension code restrictions (`src/main/**`)

Anonymizer handles client secrets inside a security tool, and BApp review checks for this.

- **No process spawning:** no `ProcessBuilder`, no `Runtime.exec`. Clipboard access goes through
  `java.awt.Toolkit.getDefaultToolkit().systemClipboard` only — this is approved because copying is
  the feature.
- **No direct networking:** no `Socket`, `HttpURLConnection`, `java.net.http.HttpClient`, OkHttp,
  Ktor. The extension sends nothing; even `api.http().sendRequest` is not used.
- **No Java deserialization**, no reflection into Burp internals, no dynamic class loading, no
  `System.exit`.
- **Files:** Montoya persistence (`api.persistence()`) for the map and settings. The only file I/O
  is the user-driven Export/Import of the map through a file chooser, and that goes through a single
  class so it can be reviewed in one place.
- **The engine package imports nothing from Montoya.** `engine/` is pure Kotlin and must stay
  testable in plain JUnit. Montoya types stop at `burp/`.
- Exceptions need approval and a line under "Approved exceptions" in `docs/PLAN.md`.

## Kotlin and concurrency

House style: immutable models, snapshots to the EDT, one engine thread.

- **Immutability first.** Model properties are `val`; `Settings` and engine results are data
  classes; collections are `listOf` / `setOf` / `mapOf`.
- **One engine executor.** All anonymize/restore/map mutation runs on a single-threaded executor
  owned by the extension. Placeholder numbering is deterministic because of this; do not add a
  second worker, a parallel stream, or a lock to "speed it up". The map hands immutable snapshots
  to the UI.
- **No `!!` on Montoya platform types.** Montoya is Java; treat return values as nullable. Use
  `requireNotNull` at boundaries, safe calls, or early returns.
- **Explicit on public surface:** visibility, return and property types, and KDoc on anything that
  is part of the extension's observable behaviour. Locals may infer.
- **All Swing changes on the EDT** (`SwingUtilities.invokeLater`), coalesced with a short
  `javax.swing.Timer` for live re-render. Parent dialogs to `SwingUtils.suiteFrame()`. Never
  block the EDT — a 2 MB response is anonymized on the engine thread.
- **AI-generated changes include tests** and must not weaken immutability or null-safety.
- **Coroutines** are not banned but not the default and may not be introduced as a side effect of
  another task. Proposing them is a `docs/PLAN.md` entry (component, what it buys, JAR cost, how
  the scope is cancelled in `extensionUnloaded()`), then approval. Never inside a Montoya handler
  path; never `GlobalScope`; convert a component wholly or not at all.

Source: [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html).

## Behaviour rules

- **Byte-identical except for replacements.** Anonymize and restore are substitution passes. Key
  order, whitespace, malformed JSON, line endings all survive. `Content-Length` is the one
  exception and is recomputed only when the text parses as an HTTP message and the body changed.
- **Numbering never reuses.** `[COOKIE_3]` means one value for the life of the session map.
  Clearing the map resets counters; nothing else does. Toggling a detector off hides its
  replacements in output but does not remove map entries.
- **Restore never invents.** Unknown or modified placeholders are flagged, left in place, and the
  user is told; they are never guessed.
- **Shape-preserving placeholders stay valid.** Hosts are valid hostnames, emails valid emails,
  UUIDs valid v4 UUIDs, synthetic JWTs three base64url segments. The request the LLM crafts must
  still parse.
- **Lenient matching is visible.** Any restore match that was not an exact placeholder is
  highlighted.
- **Warn, don't redact, when a detector is off.** Leftover high-entropy strings and words that
  resemble client terms are highlighted as "check this".
- **Detection rules are defined by the fixture corpus.** A detector change updates or adds a
  fixture under `src/test/resources/fixtures` and adds a line to the PLAN.md decision log.
  "Write the mutant test first": for any change to detection or restore, write the test that
  fails against the wrong implementation, verify it fails against a deliberate mutant, revert the
  mutant.
- **Guards.** ~2 MB body cap, binary bodies skipped, regexes reviewed for backtracking when added
  or changed (`RE_CARD`, `RE_IPV6`, `RE_JSON_KV` are the known risks).
- **Unload cleanly.** The engine executor, Swing timers and stores are released in
  `extensionUnloaded()`. Clean unload is a BApp acceptance criterion.

## Known traps

Verified on this machine and this Burp. Do not rediscover.

- **Repeater mangles non-ASCII.** Em dashes and curly apostrophes become `\x14` / `\x19`,
  producing 400s. A restored request containing LLM-written prose punctuation will break; strip or
  warn before Send to Repeater.
- **Reloading a rebuilt JAR means Remove and Add** in Extensions → Installed. Burp's auto-reload
  does not fire for a rebuilt JAR (verified 2026-10-13); do not investigate again.
- **`extensionData()` is scoped per extension entry.** Two loaded copies of the JAR have separate
  maps. "0 entries" after swapping JARs is correct, not data loss.
- **Temporary projects lose `extensionData()` on close.** Community users must Export; this is by
  design, not a bug to fix with a background file writer.
- **Hostnames in free text are only mapped when the TLD is known**, so `jquery.min.js` is left
  alone. Host headers and URLs are always mapped. Deliberate; keep.
- **Base64-encoded or compressed bodies are not decoded.** Not a target for v1.
- **Detector regexes are ASCII-only by design.** In `java.util.regex`, `(?i)`, `\w`, `\d` and
  `\s` match ASCII unless Unicode flags are set; detectors match ASCII wire shapes, so do not
  "fix" this. Add or change a pattern one at a time, each with a fixture.

## Working style

- Direct technical answers with ready-to-use code blocks; concise "why".
- Small, focused changes that keep the extension loadable at each step.
- **Diagnose before changing** when a theory is unconfirmed. Read-only investigation first,
  findings with file paths and line numbers, say explicitly when something is not determinable
  from the source.
- If a Montoya detail is unclear, consult the Javadoc or official examples rather than guessing.
- Note deviations from this document in `docs/PLAN.md`.

## References

- `docs/PLAN.md` — design, decisions, open questions, milestones, approved exceptions
- [Montoya API Javadoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/)
- [Montoya examples](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [BApp Store acceptance criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria)
- [RequestRedactorX](https://github.com/portswigger/request-redactor-x) — the overlapping BApp; see PLAN.md for how Anonymizer differs
