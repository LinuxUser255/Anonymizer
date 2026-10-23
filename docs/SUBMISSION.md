# BApp Store submission

How Anonymizer is submitted, and the exact issue body. Sources, checked 2026-10-23:
[acceptance criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-acceptance-criteria),
[submitting](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/bapp-store-submitting-extensions),
the [extension-portal](https://github.com/PortSwigger/extension-portal) README, `AGENTS.md` and
`.github/ISSUE_TEMPLATE/01-submit-extension.yml`.

## Process

1. The source must be on a **public, non-fork GitHub repository**. PortSwigger forks it, builds
   the JAR themselves and publishes from their fork; updates are pull requests against that fork
   plus an "Update for existing extension" issue.
2. Open a **New extension submission** issue on `PortSwigger/extension-portal`. The issue title is
   the extension name, used verbatim. The body is parsed literally: each field is a `### ` heading
   on its own line, a blank line, then the value. Unanswered optional fields are omitted or set to
   `_No response_` (never `N/A` or blank). Checkbox labels must match character for character.
3. A pipeline comments within minutes. If it fails, fix and comment `/resubmit` on the same issue;
   never open a second one. Progress: the "Extension submissions" GitHub project. Questions:
   bapps@portswigger.net.

Before pushing the submit button, the author confirms by hand (not the agent) that both
confirmation statements are true; they record agreement to the BApp EULA.

## Pre-flight

- `git status` clean on `main`, pushed to `origin` (GitHub), tag matching the version number.
- `./gradlew clean test shadowJar` green from a fresh clone, with network (the foojay resolver may
  download JDK 21 on PortSwigger's build machine).
- The JAR loads in Burp Pro and Burp Community, unloads cleanly (no thread left, Extensions →
  Installed shows no error), and reloads.
- `docs/BAPP-CRITERIA.md` has no open item.

## Issue body

Save as `submission.md`, replace the two placeholders in angle brackets, then either paste it into
the form or run:

```
gh issue create --repo PortSwigger/extension-portal --title 'Anonymizer' --body-file submission.md
```

```markdown
### Extension URL

https://github.com/LinuxUser255/Anonymizer

### Version number

0.1.0

### Select additional compatible products and features

- [X] Community
- [ ] DAST
- [ ] Burp AI

### Author display name

<display name>

### Contact details (optional)

<email, or _No response_>

### Discord username (optional)

_No response_

### I confirm that the following is true:

- [X] I have permission from all relevant persons to submit this extension to the BApp Store for public use
- [X] I have read and understood the submission requirements for the BApp Store

### Extension overview

Anonymizer pseudonymizes HTTP requests and responses so they can be pasted into an LLM without leaking client data, and restores the LLM's answer back into real values so it can go straight into Repeater.

It is not a redactor. The same original value always becomes the same placeholder within a session, so the model can still follow a login flow or a session cookie across requests; and every replacement is kept in a per-project map, so the request the model writes back is turned into real traffic with one click. Placeholders keep the shape of the value where it matters (valid hostnames, emails, v4 UUIDs, three-segment JWTs), so the crafted request still parses.

The extension is passive. It never sends traffic and never contacts any AI provider: text leaves Burp only through the user's clipboard, and comes back only by paste. Send to Repeater opens a tab; the user sends.

### Key features

- Right-click any request or response in Proxy, Repeater, Site map, Logger or Intruder → Send to Anonymizer; multi-select sends several.
- Consistent pseudonyms per session: hosts become `target1.example` (generic subdomains such as `api` kept), emails `user1@target1.example`, cookies `[COOKIE_n]`, Authorization `Bearer [TOKEN_n]`, UUIDs valid v4 UUIDs, JWTs re-issued as synthetic tokens whose claims are anonymized by the same rules so `alg`, `exp` and `role` stay readable.
- Detectors for hosts, public and private IPs, emails, cookies, Authorization, sensitive headers and fields by name, known secret formats (AWS, GitHub, Stripe, Slack, private keys), UUIDs, long hex, Luhn-valid cards, SSNs, phone numbers, high-entropy blobs and user-defined client terms. Each is toggleable with live re-render; a disabled detector still highlights what it would have caught.
- Byte-identical otherwise: JSON is rewritten in place (key order, whitespace, escapes and malformed bodies survive), line endings are kept per line, Content-Length is recomputed.
- Restore pane: paste the LLM's reply, Restore, Send to Repeater. Unknown placeholders are left in place and listed (nothing is guessed), lenient matches (`[cookie_1]`, lost brackets, markdown emphasis) are highlighted, a JWT whose claims were edited is flagged rather than restored.
- Copy one item, or several as a Markdown bundle, to the clipboard.
- Session map stored with the Burp project; Show, Clear, Export and Import. Detector toggles follow the user across projects; client terms stay with the project.
- Pure-Kotlin engine with no Burp dependency, pinned by a fixture corpus of byte-for-byte expectations.

### Usage instructions

1. In Proxy, Repeater, Logger, the Site map or Intruder, right-click a message and choose Send to Anonymizer. Select several first to send them all.
2. In the Anonymizer tab, review the Anonymized pane. Blue is a placeholder; yellow is a value to check that a disabled detector would have caught. Toggle detectors or add client terms (select text in any editor → Add selection as client term); the output re-renders live.
3. Press Copy, or select several items and press Copy all as Markdown, then paste into the LLM of your choice.
4. Paste the LLM's reply into the Restore pane and press Restore. Read the status line: unknown placeholders and modified JWTs are listed and highlighted in red, lenient matches in orange. Press Send to Repeater; the target is rebuilt from the Host header and the original item's scheme and port.
5. The map lives with the Burp project. On Burp Community a temporary project loses it on close: press Export before closing and Import later. Clear restarts placeholder numbering.
```
