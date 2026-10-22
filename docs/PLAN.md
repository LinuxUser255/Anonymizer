# Anonymizer — design plan (living document)

Status: **milestones 1–5 code-complete, in live testing (2026-10-22).** The engine compiles, the
fixture corpus and unit tests are green, and the extension loads in Burp Pro (anonymize, highlights,
Copy verified by hand). Each section is tagged **Decided**, **Proposed** (my default unless objected
to) or **Open**. When something moves between tags, add a line to the decision log at the bottom.
This file is the plan; `CLAUDE.md` holds the rules agents follow while building it.

## Build

```
./gradlew test        # engine, fixture corpus, UI unit tests
./gradlew shadowJar   # build/libs/anonymizer-<version>-all.jar (load this one in Burp)
```

Gradle 9.8.2 via the wrapper. JDK 21 is provisioned by the
`org.gradle.toolchains.foojay-resolver-convention` plugin in `settings.gradle.kts` if no JDK 21 is
installed; the wrapper itself runs on JDK 17+.

## What it is

A Burp Suite extension (Kotlin, Montoya API) that **pseudonymizes** HTTP requests and responses so
they can be pasted into an LLM — claude.ai, an agent, anything — without leaking client data, and
then **restores** the LLM's answer back into real values so it can go straight into Repeater.

The core gesture is Burp-native: right-click any request or response → **Send to Anonymizer**.

Two properties make this more than redaction, and they are the BApp pitch:

- **Consistent.** The same host, cookie, token or email always becomes the same placeholder in a
  session, so the model can still reason about the traffic (`user1@target1.example` logs in, gets
  `[COOKIE_3]`, `[COOKIE_3]` is replayed against `api.target1.example`).
- **Reversible.** Every replacement is kept in a session map. Paste the LLM's reply back → Restore →
  Send to Repeater.


## Decided

- **Name:** Anonymizer. Context-menu item "Send to Anonymizer", suite tab "Anonymizer",
  JAR `anonymizer-<version>-all.jar`.
- **Language:** Kotlin on JVM 21, Montoya API only. Not Java, not Jython.
- **Target:** BApp Store submission. Everything must hold on Burp Community (no saved projects).
- **No CLI.** Extension only.
- **Strictness:** not strict by default; per-detector toggles decide how much is replaced.
  Private IPs off by default, UUIDs on (see the toggle table).
- **Settings split:** detector toggles in `persistence().preferences()` (global, follow the user);
  client terms and keep-hosts in `persistence().extensionData()` (per project, engagement-specific).
- **License:** GPLv3. The BApp acceptance criteria say nothing about
  licensing; the only requirement is that source is published on PortSwigger's GitHub. Note that
  the Montoya API itself ships under the Burp Suite licence agreement, not an open-source licence;
  the extension only compiles against it (`compileOnly`, never bundled). Optional follow-up: a
  GPLv3 §7 additional permission explicitly allowing linking with Burp Suite and the Montoya API.
- **Package:** `com.anonymizer`. Entry class
  `com.anonymizer.AnonymizerExtension`, source under `src/main/kotlin/com/anonymizer/`. Burp isolates
  each extension in its own classloader, so the non-domain prefix carries no collision risk.
- **Repo:** `~/Projects/Hacking/Anonymizer`, local only for now. Public home will be **GitHub**
  (PortSwigger mirrors BApp source into github.com/PortSwigger); a GitLab mirror is optional.

### Core flow

```
Right-click a request/response (Proxy, Repeater, Site map, Logger, Intruder) → Send to Anonymizer
  → item appears in the Anonymizer tab: Original | Anonymized (highlighted)
  → adjust toggles / add client terms, output re-renders live
  → Copy (or select several items → Copy all as Markdown)
  → paste into the LLM

Paste the LLM's reply into the Restore pane → Restore → review → Send to Repeater
  (opens a Repeater tab; the extension never sends traffic itself)
```

### Architecture: a pure engine, Burp at the edges

```
engine/   pure Kotlin, zero Montoya imports, carries ~95% of the tests
  Anonymizer   anonymize(text, settings, mapping) -> Result(text, highlights, newEntries)
  Restorer     restore(text, mapping, lenient) -> Result(text, highlights, unknownPlaceholders)
  Mapping      category -> original -> placeholder, counters, reverse index
  detectors/   Host, Ip, Email, Jwt, Secret, Uuid, Hex, Blob, Card, Ssn, Phone, Terms
  body/        Json, Form, Multipart, XmlHtml, Text
  Settings     immutable data class (toggles, terms, keepHosts, ...)
burp/     Montoya edges only: Extension, ContextMenuProvider, Persistence, RepeaterBridge, Clipboard
ui/       the Anonymizer suite tab
```

Why text in, text out and not Montoya's parsed objects: restore works on text the LLM wrote (a
whole request, a curl line, a paragraph with a header in it), which is not a Burp message; and
Montoya factories only work inside a running Burp, so a pure engine is the only way to run the
fixture corpus in plain JUnit. The engine parses HTTP text itself.

### Five design points

1. **JSON is rewritten in place, never re-serialized.** A small tokenizer replaces string/number
   tokens and leaves everything else byte-identical (key order, whitespace, escapes, duplicate
   keys). Malformed JSON falls back to a key/value regex pass. No `org.json` dependency.
2. **Session = Burp project.** The map lives in `persistence().extensionData()` as JSON. The project
   already holds the raw traffic, so this adds no new exposure. Buttons: Clear mapping, Export,
   Import (file dialog; the Community answer, since temporary projects vanish on close).
   Detector toggles live in `persistence().preferences()` (follow the user across projects);
   client terms and keep-hosts live with the project (they are engagement-specific).
3. **One engine thread.** All anonymize/restore work runs on a single-threaded executor. Placeholder
   numbering is therefore deterministic with no locks; the EDT only ever receives immutable
   snapshots. Simpler than a `ConcurrentHashMap` and correct for a store that must be consistent
   with itself.
4. **Bytes ↔ text.** Bodies decode as UTF-8 for display/copy. A restored request is rebuilt from
   the restored string; its `HttpService` comes from the restored `Host` header plus the original
   item's scheme/port when the host is in the map, otherwise the user is asked. Watch the Repeater
   non-ASCII trap (see CLAUDE.md).
5. **Regex budget.** ~2 MB body cap, binary bodies skipped, and `RE_CARD` / `RE_IPV6` /
   `RE_JSON_KV` reviewed for catastrophic backtracking. Patterns use `java.util.regex`; `(?i)`,
   `\w`, `\d` and `\s` are ASCII-only, and each pattern change comes with its fixture.

## Placeholder format (Decided, examples Proposed)

Rule: a placeholder is **obviously a placeholder** (`[CATEGORY_n]`) unless the value's *shape*
matters for the request to stay valid or for the LLM to reason — then it is shape-preserving.
Numbering is per category, never reused within a session.

| Original | Placeholder | Why this shape |
| --- | --- | --- |
| `api.acmecorp.com` | `api.target1.example` | valid hostname; generic subdomain kept |
| `portal.acmecorp.com` | `sub1.target1.example` | non-generic subdomain renamed |
| `acmecorp.com` | `target1.example` | base domain restores too |
| `203.0.113.7` / `fd00::1` | `192.0.2.1` / `2001:db8::1` | documentation ranges |
| `j.smith@acmecorp.com` | `user1@target1.example` | valid email, same domain mapping |
| `Authorization: Bearer eyJ…` | `Bearer [TOKEN_1]` | scheme kept |
| `Authorization: Basic dXNl…` | `Basic [BASIC_1]` | |
| JWT anywhere | synthetic JWT: header kept, claims anonymized by the same rules, signature replaced | LLM can still read `alg`, `exp`, `role` |
| `Cookie: session=abc; lang=en` | `session=[COOKIE_1]; lang=en` | names kept; `keep_cookies` list |
| `X-Api-Key: …` | `[X_API_KEY_1]` | header name in the label |
| `"password":"Winter2024!"` | `"password":"[PASSWORD_1]"` | field name in the label |
| AWS/GitHub/Stripe/… keys | `[SECRET_1]` | |
| `-----BEGIN PRIVATE KEY-----…` | `[PRIVATE_KEY_1]` | |
| UUID | `00000000-0000-4000-8000-000000000001` | stays a valid v4 UUID |
| hex ≥ 32 chars | `[HEX_1]` | |
| opaque high-entropy field value | `[BLOB_1]` | |
| card / SSN / phone | `[CARD_1]` / `[SSN_1]` / `[PHONE_1]` | |
| client term (`Acme Corp`) | `[CLIENT_1]` | |

Worked example (what the LLM sees):

```
POST /api/v2/login HTTP/1.1                 POST /api/v2/login HTTP/1.1
Host: portal.acmecorp.com                   Host: sub1.target1.example
Origin: https://portal.acmecorp.com         Origin: https://sub1.target1.example
Cookie: session=4f3c…9a; lang=en            Cookie: session=[COOKIE_1]; lang=en
Authorization: Bearer eyJhbGciOiJIUzI1…     Authorization: Bearer [TOKEN_1]
Content-Type: application/json              Content-Type: application/json
Content-Length: 83                          Content-Length: 86

{"email":"j.smith@acmecorp.com",            {"email":"user1@target1.example",
 "password":"Winter2024!",                   "password":"[PASSWORD_1]",
 "company":"Acme Corp"}                      "company":"[CLIENT_1]"}
```

Kept on purpose so the LLM has context: method, path, header names, `Server`, `User-Agent`
(including product versions such as `Chrome/154.0.0.0`, which are not IPs), `Content-Type`, status
codes, non-sensitive JSON keys and values, well-known third-party hosts. `Content-Length` is
recomputed whenever the body changed, in both directions, and counts the bytes actually sent.
Line endings are preserved per line (a CRLF head with an LF body stays that way).

## Detector toggles and defaults (Decided as v1 defaults; see "Toggles are v1, not the ceiling")

"Not too strict" means: on by default where a miss is a real leak, off by default where the
detector is noisy and the data is rarely client-identifying. Everything is toggleable; the tab shows
the effect live. Toggling a detector off does **not** delete its map entries — numbering stays
stable across re-renders, and restore still works for anything ever mapped.

| Detector | Default | Note |
| --- | --- | --- |
| Hosts / domains | on | plus `keep_hosts`; third-party CDNs kept automatically |
| Public IPs | on | dotted quads after a product token (`Chrome/154.0.0.0`) are versions, left alone |
| Private IPs | **off** | `10.x` / `192.168.x` topology helps the LLM, rarely identifies a client (decided) |
| Emails | on | |
| Authorization header | on | |
| Cookies | on | `keep_cookies` for `lang`-style values |
| JWTs | on | synthetic re-issue |
| Sensitive headers by name | on | `X-Api-Key`, `*-Token`, `*-Secret`, `*Session*`, `*Signature*` … (`*Tokens*`, plural, is a count) |
| Sensitive fields by key | on | password, email, name, ssn, card, account, company, sub, state, code … (`*tokens*`, plural, is a count) |
| Known secret formats | on | |
| UUIDs | on | often session/user ids (decided) |
| Hex ≥ 32 | on | session ids, hashes |
| Opaque blobs (entropy) | **off** | noisy |
| Cards / SSN | on | Luhn-checked, cheap |
| Phone numbers | **off** | noisy |
| Client terms | on | "Add selection as client term" from either pane |

A detector that is off should still be able to **warn**: the Anonymized pane highlights leftover
high-entropy strings and words resembling client terms as "check this" rather than redacting them.
That is how "not strict" stays safe.

### Toggles are v1, not the ceiling

On/off per detector is the starting point; finer-grained control is expected later. The design rule
that makes that cheap: **the engine's `Settings` carries the full configuration vocabulary from day
one**, even though the v1 UI only exposes the toggles and the terms list. The fixtures already
exercise these keys, so the engine must understand them anyway:

| Settings key | What it controls | v1 UI |
| --- | --- | --- |
| `detect.<name>` | per-detector on/off | toggles |
| `terms` | client terms → `[CLIENT_n]` | list + "Add selection" |
| `keep_hosts`, `keep_base_hosts` | hosts never mapped (your VPS, a third party) | hidden |
| `keep_cookies` | cookie names whose values are kept (`lang`) | hidden |
| `keep_private_ips` | the Private IPs toggle | toggle |
| `sensitive_headers`, `sensitive_header_substrings`, `nonsensitive_headers` | header-name rules | hidden |
| `sensitive_keys_exact`, `sensitive_key_substrings`, `nonsensitive_keys` | field-name rules | hidden |
| `generic_labels` | subdomains kept as-is (`api`, `www`, `auth`) | hidden |
| `secret_patterns` | extra regexes → `[SECRET_n]` | hidden |
| `min_hex_len` | hex detector threshold | hidden |

"Hidden" means: present in `Settings`, persisted, editable only by Import/Export of a settings JSON
in v1, surfaced in the UI in a later milestone. Candidates for that later milestone, in rough order
of value: editable keep/sensitive lists; per-item overrides ("don't map this host in *this* item");
right-click a highlighted replacement → "keep original" / "always keep this key"; custom secret
patterns with a live test box; placeholder label overrides. None of these change the engine's
contract, which is the point of settling the vocabulary now.

## Restore rules and edge cases (Decided)

The restore pane is an editable text area (it is a paste box; the user may hand-edit before and
after restoring). Rules, in order:

1. **Exact placeholder known → replaced with the original.** Longest placeholder first so
   `api.target1.example` wins over `target1.example`. Percent-encoded placeholders
   (`user1%40target1.example`) count as exact. This is the only rule that changes bytes silently.
2. **Unknown placeholder of a known shape** (`[COOKIE_9]` when only 1–3 exist, `target4.example`)
   → left as-is and **flagged** in the pane ("1 unknown placeholder, line 3"). Restore never invents
   a value. Send to Repeater still works, with a warning.
3. **Mangled placeholders** — LLMs produce `[cookie_1]`, `**[COOKIE_1]**`, `` `[COOKIE_1]` ``,
   `COOKIE_1` (brackets lost), `target1-example`. Default: case-insensitive matching of bracket
   tokens, markdown emphasis/backticks ignored. A **lenient** toggle additionally tolerates missing
   brackets and `-`/`_`/` ` confusion. Every lenient match is highlighted so the user can eyeball it.
4. **Modified synthetic JWTs.** The whole synthetic token is the map entry. If the LLM edited a
   claim ("set role to admin") the token no longer matches: it is flagged "modified JWT, not
   restored", which is correct — a forged token has to be re-signed anyway. Possible later feature:
   restore the original signature-less header/claims and let the user re-sign in Burp.
5. **Manual edits around placeholders** are fine by construction: restore is a substitution pass,
   not a parse. Structure the LLM changed (new headers, reordered JSON, a curl command instead of a
   raw request) survives. `Content-Length` is recomputed only when the text parses as an HTTP
   message.
6. **Toggles do not affect restore.** Restore uses the full map regardless of what is currently
   enabled.
7. **Manual redaction in the Anonymized pane** (something the detectors missed) is allowed but is
   not in the map and therefore not restorable; the preferred path is "Add selection as client
   term", which is.

## UI sketch (Decided for v1; layout details free to change)

```
┌ Anonymizer ─────────────────────────────────────────────────────────┐
│ Items: #1 POST /login  #2 GET /api/me  #3 …     [Copy all as Markdown]│
├──────────────────────────────┬──────────────────────────────────────┤
│ Original (read-only)         │ Anonymized (highlighted)  [Copy]     │
├──────────────────────────────┴──────────────────────────────────────┤
│ ☑Hosts ☑IPs ☐Private IPs ☑Emails ☑Auth ☑Cookies ☑JWT ☑Secrets ☑UUID  │
│ ☑Hex ☐Blobs ☑Cards/SSN ☐Phone   Terms: [Acme Corp, acme] [+]        │
├─────────────────────────────────────────────────────────────────────┤
│ Restore: [paste LLM output]     [Restore] [Send to Repeater]        │
│ ⚠ 1 unknown placeholder: [COOKIE_9] (line 3)                        │
├─────────────────────────────────────────────────────────────────────┤
│ Mapping: 14 entries   [Show] [Clear] [Export…] [Import…]            │
└─────────────────────────────────────────────────────────────────────┘
```

## Fixture corpus (Decided)

The corpus is the behaviour contract of the engine. It lives at `src/test/resources/fixtures/`
and is run by `FixtureTest` (JUnit reads it as resources).

### Two layers of expectation

Every fixture carries both, and they fail for different reasons:

- **Intent assertions** (`contains`, `notContains`, `mapping`) are hand-written. They are the spec:
  "the password is gone, the role claim survives, the CDN host is kept".
- **`equals` — the full expected output** — reviewed by eye and committed. It is the regression
  lock: byte-for-byte agreement, including CRLF, key order and the synthetic JWT.

If the engine satisfies the intent assertions but fails `equals`, the behaviour changed: decide it
here, then update the fixture. If it fails an intent assertion, it is a bug.

### Shape

One JSON file per case. Inputs are inline JSON strings (CRLF written as `\r\n`), which keeps line
endings exact; long messages may live in sibling files referenced with `@file:`.

```
src/test/resources/fixtures/
  structured/login.json
  structured/crlf-line-endings.json
  detectors/form-body.json
  detectors/multipart.json
  detectors/hosts-need-known-tld.json
  detectors/ipv4-not-product-version.json
  mapping/numbering-continues-across-calls.json
  restore/unknown-placeholder.json
  restore/lenient-markdown-wrapped.json
```

```json
{
  "name": "structured/login",
  "description": "Full request+response: every structured detector fires once; roundtrip is exact.",
  "settings": { "terms": ["acme"] },
  "steps": [
    {
      "op": "anonymize",
      "input": "POST /login HTTP/1.1\r\nHost: api.acme.com\r\n…",
      "expect": {
        "equals": "POST /login HTTP/1.1\r\nHost: api.target1.example\r\n…",
        "contains": [
          "Host: api.target1.example",
          "next=https%3A%2F%2Fportal.target1.example%2Fx&q=1",
          "\"password\":\"[PASSWORD_1]\"",
          "\"ok\":true,\"n\":3",
          "lang=[COOKIE_2]"
        ],
        "notContains": ["acme.com", "Winter2024", "jdoe", "4111", "123-45-6789", "sk_test", "k1\""],
        "jwtClaims": { "header": "Authorization", "contains": ["\"role\":\"admin\""], "notContains": ["acme", "John"] }
      }
    },
    {
      "op": "anonymize",
      "input": "@step[0].output",
      "expect": { "equals": "@step[0].output" },
      "note": "idempotent: anonymizing already-anonymized text changes nothing"
    },
    {
      "op": "restore",
      "input": "@step[0].output",
      "expect": { "equals": "@step[0].input" }
    }
  ],
  "mapping": {
    "host":  { "acme.com": "target1.example", "api.acme.com": "api.target1.example" },
    "email": { "jdoe@acme.com": "user1@target1.example", "john.doe@acme.com": "user2@target1.example" }
  },
  "counters": { "host": 1, "email": 2, "cookie": 2 }
}
```

Field rules:

- **`settings`** uses the `Settings` JSON key names (`terms`, `keep_hosts`, `keep_cookies`,
  `keep_private_ips`, `detect`, `secret_patterns`, `sensitive_key_substrings`, `nonsensitive_keys`
  …). Keys present replace the corresponding `Settings.FIXTURE_DEFAULTS` value wholesale.
- **`steps`** run in order against **one shared mapping**, so a fixture can prove numbering
  continuity, consistency across messages, idempotency and roundtrip in one file.
- **`op`** is `anonymize` or `restore`. The engine contract is these two public operations,
  nothing else; lower-level cases are expressed as plain-text or full-message `anonymize` inputs.
- **References:** `@file:<name>` (sibling file, raw bytes as UTF-8), `@step[N].input`,
  `@step[N].output`. Nothing else is interpolated.
- **`expect.equalsModuloContentLength`** compares with every `Content-Length` value masked, for
  steps where the exact length is not the point.
- **`jwtClaims`** decodes the second segment of the token on the named header and asserts on the
  JSON, because leaks inside a synthetic JWT cannot be checked with plain `contains`.
- **`flags`** (`unknown`, `lenient`, `modifiedJwt`) assert on what a `restore` step reported; a
  per-step `lenient` switch turns lenient restore on.
- **`mapping` / `counters`** are checked after the last step, as subsets (the fixture lists what it
  cares about; extra entries are fine).

### Map file format

The map JSON the extension stores in `extensionData()` and writes on Export is
`{"forward": {category: {original: placeholder}}, "counters": {category: n}}`. A fixture's
`mapping` block is a subset of `forward`.

### Runner and the mutant rule

- One JUnit 5 `@TestFactory` that walks the directory and yields a dynamic test per file. A
  failing fixture names the step and the first differing offset for `equals`.
- **Mutant rule applies to fixtures.** A new fixture must be shown failing against a deliberately
  wrong engine before it is committed.
- Detector order is load-bearing — email before host — and is proven by fixtures whose output
  depends on it, not by inspecting a list.

## Milestones

1. **Engine + fixture corpus.** Engine passes every fixture byte for byte. No Burp involved.
2. **Minimal extension.** Send to Anonymizer → tab with Original/Anonymized → Copy. Map persisted in
   `extensionData()`.
3. **Restore.** Paste box, Restore, Send to Repeater, unknown-placeholder flags.
4. **Toggles and terms UI** with live re-render; highlights; leftover-entropy warnings.
5. **Multi-select** → Copy all as Markdown.
6. **BApp polish.** Clean unload, large-project and Community tests, README with before/after and
   the RequestRedactorX section, acceptance-criteria pass, submission.

1–3 is a usable tool for your own engagements; 4–6 is what makes it a BApp.

## Open

- **Community persistence.** Export/Import is the fallback; is a `preferences()`-backed map (survives
  restart, but stores client secrets in Burp's user prefs) worth offering as an opt-in?
- **Burp AI hook.** If Montoya exposes an AI prompt interface, pseudonymize prompts automatically.
  Not checked against the Javadoc yet; do not plan around it.
- **Highlight scheme.** Colour per category vs. one colour + tooltip.
- **Multi-item placeholder sharing.** One map per project means `[COOKIE_1]` in item #1 is the same
  value in item #7 — intended. Confirm the Markdown bundle format.
- **Responses.** `Set-Cookie`, HTML `<input value>`, XML are handled; the "Send to Anonymizer" menu
  must appear on responses in every tool that offers them.

## Decision log

- 2026-10-22 — Name Anonymizer; Kotlin; BApp target; no CLI; five design points accepted;
  session = project; `[CATEGORY_n]` placeholder format with shape-preserving exceptions; toggle
  defaults, restore rules and UI sketch proposed.
- 2026-10-22 — License GPLv3 (BApp criteria are silent on licensing; Montoya API is proprietary but
  compile-only). Private IPs off / UUIDs on by default confirmed. Settings split confirmed: toggles
  global in `preferences()`, terms and keep-hosts per project in `extensionData()`.
- 2026-10-22 — Package `com.anonymizer`. Primary public repo will be GitHub (BApp requirement),
  GitLab mirror optional.
- 2026-10-22 — Fixture corpus format: JSON fixtures in `src/test/resources/fixtures`, two
  expectation layers (hand-written intent + reviewed `equals`); map file is
  `{forward, counters}` JSON.
- 2026-10-22 — Plan accepted as a whole: fixture corpus, toggle defaults, restore rules and v1 UI
  sketch move to Decided. Toggles are v1 only; `Settings` carries the full configuration vocabulary
  from the start so finer-grained controls can be added later without touching the engine contract.
- 2026-10-22 (build session) — **Versions pinned** after checking Maven Central: Kotlin 2.4.21,
  Shadow 9.6.1, Montoya 2026.7, JUnit BOM 6.1.3, Gradle 9.8.2, plus
  `org.gradle.toolchains.foojay-resolver-convention` 1.0.0 in `settings.gradle.kts` so Gradle can
  provision JDK 21. The resolver can be dropped if a JDK 21 is installed system-wide.
- 2026-10-22 — **Fixture format details settled:** inputs are inline JSON strings (CRLF as `\r\n`)
  rather than `@file:` siblings, which keeps line endings exact without `.gitattributes` tricks;
  `@file:` is still supported. `settings` keys replace defaults wholesale. Added
  `equalsModuloContentLength`, `flags` (`unknown`, `lenient`, `modifiedJwt`) and a per-step
  `lenient` switch.
- 2026-10-22 — **Engine behaviours fixed by fixtures:** JSON bodies are rewritten in place
  (pretty-printing, unchanged escapes like `\/` and `é`, duplicate keys all survive). Percent-encoded
  placeholders (`user1%40target1.example`) are restored. Regex `(?i)`, `\w`, `\d`, `\s` are
  ASCII-only; no fixture depends on non-ASCII matching.
- 2026-10-22 — **Restore details decided:** percent-encoded matches count as exact (not
  highlighted); case-insensitive bracket tokens are restored and highlighted even without lenient;
  lenient adds bare tokens (`COOKIE_1`) and `-`/`_`/space confusion in tokens and hosts
  (`target1-example`); a shaped placeholder unknown as a whole (`user7@target1.example`,
  `sub9.target1.example`) is left intact and flagged rather than half-restored; a JWT carrying a
  known `REDACTED_SIGNATURE_n` but not matching the map is flagged "modified JWT".
- 2026-10-22 — **Engine `Settings` has two default sets:** `FIXTURE_DEFAULTS` (every detector on,
  private IPs mapped; what the fixture corpus assumes) and `EXTENSION_DEFAULTS` (private IPs kept,
  phone and blob off — the v1 toggle table). Four `detect` names gate the structural handlers for
  the UI toggles: `auth`, `cookies`, `headers`, `fields`; they default to on.
- 2026-10-22 — **First compile; line endings kept per line.** `HttpText.parse` keeps each line's
  terminator and bodies raw; detectors see LF only when a segment is CRLF throughout. A CRLF head
  with an LF body stays mixed, and `Content-Length` counts the bytes actually sent. Fixture:
  `structured/crlf-line-endings`.
- 2026-10-22 — **Highlights mapped to document offsets.** Swing stores CRLF as LF, so engine span
  offsets drifted one character per line; `HighlightPane` now converts them. Test:
  `HighlightPaneTest`. Verified live in Burp Pro 2026-10-22.
- 2026-10-22 — **IPv4 skips product versions.** Found in the first live load: `Chrome/154.0.0.0` in
  every Chromium User-Agent became `Chrome/192.0.2.1`. The free-text IPv4 replacer now leaves a
  dotted quad that directly follows a product token and slash (`Detectors.followsProductToken`).
  Host headers, URL hosts and path segments are unaffected. Fixture:
  `detectors/ipv4-not-product-version`. Verified live in Burp Pro 2026-10-22.
- 2026-10-22 — **Anonymizer is standalone:** its predecessor tool is no longer referenced;
  fixtures are owned here and run only by FixtureTest.
- 2026-10-22 — **Plural `tokens` is a count, not a credential.** Seen live: `X-Ratelimit-*-Tokens`
  headers and `usage.*_tokens` / `max_tokens` fields got placeholders because their names contain
  `token`. The `token` substring now does not fire on a key or header name that contains `tokens`;
  every other sensitive word in the same name still does (`secret_tokens` maps), singular `token`
  is unchanged, and the value still runs through the shape and free-text detectors, so a UUID or
  JWT under a plural key is still mapped. Trade-off accepted: a short opaque credential under a
  plural-only key (`access_tokens: "abc"`) is left for the entropy warning rather than mapped.
  Fixture: `detectors/tokens-plural-is-a-count`; mutant verified.
