# Anonymizer

<p align="center">
  <img src="images/Anonymizer-Logo.jpg" alt="Burp Anonymizer logo" width="300">
</p>

A Burp Suite extension that **pseudonymizes** HTTP requests and responses so you can paste them
into an LLM without leaking client data, and **restores** the LLM's answer back into real values so
it can go straight into Repeater.

Right-click any request or response → **Send to Anonymizer**.

```
POST /api/v2/login HTTP/1.1                 POST /api/v2/login HTTP/1.1
Host: portal.acmecorp.com                   Host: portal.target1.example
Cookie: session=4f3c…9a; lang=en            Cookie: session=[COOKIE_1]; lang=[COOKIE_2]
Authorization: Bearer eyJhbGciOiJIUzI1…     Authorization: Bearer eyJhbGciOiJIUzI1…REDACTED_SIGNATURE_1
Content-Type: application/json              Content-Type: application/json
Content-Length: 83                          Content-Length: 86

{"email":"j.smith@acmecorp.com",            {"email":"user1@target1.example",
 "password":"Winter2024!",                   "password":"[PASSWORD_1]",
 "company":"Acme Corp"}                      "company":"[CLIENT_1]"}
```

Two properties make this more than redaction:

- **Consistent.** The same host, cookie, token or email always becomes the same placeholder within
  a session, so the model can still reason about the traffic: `user1@target1.example` logs in, gets
  `[COOKIE_3]`, `[COOKIE_3]` is replayed against `api.target1.example`.
- **Reversible.** Every replacement is kept in a session map. Paste the LLM's reply into the Restore
  pane → **Restore** → **Send to Repeater**.

The extension is passive: it never sends traffic. "Send to Repeater" opens a tab; you send.

## What is detected

Hosts and domains (generic subdomains such as `api`, `www`, `auth` are kept; well-known CDNs and
third parties are kept), public IPs (private ranges optional), emails, `Authorization` headers,
cookies, JWTs (re-issued as synthetic tokens whose claims are anonymized by the same rules so `alg`,
`exp`, `role` stay readable), sensitive headers by name, sensitive JSON/form/XML/cookie fields by
key (`password`, `token`, `ssn`, `card`…), known secret formats (AWS, GitHub, Stripe, Slack, private
keys…), UUIDs, long hex strings, Luhn-valid card numbers, SSNs, phone numbers, opaque high-entropy
blobs, and your own **client terms** (company name, codenames).

Placeholders keep the value's shape where it matters: hosts stay valid hostnames, emails valid
emails, UUIDs valid v4 UUIDs, JWTs three base64url segments. The request the LLM crafts still
parses.

## Using it

1. In Proxy, Repeater, Logger, the Site map or Intruder, right-click a message → **Send to
   Anonymizer**. Select several first to send them all.
2. In the Anonymizer tab, review the **Anonymized** pane. Blue is a placeholder; yellow is "check
   this", a value a disabled detector would have caught. Toggle detectors or add client terms
   (select text in any editor → **Add selection as client term**); the output re-renders live.
3. **Copy**, or select several items → **Copy all as Markdown**, and paste into the LLM.
4. Paste the LLM's reply into **Restore** → **Restore**. Unknown placeholders are left in place and
   listed (restore never invents a value); lenient matches are highlighted; a JWT whose claims the
   LLM edited is flagged rather than guessed. Then **Send to Repeater**.

The session map lives with the Burp project. Temporary projects (Burp Community) lose it on close:
**Export** it first, **Import** it later. Clearing the map restarts numbering; nothing else does.
Detector toggles follow you across projects; client terms stay with the project.


## Building

Requires JDK 21 (Gradle provisions one if missing) and the Montoya API (compile-only; never bundled).

```
./gradlew shadowJar      # → build/libs/anonymizer-<version>-all.jar
./gradlew test           # engine fixtures + unit tests
```

Load the JAR in Burp via Extensions → Installed → Add. After rebuilding, use Remove and Add; Burp's
auto-reload does not pick up a rebuilt JAR.

## Design

The engine (`com.anonymizer.engine`) is pure Kotlin with no Burp dependency; it is text in, text out
and its behaviour is pinned by a fixture corpus (`src/test/resources/fixtures`). Every
anonymize/restore runs on one engine thread, so numbering is deterministic. JSON is rewritten in
place and line endings are kept per line, so key order, whitespace and malformed bodies survive
byte for byte.
See `docs/PLAN.md` for the full design and decision log.

## Licence

GPLv3. The Montoya API is compiled against under the Burp Suite licence and is not bundled.
