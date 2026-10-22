package com.anonymizer.engine

/**
 * Engine configuration. Carries the full config vocabulary even though the v1 UI only shows
 * toggles (see `docs/PLAN.md`, "Toggles are v1, not the ceiling"); [fromJson] and [toJson] use
 * snake_case key names, which fixtures and exported settings share.
 *
 * Immutable: build a new instance with `copy(...)` to change anything.
 */
public data class Settings(
    /** Client-identifying words → `[CLIENT_n]`; case-insensitive. */
    val terms: List<String> = emptyList(),
    /** Hosts kept verbatim (base domain and every subdomain). */
    val keepHosts: List<String> = emptyList(),
    /** Hosts whose base is kept but whose non-generic subdomains are still pseudonymised. */
    val keepBaseHosts: List<String> = emptyList(),
    /** Subdomain labels that carry no client identity and are kept. */
    val genericLabels: List<String> = emptyList(),
    /** Keep RFC1918 / loopback / link-local addresses untouched. */
    val keepPrivateIps: Boolean = false,
    /** Header names whose entire value is replaced. */
    val sensitiveHeaders: List<String> = emptyList(),
    /** Substrings that mark a header as sensitive. */
    val sensitiveHeaderSubstrings: List<String> = emptyList(),
    /** Headers excluded from the substring rule. */
    val nonsensitiveHeaders: List<String> = emptyList(),
    /** Substrings (normalised key) that mark a field as sensitive. */
    val sensitiveKeySubstrings: List<String> = emptyList(),
    /** Exact normalised keys that are sensitive. */
    val sensitiveKeysExact: List<String> = emptyList(),
    /** Normalised keys that are never sensitive even if they match above. */
    val nonsensitiveKeys: List<String> = emptyList(),
    /** Cookie names whose value is kept. */
    val keepCookies: List<String> = emptyList(),
    /** Extra secret regexes merged with the built-in list. */
    val secretPatterns: List<String> = emptyList(),
    /** Per-detector on/off; a missing name means on. See [DETECTOR_NAMES]. */
    val detect: Map<String, Boolean> = emptyMap(),
    /** Minimum length for the hex detector. */
    val minHexLen: Int = 32,
    /** Recompute `Content-Length` when a body changed. */
    val updateContentLength: Boolean = true,
) {
    /** Whether detector [name] is enabled (missing means enabled). */
    public fun isOn(name: String): Boolean = detect[name] ?: true

    /** Serialises with the snake_case key names; the inverse of [fromJson]. */
    public fun toJson(): Map<String, Any?> = linkedMapOf(
        "terms" to terms,
        "keep_hosts" to keepHosts,
        "keep_base_hosts" to keepBaseHosts,
        "generic_labels" to genericLabels,
        "keep_private_ips" to keepPrivateIps,
        "sensitive_headers" to sensitiveHeaders,
        "sensitive_header_substrings" to sensitiveHeaderSubstrings,
        "nonsensitive_headers" to nonsensitiveHeaders,
        "sensitive_key_substrings" to sensitiveKeySubstrings,
        "sensitive_keys_exact" to sensitiveKeysExact,
        "nonsensitive_keys" to nonsensitiveKeys,
        "keep_cookies" to keepCookies,
        "secret_patterns" to secretPatterns,
        "detect" to detect,
        "min_hex_len" to minHexLen,
        "update_content_length" to updateContentLength,
    )

    public companion object {
        /**
         * Detector names understood by [isOn]. The first fourteen gate value detectors; `auth`,
         * `cookies`, `headers` and `fields` gate the structural handlers behind the UI toggles.
         */
        public val DETECTOR_NAMES: List<String> = listOf(
            "jwt", "url", "email", "host", "ipv4", "ipv6", "uuid", "hex", "card", "ssn", "phone",
            "blob", "secrets", "terms", "auth", "cookies", "headers", "fields",
        )

        /** Every detector on, private IPs mapped: the baseline the fixture corpus assumes. */
        public val FIXTURE_DEFAULTS: Settings = Settings(
            terms = emptyList(),
            keepHosts = listOf(
                "localhost", "example.com", "example.org", "example.net", "w3.org", "schema.org",
                "xmlsoap.org", "openxmlformats.org", "purl.org", "ietf.org", "mozilla.org",
                "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
                "google-analytics.com", "doubleclick.net", "cloudflare.com",
                "cloudflareinsights.com", "jquery.com", "jsdelivr.net", "unpkg.com",
                "bootstrapcdn.com", "fontawesome.com", "github.com", "githubusercontent.com",
                "microsoft.com", "apple.com", "facebook.com", "twitter.com", "x.com", "youtube.com",
                "linkedin.com", "wikipedia.org", "gmail.com", "portswigger.net",
                "burpcollaborator.net", "oastify.com", "interact.sh", "ngrok.io",
            ),
            keepBaseHosts = listOf(
                "amazonaws.com", "cloudfront.net", "azurewebsites.net", "windows.net", "azure.com",
                "azureedge.net", "herokuapp.com", "github.io", "okta.com", "auth0.com",
                "salesforce.com", "force.com", "sharepoint.com", "onmicrosoft.com", "cloudapp.net",
                "appspot.com", "firebaseio.com", "akamaized.net", "akamaihd.net", "fastly.net",
                "netlify.app", "vercel.app",
            ),
            genericLabels = listOf(
                "www", "api", "apis", "app", "apps", "auth", "login", "sso", "idp", "oauth", "id",
                "accounts", "account", "static", "cdn", "assets", "img", "images", "media", "mail",
                "smtp", "imap", "admin", "dev", "develop", "staging", "stage", "stg", "prod",
                "production", "test", "testing", "uat", "qa", "m", "mobile", "portal", "my", "secure",
                "shop", "store", "blog", "docs", "help", "support", "status", "internal", "intranet",
                "vpn", "git", "gitlab", "jenkins", "ci", "ws", "wss", "graphql", "beta", "demo",
                "sandbox", "preview", "gateway", "gw", "proxy", "edge", "web", "web1", "web2", "s3",
                "storage", "files", "upload", "uploads", "download", "downloads", "fonts", "ajax",
                "code", "maps", "graph", "login-us", "ns1", "ns2", "mx", "mx1", "mx2", "ftp", "sftp",
                "autodiscover", "owa", "mail1", "mail2", "exchange", "remote", "citrix", "rdp", "dc",
                "dc1", "dc2", "ad", "ldap",
            ),
            keepPrivateIps = false,
            sensitiveHeaders = listOf(
                "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token", "x-refresh-token",
                "x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token", "x-session-id",
                "x-session-token", "x-amz-security-token", "x-amz-credential", "x-amz-signature",
                "x-client-secret", "x-signature", "x-hub-signature", "x-hub-signature-256",
                "x-slack-signature", "x-shopify-access-token", "x-auth", "x-auth-key", "x-api-token",
                "x-token", "x-user-token", "x-identity-token", "x-ms-authorization", "x-goog-api-key",
                "x-pingother", "x-aspnet-version", "ocp-apim-subscription-key",
            ),
            sensitiveHeaderSubstrings = listOf(
                "token", "secret", "apikey", "api-key", "csrf", "xsrf", "session", "signature",
                "credential", "password", "passwd",
            ),
            nonsensitiveHeaders = listOf(
                "www-authenticate", "content-security-policy", "content-security-policy-report-only",
            ),
            sensitiveKeySubstrings = listOf(
                "password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey",
                "privatekey", "clientsecret", "credential", "auth", "session", "csrf", "xsrf", "ssn",
                "socialsecurity", "creditcard", "cardnumber", "ccnumber", "cvv", "cvc", "iban",
                "swift", "bic", "accountnumber", "routing", "sortcode", "dob", "dateofbirth",
                "birthdate", "birthday", "phone", "mobile", "email", "firstname", "lastname",
                "fullname", "givenname", "familyname", "surname", "displayname", "username", "userid",
                "address", "street", "zipcode", "postcode", "postal", "latitude", "longitude", "otp",
                "signature", "hmac", "nonce", "salt", "passport", "nationalid", "taxid",
                "licensenumber", "driverslicense", "securityanswer", "companyname", "organization",
                "organisation", "orgname", "employer", "bearer", "refresh", "idtoken", "mfa", "totp",
                "recovery", "cookie", "ipaddress", "clientip", "remoteaddr", "hostname",
            ),
            sensitiveKeysExact = listOf(
                "name", "user", "login", "pin", "sub", "jti", "sid", "upn", "oid", "tid", "key", "pwd",
                "pass", "pw", "code", "state", "hash", "sig", "account", "acct", "acctid", "accountid",
                "customerid", "company", "org", "tenant", "domain", "host", "ip", "lat", "lng", "lon",
                "zip", "tel", "cell", "fax", "ein", "vat", "card", "pan", "exp", "expiry", "ccexp",
                "answer", "question", "mothersmaidenname", "fname", "lname", "mname", "middlename",
                "nickname", "handle", "alias", "owner", "author", "creator", "contact", "recipient",
                "sender", "from", "to", "cc", "bcc", "realm", "uid", "guid", "uuid",
            ),
            nonsensitiveKeys = listOf(
                "contenttype", "tokentype", "authtype", "sessiontimeout", "emailverified",
                "phoneverified", "exp", "iat", "nbf", "statecode", "statename", "hashalgorithm",
                "keytype", "codepage", "statuscode", "errorcode", "countrycode", "currencycode",
                "languagecode", "zipformat", "fromdate", "todate", "ccy", "owner_type", "ownertype",
                "authmethod", "authenticated", "authorized",
            ),
            keepCookies = emptyList(),
            secretPatterns = emptyList(),
            detect = linkedMapOf(
                "jwt" to true, "url" to true, "email" to true, "host" to true, "ipv4" to true,
                "ipv6" to true, "uuid" to true, "hex" to true, "card" to true, "ssn" to true,
                "phone" to true, "blob" to true, "secrets" to true, "terms" to true,
            ),
            minHexLen = 32,
            updateContentLength = true,
        )

        /**
         * The extension's v1 defaults (`docs/PLAN.md`, toggle table): [FIXTURE_DEFAULTS] with
         * private IPs kept, phone numbers and opaque blobs off.
         */
        public val EXTENSION_DEFAULTS: Settings = FIXTURE_DEFAULTS.copy(
            keepPrivateIps = true,
            detect = FIXTURE_DEFAULTS.detect + mapOf("phone" to false, "blob" to false),
        )

        /**
         * Reads a settings object using the snake_case key names. Keys present in [json] replace
         * the corresponding value of [base] wholesale (list keys are not merged). Unknown keys are
         * ignored.
         */
        public fun fromJson(json: Map<String, Any?>, base: Settings = FIXTURE_DEFAULTS): Settings {
            fun strings(key: String, fallback: List<String>): List<String> {
                val v = json[key] ?: return fallback
                if (!json.containsKey(key)) return fallback
                return (v as? List<*>)?.map { it.toString() } ?: fallback
            }

            fun bool(key: String, fallback: Boolean): Boolean = (json[key] as? Boolean) ?: fallback
            fun int(key: String, fallback: Int): Int = when (val v = json[key]) {
                is JsonNumber -> v.raw.toIntOrNull() ?: fallback
                is Number -> v.toInt()
                else -> fallback
            }

            val detect: Map<String, Boolean> = when (val d = json["detect"]) {
                is Map<*, *> -> d.entries
                    .filter { it.value is Boolean }
                    .associate { it.key.toString() to (it.value as Boolean) }
                else -> base.detect
            }
            return base.copy(
                terms = strings("terms", base.terms),
                keepHosts = strings("keep_hosts", base.keepHosts),
                keepBaseHosts = strings("keep_base_hosts", base.keepBaseHosts),
                genericLabels = strings("generic_labels", base.genericLabels),
                keepPrivateIps = bool("keep_private_ips", base.keepPrivateIps),
                sensitiveHeaders = strings("sensitive_headers", base.sensitiveHeaders),
                sensitiveHeaderSubstrings = strings("sensitive_header_substrings", base.sensitiveHeaderSubstrings),
                nonsensitiveHeaders = strings("nonsensitive_headers", base.nonsensitiveHeaders),
                sensitiveKeySubstrings = strings("sensitive_key_substrings", base.sensitiveKeySubstrings),
                sensitiveKeysExact = strings("sensitive_keys_exact", base.sensitiveKeysExact),
                nonsensitiveKeys = strings("nonsensitive_keys", base.nonsensitiveKeys),
                keepCookies = strings("keep_cookies", base.keepCookies),
                secretPatterns = strings("secret_patterns", base.secretPatterns),
                detect = detect,
                minHexLen = int("min_hex_len", base.minHexLen),
                updateContentLength = bool("update_content_length", base.updateContentLength),
            )
        }
    }
}
