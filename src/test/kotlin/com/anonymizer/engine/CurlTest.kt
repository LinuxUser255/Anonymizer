package com.anonymizer.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** "Copy as curl": the command is built from anonymized text only, and Restore brings it back. */
class CurlTest {
    private val login = "POST /api/login?next=%2Fhome HTTP/1.1\r\n" +
        "Host: portal.acmecorp.com\r\n" +
        "Cookie: session=4f3c2b1a9d; lang=en\r\n" +
        "Authorization: Bearer abc123def456\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: 55\r\n" +
        "\r\n" +
        "{\"email\":\"j.smith@acmecorp.com\",\"password\":\"Winter2024!\"}"

    @Test
    fun `request becomes a bash curl command`() {
        val text = "POST /a?b=1 HTTP/1.1\r\nHost: h.example:8443\r\nX-Empty:\r\nAccept: */*\r\nContent-Length: 9\r\n\r\nit's\r\na\\b\u0001"
        assertEquals(
            "curl --path-as-is -i -s -k -X \$'POST' \\\n" +
                "    -H \$'X-Empty;' \\\n" +
                "    -H \$'Accept: */*' \\\n" +
                "    --data-binary \$'it\\'s\\r\\na\\\\b\\x01' \\\n" +
                "    \$'https://h.example:8443/a?b=1'",
            Curl.fromRequest(text, secure = true),
        )
    }

    @Test
    fun `scheme, absolute target, HEAD and missing body`() {
        assertEquals(
            "curl --path-as-is -i -s -k -X \$'GET' \\\n    \$'http://h.example/x'",
            Curl.fromRequest("GET /x HTTP/1.1\nHost: h.example\n\n", secure = false),
        )
        assertEquals(
            "curl --path-as-is -i -s -k --head \\\n    \$'http://proxy.example/y'",
            Curl.fromRequest("HEAD http://proxy.example/y HTTP/1.1\r\nHost: other.example\r\n\r\n", secure = true),
        )
    }

    @Test
    fun `a body line that looks like a start line stays in the body`() {
        val out = Curl.fromRequest("POST /x HTTP/1.1\nHost: h.example\n\na=1\n\nGET /y HTTP/1.1\nHost: z.example\n", secure = true)
        assertTrue(out!!.contains("--data-binary \$'a=1\\n\\nGET /y HTTP/1.1\\nHost: z.example\\n'"), out)
    }

    @Test
    fun `no command without a request line or a host in the text`() {
        assertNull(Curl.fromRequest("HTTP/1.1 200 OK\r\nServer: x\r\n\r\nhi", secure = true))
        assertNull(Curl.fromRequest("just some text", secure = true))
        // The real service host is deliberately not an input: no Host header means no URL, not a leak.
        assertNull(Curl.fromRequest("GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n", secure = true))
    }

    @Test
    fun `curl of anonymized text leaks nothing and restores to the curl of the original`() {
        val mapping = Mapping()
        val anonymized = Anonymizer(Settings.FIXTURE_DEFAULTS, mapping).anonymize(login)
        val curl = Curl.fromRequest(anonymized, secure = true)!!
        for (secret in listOf("acmecorp", "4f3c2b1a9d", "abc123def456", "Winter2024", "j.smith")) {
            assertFalse(curl.contains(secret), "leaked $secret in: $curl")
        }
        assertTrue(curl.endsWith("\$'https://portal.target1.example/api/login?next=%2Fhome'"), curl)
        assertTrue(curl.contains("-H \$'Authorization: Bearer [TOKEN_1]'"), curl)
        assertFalse(curl.contains("Content-Length"), curl)
        val restored = Restorer(mapping.snapshot()).restore(curl, lenient = false)
        assertEquals(Curl.fromRequest(login, secure = true), restored.text)
    }
}
