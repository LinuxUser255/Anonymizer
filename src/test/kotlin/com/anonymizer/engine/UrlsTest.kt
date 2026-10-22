package com.anonymizer.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/** URL split/rebuild quirks the URL mapper relies on; changing one changes anonymized URLs. */
class UrlsTest {
    private fun roundTrip(u: String): String = Urls.split(u).let { Urls.unsplit(it.scheme, it.netloc, it.path, it.query, it.fragment) }

    @Test
    fun `urlsplit and urlunsplit quirks`() {
        assertEquals("http://h/p", roundTrip("http://h/p?"))
        assertEquals("http://h/p", roundTrip("http://h/p#"))
        assertEquals("http://h?q", roundTrip("http://h?q"))
        assertEquals("http://H/P", roundTrip("HTTP://H/P"))
        assertEquals("http://h:/p", roundTrip("http://h:/p"))
        assertEquals("http://u@h/", roundTrip("http://u@h/"))
        assertEquals("http://h", roundTrip("http://h"))
        assertEquals("http://[::1]:8/x", roundTrip("http://[::1]:8/x"))
        assertEquals("ftp://h/a?b=c#d=e", roundTrip("ftp://h/a?b=c#d=e"))
        assertEquals("http:///x", roundTrip("http:///x"))
        assertEquals("http://h/p#f", roundTrip("http://h/p?#f"))
        assertEquals("http://h/p%20?x=%41#%42", roundTrip("http://h/p%20?x=%41#%42"))
        val s = Urls.split("ftp://h/a?b=c#d=e")
        assertEquals("b=c", s.query)
        assertEquals("d=e", s.fragment)
        assertEquals("/a", s.path)
    }

    @Test
    fun `malformed brackets are rejected`() {
        assertThrows(IllegalArgumentException::class.java) { Urls.split("http://[abc/") }
        assertThrows(IllegalArgumentException::class.java) { Urls.split("http://[1.2.3.4]/") }
        assertThrows(IllegalArgumentException::class.java) { Urls.split("http://[vx]/") }
        assertEquals("[2001:db8::1]:80", Urls.split("http://[2001:db8::1]:80/").netloc)
    }

    @Test
    fun `quote and unquote`() {
        assertEquals("a+b[1]%2F%C3%A9%2B%26%3D", Urls.quotePlus("a b[1]/é+&=", "[]"))
        assertEquals("a bAé%zz\uFFFDx", Urls.unquotePlus("a+b%41%c3%a9%zz%e9x"))
        assertEquals("user1%40target1.example", Urls.quotePlus("user1@target1.example", "[]"))
        assertEquals("%5BCOOKIE_1%5D", Urls.quotePlus("[COOKIE_1]", ""))
    }
}
