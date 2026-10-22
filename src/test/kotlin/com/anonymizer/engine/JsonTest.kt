package com.anonymizer.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.util.Base64

/** The hand-written JSON reader/writer: what parses, what falls back, and exact output bytes. */
class JsonTest {
    @Test
    fun `accepts strict JSON plus NaN and Infinity, rejects the rest`() {
        assertNotNull(JsonParser.parseOrNull("""{"a":[1,2.5,-0,1e5,true,null,"xé\n"]}"""))
        assertNotNull(JsonParser.parseOrNull(" [NaN, Infinity, -Infinity] "))
        assertNull(JsonParser.parseOrNull("""{"a":1,}"""), "trailing comma")
        assertNull(JsonParser.parseOrNull("""{'a':1}"""), "single quotes")
        assertNull(JsonParser.parseOrNull("\"tab\there\""), "raw control char in string")
        assertNull(JsonParser.parseOrNull("01"), "leading zero")
        assertNull(JsonParser.parseOrNull(""), "empty")
        assertNull(JsonParser.parseOrNull("{} x"), "trailing data")
    }

    @Test
    fun `compact writer keeps non-ASCII and number text`() {
        val v = JsonParser.parseOrNull("""{"k":"q\"b\\s\/é\u0001","n":[1,-0,2.50,1E5],"t":true,"z":null,"e":{}}""")!!.toValue()
        assertEquals("""{"k":"q\"b\\s/é\u0001","n":[1,-0,2.50,1E5],"t":true,"z":null,"e":{}}""", JsonWriter.compact(v))
    }

    @Test
    fun `pretty writer indents by two`() {
        val v = linkedMapOf("forward" to linkedMapOf("host" to linkedMapOf("acme.com" to "target1.example")), "counters" to linkedMapOf("host" to 1))
        assertEquals(
            "{\n  \"forward\": {\n    \"host\": {\n      \"acme.com\": \"target1.example\"\n    }\n  },\n  \"counters\": {\n    \"host\": 1\n  }\n}",
            JsonWriter.pretty(v),
        )
        assertEquals("{\n  \"forward\": {},\n  \"counters\": {}\n}", JsonWriter.pretty(linkedMapOf("forward" to emptyMap<String, String>(), "counters" to emptyMap<String, Int>())))
    }

    @Test
    fun `canonical text of numbers`() {
        assertEquals("0", JsonNumber("-0").canonicalStr())
        assertEquals("1234", JsonNumber("1234").canonicalStr())
        assertEquals("100000.0", JsonNumber("1E5").canonicalStr())
        assertEquals("2.5", JsonNumber("2.50").canonicalStr())
        assertEquals("1e+16", JsonNumber("1e16").canonicalStr())
        assertEquals("1000000000000000.0", JsonNumber("1e15").canonicalStr())
        assertEquals("0.0001", JsonNumber("0.0001").canonicalStr())
        assertEquals("1e-05", JsonNumber("0.00001").canonicalStr())
        assertEquals("1.5e-07", JsonNumber("1.5e-7").canonicalStr())
        assertEquals("0.0", JsonNumber("0.0").canonicalStr())
        assertEquals("-0.0", JsonNumber("-0.0").canonicalStr())
        assertEquals("3.14", JsonNumber("3.14").canonicalStr())
    }

    @Test
    fun `mapping json round trips`() {
        val m = Mapping()
        m.get("host", "acme.com") { n -> "target$n.example" }
        m.get("email", "a@acme.com") { n -> "user$n@target1.example" }
        val json = m.toJson()
        val back = Mapping.fromJson(json)
        assertEquals(json, back.toJson())
        assertEquals("acme.com", back.originalOf("target1.example"))
        assertEquals(1, back.counter("email"))
    }

    @Test
    fun `non-string JWT kid is mapped by its JSON text`() {
        fun seg(s: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(s.toByteArray())
        val m = Mapping()
        Anonymizer(Settings.FIXTURE_DEFAULTS, m).jwt(seg("""{"alg":"HS256","kid":true}""") + "." + seg("""{"sub":"x"}""") + ".c2ln")
        assertEquals("true", m.snapshot().forward["field:KID"]?.keys?.single())
    }
}
