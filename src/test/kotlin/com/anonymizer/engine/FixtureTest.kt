package com.anonymizer.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.fail
import java.io.File
import java.util.Base64

/**
 * Runs the fixture corpus (every `.json` under `src/test/resources/fixtures`), the engine's
 * behaviour contract; see docs/PLAN.md, "Fixture corpus".
 */
class FixtureTest {
    private val contentLength = Regex("Content-Length: \\d+")

    @TestFactory
    fun fixtures(): List<DynamicTest> {
        val root = fixturesDir()
        val files = root.walkTopDown().filter { it.isFile && it.extension == "json" }.sortedBy { it.path }.toList()
        assertTrue(files.isNotEmpty(), "no fixtures found under $root")
        return files.map { f -> DynamicTest.dynamicTest(f.relativeTo(root).path) { runFixture(f) } }
    }

    private fun fixturesDir(): File {
        val url = javaClass.classLoader.getResource("fixtures") ?: fail("fixtures resource directory missing")
        return File(url.toURI())
    }

    @Suppress("UNCHECKED_CAST")
    private fun runFixture(file: File) {
        val data = JsonParser.parseOrNull(file.readText(Charsets.UTF_8))?.toValue() as? Map<String, Any?>
            ?: fail("${file.name}: not a JSON object")
        val settings = Settings.fromJson((data["settings"] as? Map<String, Any?>) ?: emptyMap(), Settings.FIXTURE_DEFAULTS)
        val mapping = Mapping()
        val anonymizer = Anonymizer(settings, mapping)
        val steps = data["steps"] as? List<Map<String, Any?>> ?: fail("${file.name}: no steps")
        val done = ArrayList<Pair<String, String>>() // input, output
        for ((i, step) in steps.withIndex()) {
            val input = resolve(step["input"], file, done)
            val op = step["op"] as? String
            val where = "${file.name} step $i"
            var flags: Restorer.Result? = null
            val output = when (op) {
                "anonymize" -> anonymizer.anonymize(input)
                "restore" -> {
                    val r = Restorer(mapping.snapshot()).restore(input, lenient = step["lenient"] == true)
                    flags = r
                    r.text
                }
                else -> fail("$where: unknown op $op")
            }
            done.add(input to output)
            val expect = step["expect"] as? Map<String, Any?> ?: emptyMap()
            check(output, expect, file, done, where, flags)
        }
        val wantMapping = data["mapping"] as? Map<String, Any?> ?: emptyMap()
        val snap = mapping.snapshot()
        for ((cat, pairs) in wantMapping) {
            val have = snap.forward[cat] ?: emptyMap()
            for ((orig, ph) in pairs as Map<String, Any?>) {
                assertEquals(ph, have[orig], "${file.name}: mapping[$cat][$orig]")
            }
        }
        val wantCounters = data["counters"] as? Map<String, Any?> ?: emptyMap()
        for ((cat, n) in wantCounters) {
            assertEquals((n as JsonNumber).raw.toInt(), snap.counters[cat] ?: 0, "${file.name}: counters[$cat]")
        }
    }

    private fun resolve(ref: Any?, file: File, done: List<Pair<String, String>>): String {
        val s = ref as? String ?: fail("${file.name}: reference must be a string: $ref")
        if (s.startsWith("@file:")) return File(file.parentFile, s.removePrefix("@file:")).readText(Charsets.UTF_8)
        val m = Regex("@step\\[(\\d+)\\]\\.(input|output)").matchEntire(s)
        if (m != null) {
            val step = done[m.groupValues[1].toInt()]
            return if (m.groupValues[2] == "input") step.first else step.second
        }
        return s
    }

    @Suppress("UNCHECKED_CAST")
    private fun check(
        out: String,
        expect: Map<String, Any?>,
        file: File,
        done: List<Pair<String, String>>,
        where: String,
        flags: Restorer.Result?,
    ) {
        expect["equals"]?.let { ref ->
            val want = resolve(ref, file, done)
            if (out != want) fail("$where: equals mismatch at ${firstDiff(out, want)}")
        }
        expect["equalsModuloContentLength"]?.let { ref ->
            val want = resolve(ref, file, done)
            val a = contentLength.replace(out, "Content-Length: *")
            val b = contentLength.replace(want, "Content-Length: *")
            if (a != b) fail("$where: equalsModuloContentLength mismatch at ${firstDiff(a, b)}")
        }
        for (s in (expect["contains"] as? List<String>) ?: emptyList()) {
            if (s !in out) fail("$where: missing ${repr(s)} in ${repr(out)}")
        }
        for (s in (expect["notContains"] as? List<String>) ?: emptyList()) {
            if (s in out) fail("$where: leaked ${repr(s)}")
        }
        (expect["jwtClaims"] as? Map<String, Any?>)?.let { jc ->
            val hdr = jc["header"] as String
            val line = out.lines().firstOrNull { it.lowercase().startsWith(hdr.lowercase() + ":") }
                ?: fail("$where: no $hdr header for jwtClaims")
            val tok = line.trim().substringAfterLast(' ')
            val seg = tok.split(".")[1]
            val pay = String(Base64.getUrlDecoder().decode(seg), Charsets.UTF_8)
            for (s in (jc["contains"] as? List<String>) ?: emptyList()) {
                if (s !in pay) fail("$where: jwt payload missing ${repr(s)} (payload ${repr(pay)})")
            }
            for (s in (jc["notContains"] as? List<String>) ?: emptyList()) {
                if (s in pay) fail("$where: jwt payload leaked ${repr(s)} (payload ${repr(pay)})")
            }
        }
        (expect["flags"] as? Map<String, Any?>)?.let { fl ->
            val r = flags ?: fail("$where: flags expected on a non-restore step")
            (fl["unknown"] as? List<String>)?.let { want ->
                assertEquals(want.sorted(), r.unknown.map { it.token }.sorted(), "$where: unknown placeholders")
            }
            (fl["lenient"] as? JsonNumber)?.let { want ->
                assertEquals(want.raw.toInt(), r.lenient.size, "$where: lenient match count (${r.lenient.map { it.token }})")
            }
            (fl["modifiedJwt"] as? JsonNumber)?.let { want ->
                assertEquals(want.raw.toInt(), r.modifiedJwts.size, "$where: modified JWT count")
            }
        }
    }

    private fun firstDiff(a: String, b: String): String {
        val n = minOf(a.length, b.length)
        for (i in 0 until n) {
            if (a[i] != b[i]) {
                val from = maxOf(0, i - 20)
                return "offset $i: expected ${repr(b.substring(from, minOf(b.length, i + 40)))} got ${repr(a.substring(from, minOf(a.length, i + 40)))}"
            }
        }
        return "length differs: expected ${b.length} got ${a.length} (tail expected ${repr(b.takeLast(40))}, got ${repr(a.takeLast(40))})"
    }

    private fun repr(s: String): String = JsonWriter.encodeString(s)
}
