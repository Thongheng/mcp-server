package net.portswigger.mcp.schema

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HistoryItemJsonTest {
    @Test
    fun `small history items are unchanged`() {
        val item = HttpRequestResponse("request", "response", "notes")

        assertEquals(Json.encodeToString(item), encodeHistoryItem(item))
    }

    @Test
    fun `oversized history items remain valid bounded JSON`() {
        val encoded = encodeHistoryItem(
            HttpRequestResponse(
                request = "\\\"😀".repeat(2_000),
                response = "😀".repeat(3_000),
                notes = "keep me"
            )
        )
        val item = Json.parseToJsonElement(encoded).jsonObject

        assertTrue(item.keys.containsAll(setOf("request", "response", "notes", "_truncated")))
        assertTrue(item.getValue("request").jsonPrimitive.content.endsWith("... (truncated)"))
        assertTrue(item.getValue("response").jsonPrimitive.content.endsWith("... (truncated)"))
        assertEquals("keep me", item.getValue("notes").jsonPrimitive.content)
        assertEquals(true, item.getValue("_truncated").jsonPrimitive.boolean)
    }

    @Test
    fun `truncation does not split surrogate pairs`() {
        val encoded = encodeHistoryItem(HttpRequestResponse("a" + "😀".repeat(4_000), null, null))
        val request = Json.parseToJsonElement(encoded).jsonObject.getValue("request").jsonPrimitive.content

        assertFalse(request.codePoints().anyMatch { it in 0xD800..0xDFFF })
    }

    @Test
    fun `irreducible JSON fails instead of exceeding the limit`() {
        val oversizedKey = "a".repeat(5_000)

        assertThrows(IllegalStateException::class.java) {
            limitHistoryItemJson("{\"$oversizedKey\":0}")
        }
    }
}
