package net.portswigger.mcp.schema

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

private const val MAX_HISTORY_ITEM_LENGTH = 5_000
private const val TRUNCATION_MARKER = "... (truncated)"

private val historyJson = Json { explicitNulls = false }

internal inline fun <reified T> encodeHistoryItem(item: T, maxItemLength: Int? = null): String =
    limitHistoryItemJson(historyJson.encodeToString(item), maxItemLength ?: MAX_HISTORY_ITEM_LENGTH)

@PublishedApi
internal fun limitHistoryItemJson(serialized: String, maxLength: Int = MAX_HISTORY_ITEM_LENGTH): String {
    if (serialized.length <= maxLength) return serialized

    val item = Json.parseToJsonElement(serialized)
    var lowerBound = TRUNCATION_MARKER.length
    var upperBound = serialized.length
    var best: String? = null

    while (lowerBound <= upperBound) {
        val fieldLimit = (lowerBound + upperBound) / 2
        val candidate = Json.encodeToString(
            JsonElement.serializer(), item.truncateStringsTo(fieldLimit).dropNulls()
        )

        if (candidate.length <= maxLength) {
            best = candidate
            lowerBound = fieldLimit + 1
        } else {
            upperBound = fieldLimit - 1
        }
    }

    val truncated = checkNotNull(best) {
        "History item JSON structure exceeds the $maxLength character limit"
    }

    val parsed = Json.parseToJsonElement(truncated)
    return if (parsed is JsonObject) {
        Json.encodeToString(JsonElement.serializer(), JsonObject(parsed + ("_truncated" to JsonPrimitive(true))))
    } else {
        truncated
    }
}

private fun JsonElement.truncateStringsTo(maxLength: Int): JsonElement = when (this) {
    is JsonObject -> JsonObject(mapValues { (_, value) -> value.truncateStringsTo(maxLength) })
    is JsonArray -> JsonArray(map { it.truncateStringsTo(maxLength) })
    is JsonPrimitive -> if (isString) JsonPrimitive(content.truncateTo(maxLength)) else this
}

private fun JsonElement.dropNulls(): JsonElement = when (this) {
    is JsonObject -> JsonObject(entries
        .filter { (_, v) -> v !is JsonNull }
        .associate { (k, v) -> k to v.dropNulls() })
    is JsonArray -> JsonArray(map { it.dropNulls() })
    else -> this
}

private fun String.truncateTo(maxLength: Int): String {
    if (length <= maxLength) return this

    var prefixLength = maxLength - TRUNCATION_MARKER.length
    if (prefixLength > 0 && this[prefixLength - 1].isHighSurrogate() && this[prefixLength].isLowSurrogate()) {
        prefixLength--
    }
    return take(prefixLength) + TRUNCATION_MARKER
}
