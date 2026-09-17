package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.organizer.OrganizerItem
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

// ---------------------------------------------------------------------------
// Filter extension functions — applied before serialisation so we only encode
// items the caller actually wants.
// ---------------------------------------------------------------------------

private fun ProxyHttpRequestResponse.matchesFilter(
    inScopeOnly: Boolean?,
    hosts: List<String>?,
    methods: List<String>?,
    statusCodes: List<Int>?,
    excludeExtensions: List<String>?,
    mimeTypes: List<String>?,
    highlightColor: String?,
    hasHighlight: Boolean?,
    editedOnly: Boolean?,
    hasNotes: Boolean?,
    pathContains: String?,
): Boolean {
    if (inScopeOnly == true && !request().isInScope()) return false
    if (!hosts.isNullOrEmpty() && !hosts.any { it.equals(request().httpService().host(), ignoreCase = true) }) return false
    if (!methods.isNullOrEmpty() && !methods.any { it.equals(request().method(), ignoreCase = true) }) return false
    if (!statusCodes.isNullOrEmpty()) {
        if (!hasResponse()) return false
        val sc = response()?.statusCode()?.toInt() ?: return false
        if (!statusCodes.contains(sc)) return false
    }
    if (!excludeExtensions.isNullOrEmpty()) {
        val ext = request().fileExtension()
        if (ext.isNotEmpty() && excludeExtensions.any { it.equals(ext, ignoreCase = true) }) return false
    }
    if (!mimeTypes.isNullOrEmpty() && !mimeTypes.any { it.equals(mimeType().name, ignoreCase = true) }) return false
    if (highlightColor != null && !annotations().highlightColor().name.equals(highlightColor, ignoreCase = true)) return false
    if (hasHighlight != null && annotations().hasHighlightColor() != hasHighlight) return false
    if (editedOnly == true && !edited()) return false
    if (hasNotes != null && annotations().hasNotes() != hasNotes) return false
    if (pathContains != null && !request().path().contains(pathContains, ignoreCase = true)) return false
    return true
}

private fun OrganizerItem.matchesFilter(
    hosts: List<String>?,
    methods: List<String>?,
    statusCodes: List<Int>?,
    highlightColor: String?,
    hasHighlight: Boolean?,
    hasNotes: Boolean?,
    pathContains: String?,
): Boolean {
    if (!hosts.isNullOrEmpty() && !hosts.any { it.equals(request()?.httpService()?.host(), ignoreCase = true) }) return false
    if (!methods.isNullOrEmpty() && !methods.any { it.equals(request()?.method(), ignoreCase = true) }) return false
    if (!statusCodes.isNullOrEmpty()) {
        val sc = response()?.statusCode()?.toInt() ?: return false
        if (!statusCodes.contains(sc)) return false
    }
    if (highlightColor != null && !annotations().highlightColor().name.equals(highlightColor, ignoreCase = true)) return false
    if (hasHighlight != null && annotations().hasHighlightColor() != hasHighlight) return false
    if (hasNotes != null && annotations().hasNotes() != hasNotes) return false
    if (pathContains != null && request()?.path()?.contains(pathContains, ignoreCase = true) != true) return false
    return true
}

private fun ProxyWebSocketMessage.matchesFilter(
    hosts: List<String>?,
    directionFilter: String?,
    highlightColor: String?,
    hasHighlight: Boolean?,
    hasNotes: Boolean?,
): Boolean {
    if (!hosts.isNullOrEmpty() && !hosts.any { it.equals(upgradeRequest().httpService().host(), ignoreCase = true) }) return false
    if (directionFilter != null && !direction().name.equals(directionFilter, ignoreCase = true)) return false
    if (highlightColor != null && !annotations().highlightColor().name.equals(highlightColor, ignoreCase = true)) return false
    if (hasHighlight != null && annotations().hasHighlightColor() != hasHighlight) return false
    if (hasNotes != null && annotations().hasNotes() != hasNotes) return false
    return true
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner. Returns total count, items returned, and next offset for pagination.") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        mcpTool(
            "get_scanner_issue_count",
            "Returns the total number of issues found by the Burp scanner."
        ) {
            api.siteMap().issues().size.toString()
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Proxy HTTP history
    // -----------------------------------------------------------------------

    mcpTool(
        "get_proxy_history_count",
        "Returns the total number of items in the proxy HTTP history. Use this before paginating to know the total."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpTool "HTTP history access denied by Burp Suite"
        api.proxy().history().size.toString()
    }

    mcpPaginatedTool<GetProxyHttpHistory>(
        "Displays items within the proxy HTTP history. Returns a JSON object with total, returned, offset, " +
        "optional nextOffset, and an items array. Returns newest items first by default. " +
        "Filters: hosts (hostnames), methods ([\"POST\",\"PUT\"]), statusCodes ([200,401,403]), " +
        "excludeExtensions ([\"js\",\"css\"]), mimeTypes ([\"JSON\",\"HTML\"]), " +
        "pathContains (substring match on URL path, e.g. \"/api/v2/\"), " +
        "highlightColor (RED/ORANGE/YELLOW/GREEN/CYAN/BLUE/PINK/MAGENTA/GRAY), " +
        "hasHighlight, editedOnly, hasNotes, inScopeOnly. " +
        "Set headersOnly=true to omit request/response bodies (saves tokens for large JSON APIs). " +
        "Set maxItemLength to raise the 5000-char per-item truncation limit for large cookie jars. " +
        "Items with _truncated:true were cut to fit the limit."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")

        api.proxy().history()
            .let { list -> if (newestFirst != false) list.asReversed() else list }
            .filter { it.matchesFilter(inScopeOnly, hosts, methods, statusCodes, excludeExtensions, mimeTypes, highlightColor, hasHighlight, editedOnly, hasNotes, pathContains) }
            .asSequence()
            .map { encodeHistoryItem(it.toSerializableForm(headersOnly == true), maxItemLength) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Displays proxy HTTP history items whose raw content matches the given regex. " +
        "Supports caseInsensitive flag, headersOnly, pathContains, and all filters from get_proxy_http_history. " +
        "Returns newest items first by default. Output is the same JSON envelope as get_proxy_http_history."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")

        val flags = if (caseInsensitive == true) Pattern.CASE_INSENSITIVE else 0
        val compiledRegex = Pattern.compile(regex, flags)

        api.proxy().history { it.contains(compiledRegex) }
            .let { list -> if (newestFirst != false) list.asReversed() else list }
            .filter { it.matchesFilter(inScopeOnly, hosts, methods, statusCodes, excludeExtensions, mimeTypes, highlightColor, hasHighlight, editedOnly, hasNotes, pathContains) }
            .asSequence()
            .map { encodeHistoryItem(it.toSerializableForm(headersOnly == true), maxItemLength) }
    }

    // -----------------------------------------------------------------------
    // Organizer
    // -----------------------------------------------------------------------

    mcpTool(
        "get_organizer_count",
        "Returns the total number of items in the Organizer tab. Use this before paginating to know the total."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) return@mcpTool "Organizer access denied by Burp Suite"
        api.organizer().items().size.toString()
    }

    mcpPaginatedTool<GetOrganizerItems>(
        "Displays items within the Organizer tab. Returns newest items first by default. " +
        "Supports filtering by: hosts, methods, statusCodes, highlightColor, hasHighlight, hasNotes."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")

        api.organizer().items()
            .let { list -> if (newestFirst != false) list.asReversed() else list }
            .filter { it.matchesFilter(hosts, methods, statusCodes, highlightColor, hasHighlight, hasNotes, pathContains) }
            .asSequence()
            .map { encodeHistoryItem(it.toSerializableForm(headersOnly == true), maxItemLength) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>(
        "Displays Organizer items whose raw content matches the given regex. " +
        "Supports caseInsensitive flag and all filters from get_organizer_items."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")

        val flags = if (caseInsensitive == true) Pattern.CASE_INSENSITIVE else 0
        val compiledRegex = Pattern.compile(regex, flags)

        api.organizer().items { it.contains(compiledRegex) }
            .let { list -> if (newestFirst != false) list.asReversed() else list }
            .filter { it.matchesFilter(hosts, methods, statusCodes, highlightColor, hasHighlight, hasNotes, pathContains) }
            .asSequence()
            .map { encodeHistoryItem(it.toSerializableForm(headersOnly == true), maxItemLength) }
    }

    // -----------------------------------------------------------------------
    // Proxy WebSocket history
    // -----------------------------------------------------------------------

    mcpTool(
        "get_websocket_history_count",
        "Returns the total number of items in the proxy WebSocket history. Use this before paginating to know the total."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) return@mcpTool "WebSocket history access denied by Burp Suite"
        api.proxy().webSocketHistory().size.toString()
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>(
        "Displays items within the proxy WebSocket history. Returns newest items first by default. " +
        "Supports filtering by: hosts (upgrade request hostname), " +
        "direction (CLIENT_TO_SERVER or SERVER_TO_CLIENT), " +
        "highlightColor, hasHighlight, hasNotes."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")

        api.proxy().webSocketHistory()
            .let { list -> if (newestFirst != false) list.asReversed() else list }
            .filter { it.matchesFilter(hosts, direction, highlightColor, hasHighlight, hasNotes) }
            .asSequence()
            .map { encodeHistoryItem(it.toSerializableForm(), maxItemLength) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>(
        "Displays proxy WebSocket history items whose raw content matches the given regex. " +
        "Supports caseInsensitive flag and all filters from get_proxy_websocket_history."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")

        val flags = if (caseInsensitive == true) Pattern.CASE_INSENSITIVE else 0
        val compiledRegex = Pattern.compile(regex, flags)

        api.proxy().webSocketHistory { it.contains(compiledRegex) }
            .let { list -> if (newestFirst != false) list.asReversed() else list }
            .filter { it.matchesFilter(hosts, direction, highlightColor, hasHighlight, hasNotes) }
            .asSequence()
            .map { encodeHistoryItem(it.toSerializableForm(), maxItemLength) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

// ---------------------------------------------------------------------------
// History data classes — filter fields are all nullable (optional in schema)
// ---------------------------------------------------------------------------

@Serializable
data class GetProxyHttpHistory(
    override val count: Int,
    override val offset: Int,
    val newestFirst: Boolean? = null,
    val inScopeOnly: Boolean? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val statusCodes: List<Int>? = null,
    val excludeExtensions: List<String>? = null,
    val mimeTypes: List<String>? = null,
    val highlightColor: String? = null,
    val hasHighlight: Boolean? = null,
    val editedOnly: Boolean? = null,
    val hasNotes: Boolean? = null,
    val pathContains: String? = null,
    val headersOnly: Boolean? = null,
    val maxItemLength: Int? = null,
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val caseInsensitive: Boolean? = null,
    val newestFirst: Boolean? = null,
    val inScopeOnly: Boolean? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val statusCodes: List<Int>? = null,
    val excludeExtensions: List<String>? = null,
    val mimeTypes: List<String>? = null,
    val highlightColor: String? = null,
    val hasHighlight: Boolean? = null,
    val editedOnly: Boolean? = null,
    val hasNotes: Boolean? = null,
    val pathContains: String? = null,
    val headersOnly: Boolean? = null,
    val maxItemLength: Int? = null,
) : Paginated

@Serializable
data class GetOrganizerItems(
    override val count: Int,
    override val offset: Int,
    val newestFirst: Boolean? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val statusCodes: List<Int>? = null,
    val highlightColor: String? = null,
    val hasHighlight: Boolean? = null,
    val hasNotes: Boolean? = null,
    val pathContains: String? = null,
    val headersOnly: Boolean? = null,
    val maxItemLength: Int? = null,
) : Paginated

@Serializable
data class GetOrganizerItemsRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val caseInsensitive: Boolean? = null,
    val newestFirst: Boolean? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val statusCodes: List<Int>? = null,
    val highlightColor: String? = null,
    val hasHighlight: Boolean? = null,
    val hasNotes: Boolean? = null,
    val pathContains: String? = null,
    val headersOnly: Boolean? = null,
    val maxItemLength: Int? = null,
) : Paginated

@Serializable
data class GetProxyWebsocketHistory(
    override val count: Int,
    override val offset: Int,
    val newestFirst: Boolean? = null,
    val hosts: List<String>? = null,
    val direction: String? = null,
    val highlightColor: String? = null,
    val hasHighlight: Boolean? = null,
    val hasNotes: Boolean? = null,
    val maxItemLength: Int? = null,
) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val caseInsensitive: Boolean? = null,
    val newestFirst: Boolean? = null,
    val hosts: List<String>? = null,
    val direction: String? = null,
    val highlightColor: String? = null,
    val hasHighlight: Boolean? = null,
    val hasNotes: Boolean? = null,
    val maxItemLength: Int? = null,
) : Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
