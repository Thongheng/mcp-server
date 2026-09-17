# Burp Suite MCP Server

Integrates Burp Suite with AI clients (Claude, Cursor, etc.) using the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). The extension runs a local MCP server inside Burp, exposing Burp's data and actions as tools that AI assistants can call directly.

---

## Installation

1. Build: `./gradlew embedProxyJar` → produces `build/libs/burp-mcp-all.jar`
2. Load the JAR as a Burp extension (Extensions → Add → Java)
3. Configure the MCP tab in Burp (host, port, approvals)
4. Point your AI client at the SSE endpoint:
   - Documented path: `http://127.0.0.1:9876/sse`
   - The server also serves the SSE stream at the root: `http://127.0.0.1:9876/` (verified working — clients that connect to `/` receive `event: endpoint` with the message URL `?sessionId=<uuid>`)

---

## Available Tools

### HTTP Requests

| Tool | Description |
|------|-------------|
| `send_http1_request` | Send an HTTP/1.1 request and return the response. Params: `content`, `targetHostname`, `targetPort`, `usesHttps` |
| `send_http2_request` | Send an HTTP/2 request and return the response. Params: `pseudoHeaders` (map), `headers` (map), `requestBody`, `targetHostname`, `targetPort`, `usesHttps` |

### Repeater & Intruder

| Tool | Description |
|------|-------------|
| `create_repeater_tab` | Create an HTTP/1.1 Repeater tab. Params: `content`, `targetHostname`, `targetPort`, `usesHttps`, `tabName` (optional) |
| `create_repeater_tab_http2` | Create an HTTP/2 Repeater tab. Params: `pseudoHeaders`, `headers`, `requestBody`, `targetHostname`, `targetPort`, `usesHttps`, `tabName` (optional) |
| `send_to_intruder` | Send a request to Intruder. Params: `content`, `targetHostname`, `targetPort`, `usesHttps`, `tabName` (optional) |

### Proxy HTTP History

| Tool | Description |
|------|-------------|
| `get_proxy_history_count` | Return the total number of items in the proxy HTTP history. |
| `get_proxy_http_history` | Return proxy HTTP history items with pagination and optional filters (see [Filters](#filters)). |
| `get_proxy_http_history_regex` | Return proxy HTTP history items whose raw content matches a regex. Params: `regex`, `caseInsensitive` (optional), plus all filters. |

> **Output format:** all history tools return a JSON object: `{"total":N,"returned":N,"offset":N,"nextOffset":N,"items":[...]}`. Use `nextOffset` to page. Items with `"_truncated":true` were cut to fit the per-item length limit — re-request with a higher `maxItemLength` to get the full content.

### WebSocket History

| Tool | Description |
|------|-------------|
| `get_websocket_history_count` | Return the total number of items in the proxy WebSocket history. |
| `get_proxy_websocket_history` | Return WebSocket history items. Params: `count`, `offset`, `newestFirst`, `hosts`, `direction` (`CLIENT_TO_SERVER` or `SERVER_TO_CLIENT`), `highlightColor`, `hasHighlight`, `hasNotes` |
| `get_proxy_websocket_history_regex` | Return WebSocket history items matching a regex. Params: `regex`, `caseInsensitive`, plus all WebSocket filters. |

### Organizer

| Tool | Description |
|------|-------------|
| `get_organizer_count` | Return the total number of items in the Organizer tab. |
| `get_organizer_items` | Return Organizer items with pagination and filters. Supports `hosts`, `methods`, `statusCodes`, `pathContains`, `headersOnly`, `highlightColor`, `hasHighlight`, `hasNotes`, `maxItemLength`. |
| `get_organizer_items_regex` | Return Organizer items matching a regex. Params: `regex`, `caseInsensitive`, plus all Organizer filters. |

### Scanner *(Burp Pro only)*

| Tool | Description |
|------|-------------|
| `get_scanner_issue_count` | Return the total number of issues found by the Burp scanner. |
| `get_scanner_issues` | Return scanner issues with pagination. Params: `count`, `offset` |

### Collaborator *(Burp Pro only)*

| Tool | Description |
|------|-------------|
| `generate_collaborator_payload` | Generate a Burp Collaborator payload for OOB testing. Params: `customData` (optional). Returns payload URL and ID. |
| `get_collaborator_interactions` | Poll Collaborator for DNS/HTTP/SMTP interactions. Params: `payloadId` (optional — omit to get all interactions) |

### Burp Configuration

| Tool | Description |
|------|-------------|
| `output_project_options` | Export current project-level options as JSON. |
| `output_user_options` | Export current user-level options as JSON. |
| `set_project_options` | Merge JSON into project-level options. Requires *Enable tools that can edit your config*. Param: `json` (must have top-level `project_options` key) |
| `set_user_options` | Merge JSON into user-level options. Requires *Enable tools that can edit your config*. Param: `json` (must have top-level `user_options` key) |

### Burp Controls

| Tool | Description |
|------|-------------|
| `set_task_execution_engine_state` | Pause or unpause Burp's task execution engine. Param: `running` (boolean) |
| `set_proxy_intercept_state` | Enable or disable Burp Proxy intercept. Param: `intercepting` (boolean) |

### Editor

| Tool | Description |
|------|-------------|
| `get_active_editor_contents` | Return the text content of the currently focused Burp message editor. |
| `set_active_editor_contents` | Set the text content of the currently focused Burp message editor. Param: `text` |

### Utilities

| Tool | Description |
|------|-------------|
| `url_encode` | URL-encode a string. Param: `content` |
| `url_decode` | URL-decode a string. Param: `content` |
| `base64_encode` | Base64-encode a string. Param: `content` |
| `base64_decode` | Base64-decode a string. Param: `content` |
| `generate_random_string` | Generate a random string. Params: `length`, `characterSet` |

---

## Filters

`get_proxy_http_history`, `get_proxy_http_history_regex`, `get_organizer_items`, and `get_organizer_items_regex` support the following optional parameters. All can be combined.

### Pagination

| Parameter | Type | Description |
|-----------|------|-------------|
| `count` | int | Number of items to return per page |
| `offset` | int | Starting position (0-based) |
| `newestFirst` | boolean | Return newest items first (default: `true`) |

Response is always a JSON object:
```json
{"total": 47, "returned": 10, "offset": 0, "nextOffset": 10, "items": [...]}
```
`nextOffset` is omitted when you have reached the end. Items with `"_truncated": true` were cut to fit the per-item length limit.

### Filters

| Parameter | Type | Description |
|-----------|------|-------------|
| `inScopeOnly` | boolean | Only return items in Burp's target scope (HTTP history only) |
| `hosts` | string[] | Filter to specific hostnames, e.g. `["api.example.com"]` |
| `methods` | string[] | Filter by HTTP method, e.g. `["POST", "PUT", "PATCH"]` |
| `statusCodes` | int[] | Filter by response status code, e.g. `[200, 401, 403, 500]` |
| `pathContains` | string | Substring match on URL path (case-insensitive), e.g. `"/api/v2/"` |
| `excludeExtensions` | string[] | Exclude by file extension, e.g. `["png", "css", "woff2"]` |
| `mimeTypes` | string[] | Include only these MIME types (Burp enum names), e.g. `["JSON", "HTML", "SCRIPT"]` |
| `highlightColor` | string | Filter by highlight colour: `RED`, `ORANGE`, `YELLOW`, `GREEN`, `CYAN`, `BLUE`, `PINK`, `MAGENTA`, `GRAY` |
| `hasHighlight` | boolean | `true` = any highlighted item; `false` = no highlight |
| `editedOnly` | boolean | `true` = only items modified by a match-and-replace rule (HTTP history only) |
| `hasNotes` | boolean | Filter by whether the item has an annotation note |

### Output size

| Parameter | Type | Description |
|-----------|------|-------------|
| `headersOnly` | boolean | Strip request/response bodies — keeps only HTTP headers. Reduces token use 5–50× for JSON API traffic. Bodies are replaced with `<body omitted>`. |
| `maxItemLength` | int | Override the default 5 000-character per-item truncation limit. Useful for requests with large cookie jars (e.g. `50000`). |

---

## Security & Approvals

Two approval layers gate the tools. Both prompt **inside the Burp UI** — watch for dialogs:

1. **HTTP request approval** (`send_http1_request`, `send_http2_request`, Repeater/Intruder tools):
   on the first request to any host, Burp shows:
   `Allow Once` / `Always Allow Host` / `Always Allow Host:Port` / `Deny`.
   "Always Allow" adds the host to the auto-approve target list (persisted in config).
2. **Data access approval** (history/Organizer/WebSocket read tools):
   on first read of each data type, Burp shows:
   `Allow Once` / `Always Allow <HTTP history|WebSocket history|Organizer items>` / `Deny`.
   Note: history items may contain sensitive data from previous web sessions.

Additional gates:
- `set_project_options` / `set_user_options` require the *Enable tools that can edit your config* checkbox in the MCP tab.
- Collaborator tools require Burp Pro.

### Request content normalization

MCP clients often emit `\r\n` as the literal 4-character sequence backslash-r-backslash-n in
JSON tool arguments instead of real CRLF bytes. The server normalizes the request **prelude**
(request line + headers, up to the first blank line) to proper CRLF; request **bodies are
preserved verbatim** so escape sequences inside JSON/binary bodies stay byte-exact.
If a strict backend still rejects your request, check for duplicated headers
(e.g. two `Content-Length` lines) — Cloudflare-class edges return 400 for that.

---

## Configuration Defaults

| Setting | Default |
|---------|---------|
| Require approval for HTTP requests | `false` |
| Require approval for project data access | `false` |
| Enable tools that can edit your config | `true` |

> **Note:** Defaults apply to new installs. Existing Burp projects retain previously saved values — toggle the settings manually in the MCP tab if needed.
