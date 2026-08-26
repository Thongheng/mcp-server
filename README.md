# Burp Suite MCP Server

Integrates Burp Suite with AI clients (Claude, Cursor, etc.) using the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). The extension runs a local MCP server inside Burp, exposing Burp's data and actions as tools that AI assistants can call directly.

---

## Installation

1. Build: `./gradlew embedProxyJar` → produces `build/libs/burp-mcp-all.jar`
2. Load the JAR as a Burp extension (Extensions → Add → Java)
3. Configure the MCP tab in Burp (host, port, approvals)
4. Point your AI client at `http://127.0.0.1:9876/sse`

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
| `get_organizer_items` | Return Organizer items with pagination and filters. Params: `count`, `offset`, `newestFirst`, `hosts`, `methods`, `statusCodes`, `highlightColor`, `hasHighlight`, `hasNotes` |
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

`get_proxy_http_history` and `get_proxy_http_history_regex` support the following optional filter parameters. All filters can be combined.

| Parameter | Type | Description |
|-----------|------|-------------|
| `count` | int | Number of items to return per page |
| `offset` | int | Starting position (0 = newest when `newestFirst` is true) |
| `newestFirst` | boolean | Return newest items first (default: `true`) |
| `inScopeOnly` | boolean | Only return items in Burp's target scope |
| `hosts` | string[] | Filter to specific hostnames, e.g. `["api.example.com"]` |
| `methods` | string[] | Filter by HTTP method, e.g. `["POST", "PUT", "PATCH"]` |
| `statusCodes` | int[] | Filter by response status code, e.g. `[200, 401, 403, 500]` |
| `excludeExtensions` | string[] | Exclude requests by file extension, e.g. `["png", "css", "woff2"]` |
| `mimeTypes` | string[] | Include only these MIME types (Burp enum names), e.g. `["JSON", "HTML", "SCRIPT"]` |
| `highlightColor` | string | Filter by specific highlight colour: `RED`, `ORANGE`, `YELLOW`, `GREEN`, `CYAN`, `BLUE`, `PINK`, `MAGENTA`, `GRAY` |
| `hasHighlight` | boolean | `true` = any highlighted item; `false` = no highlight |
| `editedOnly` | boolean | `true` = only items modified by a match-and-replace rule |
| `hasNotes` | boolean | `true` / `false` to filter by whether the item has an annotation note |

Pagination response includes a metadata header: `[Total: N | Returned: N | Offset: N | Next offset: N]`

---

## Configuration Defaults

| Setting | Default |
|---------|---------|
| Require approval for HTTP requests | `false` |
| Require approval for project data access | `false` |
| Enable tools that can edit your config | `true` |

> **Note:** Defaults apply to new installs. Existing Burp projects retain previously saved values — toggle the settings manually in the MCP tab if needed.
