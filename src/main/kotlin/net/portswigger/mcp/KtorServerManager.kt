package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.tools.registerTools
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class KtorServerManager(private val api: MontoyaApi) : ServerManager {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    override fun start(config: McpConfig, callback: (ServerState) -> Unit) {
        callback(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                val mcpServer = Server(
                    serverInfo = Implementation("burp-suite", "1.1.2"), options = ServerOptions(
                        capabilities = ServerCapabilities(
                            tools = ServerCapabilities.Tools(listChanged = false)
                        )
                    )
                )

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    install(CORS) {
                        allowHost("localhost:${config.port}")
                        allowHost("127.0.0.1:${config.port}")
                        if (config.host == "0.0.0.0" || config.host == "::") {
                            anyHost()
                        } else if (config.host != "localhost" && config.host != "127.0.0.1") {
                            allowHost("${config.host}:${config.port}")
                        }

                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader("Last-Event-ID")

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    intercept(ApplicationCallPipeline.Call) {
                        val origin = call.request.header("Origin")
                        val host = call.request.header("Host")
                        val referer = call.request.header("Referer")
                        val userAgent = call.request.header("User-Agent")

                        if (origin != null && !isValidOrigin(origin, config.host)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from origin: $origin")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        } else if (isBrowserRequest(userAgent)) {
                            api.logging().logToOutput("Blocked browser request without Origin header")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (host != null && !isValidHost(host, config.port, config.host)) {
                            api.logging().logToOutput("Blocked DNS rebinding attack from host: $host")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        if (referer != null && !isValidReferer(referer, config.host)) {
                            api.logging().logToOutput("Blocked suspicious request from referer: $referer")
                            call.respond(HttpStatusCode.Forbidden)
                            return@intercept
                        }

                        call.response.header("X-Frame-Options", "DENY")
                        call.response.header("X-Content-Type-Options", "nosniff")
                        call.response.header("Referrer-Policy", "same-origin")
                        call.response.header("Content-Security-Policy", "default-src 'none'")
                    }

                    val isAllInterfaces = config.host == "0.0.0.0" || config.host == "::"
                    val isLocalhost = config.host == "localhost" || config.host == "127.0.0.1" || config.host == "::1"
                    val extraHost = if (!isAllInterfaces && !isLocalhost) config.host else null

                    // SDK validates allowedHosts as bare names (no IPv6 colons) and allowedOrigins as full URLs
                    val sdkHosts = listOfNotNull("localhost", "127.0.0.1", extraHost)
                    val sdkOrigins = listOfNotNull(
                        "http://localhost", "http://127.0.0.1", "http://[::1]",
                        extraHost?.let { "http://$it" }
                    )

                    mcp(
                        enableDnsRebindingProtection = !isAllInterfaces,
                        allowedHosts = sdkHosts,
                        allowedOrigins = sdkOrigins
                    ) {
                        mcpServer
                    }

                    mcpServer.registerTools(api, config)
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                callback(ServerState.Running)

            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (ServerState) -> Unit) {
        callback(ServerState.Stopping)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null
                api.logging().logToOutput("Stopped MCP server")
                callback(ServerState.Stopped)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(ServerState.Failed(e))
            }
        }
    }

    override fun shutdown() {
        server?.stop(1000, 5000)
        server = null

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

    private fun isValidOrigin(origin: String, configuredHost: String): Boolean {
        try {
            val url = URI(origin).toURL()
            val hostname = url.host.lowercase().trimStart('[').trimEnd(']')

            if (configuredHost == "0.0.0.0" || configuredHost == "::") return true

            val allowedHosts = mutableSetOf("localhost", "127.0.0.1", "::1")
            if (configuredHost != "localhost" && configuredHost != "127.0.0.1") {
                allowedHosts.add(configuredHost)
            }

            return hostname in allowedHosts
        } catch (_: Exception) {
            return false
        }
    }

    private fun isBrowserRequest(userAgent: String?): Boolean {
        if (userAgent == null) return false

        val userAgentLower = userAgent.lowercase()
        val browserIndicators = listOf(
            "mozilla/", "chrome/", "safari/", "webkit/", "gecko/", "firefox/", "edge/", "opera/", "browser"
        )

        return browserIndicators.any { userAgentLower.contains(it) }
    }

    private fun isValidHost(host: String, expectedPort: Int, configuredHost: String): Boolean {
        try {
            val (hostname, port) = parseHostHeader(host)

            if (configuredHost == "0.0.0.0" || configuredHost == "::") {
                return port == null || port == expectedPort
            }

            val allowedHosts = mutableSetOf("localhost", "127.0.0.1", "::1")
            if (configuredHost != "localhost" && configuredHost != "127.0.0.1") {
                allowedHosts.add(configuredHost)
            }

            if (hostname !in allowedHosts) {
                return false
            }

            if (port != null && port != expectedPort) {
                return false
            }

            return true
        } catch (_: Exception) {
            return false
        }
    }

    private fun parseHostHeader(host: String): Pair<String, Int?> {
        return if (host.startsWith("[")) {
            // IPv6: [::1] or [::1]:9876
            val closeBracket = host.indexOf(']')
            if (closeBracket < 0) throw IllegalArgumentException("Invalid IPv6 host header: $host")
            val h = host.substring(1, closeBracket).lowercase()
            val p = if (closeBracket + 1 < host.length && host[closeBracket + 1] == ':')
                host.substring(closeBracket + 2).toIntOrNull()
            else null
            h to p
        } else {
            val parts = host.split(":")
            parts[0].lowercase() to (if (parts.size == 2) parts[1].toIntOrNull() else null)
        }
    }

    private fun isValidReferer(referer: String, configuredHost: String): Boolean {
        try {
            val url = URI(referer).toURL()
            val hostname = url.host.lowercase().trimStart('[').trimEnd(']')

            if (configuredHost == "0.0.0.0" || configuredHost == "::") return true

            val allowedHosts = mutableSetOf("localhost", "127.0.0.1", "::1")
            if (configuredHost != "localhost" && configuredHost != "127.0.0.1") {
                allowedHosts.add(configuredHost)
            }

            return hostname in allowedHosts

        } catch (_: Exception) {
            return false
        }
    }
}