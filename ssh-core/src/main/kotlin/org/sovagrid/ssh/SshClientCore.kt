/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 Jigokuraku01
 * Additional author attribution terms: see ATTRIBUTION.md. */
package org.sovagrid.ssh

import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.connection.channel.direct.DirectConnection
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder
import net.schmizz.sshj.connection.channel.direct.Parameters
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.password.PasswordUtils
import net.schmizz.sshj.sftp.SFTPClient
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.ServerSocket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.Security
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

sealed class Authentication {
    abstract fun clear()

    class Password(val secret: CharArray) : Authentication() {
        override fun clear() = secret.fill('\u0000')
    }

    /** PEM text remains in memory only until the call returns; SSHJ requires a String here. */
    class PrivateKey(val pem: String, val passphrase: CharArray) : Authentication() {
        override fun clear() = passphrase.fill('\u0000')
    }
}

class AuthenticationFailedException(val endpoint: Endpoint? = null) : IOException("SSH authentication failed")
/** Only fixed, reviewed installer messages may be shown verbatim in the Android UI. */
class ServerBootstrapException(message: String) : IOException(message)

/** The gateway key is pinned independently from the destination key. Credentials are never stored. */
class JumpHost(val endpoint: Endpoint, val pinnedWireBase64: String, val authentication: Authentication)

class SshClientCore {
    init {
        // Android ships a limited provider named BC. SSHJ sees that name and skips
        // registering its own provider, then X25519 key exchange fails on Android.
        synchronized(SecurityUtils::class.java) {
            val bundled = BouncyCastleProvider()
            val installed = Security.getProvider(bundled.name)
            if (installed?.javaClass != bundled.javaClass) {
                if (installed != null) Security.removeProvider(bundled.name)
                check(Security.insertProviderAt(bundled, 1) > 0) { "Cannot install SSH crypto provider" }
            }
            SecurityUtils.setSecurityProvider(bundled.name)
        }
    }

    private fun newClient() = SSHClient().apply {
        connectTimeout = 10_000
        timeout = 20_000
    }

    /** Connects with a verifier that always rejects. No username, password or key is sent. */
    fun probe(endpoint: Endpoint, jump: JumpHost? = null): HostKeySnapshot {
        val verifier = ProbeVerifier()
        val client = newClient()
        client.addHostKeyVerifier(verifier)
        var gateway: SSHClient? = null
        var channel: DirectConnection? = null
        try {
            if (jump == null) {
                client.connect(endpoint.host, endpoint.port)
            } else {
                val tunnel = connectGateway(jump, endpoint)
                gateway = tunnel.first
                channel = tunnel.second
                client.connectVia(channel)
            }
            throw IOException("Server did not present a host key")
        } catch (error: IOException) {
            return verifier.observed ?: throw error
        } finally {
            runCatching { client.disconnect() }
            runCatching { channel?.close() }
            runCatching { gateway?.disconnect() }
            jump?.authentication?.clear()
        }
    }

    private fun connectGateway(jump: JumpHost, destination: Endpoint): Pair<SSHClient, DirectConnection> {
        val gateway = newClient()
        val verifier = PinnedVerifier(jump.endpoint, jump.pinnedWireBase64)
        gateway.addHostKeyVerifier(verifier)
        try {
            gateway.connect(jump.endpoint.host, jump.endpoint.port)
            authenticate(gateway, jump.endpoint, jump.authentication)
            // SSHJ sends destination.host to the gateway, so 127.0.0.1 means the gateway loopback.
            val channel = gateway.newDirectConnection(destination.host, destination.port)
            return gateway to channel
        } catch (error: Exception) {
            runCatching { gateway.disconnect() }
            throw keyError(jump.endpoint, jump.pinnedWireBase64, verifier) ?: error
        } finally {
            jump.authentication.clear()
        }
    }

    private fun authenticate(client: SSHClient, endpoint: Endpoint, authentication: Authentication) {
        try {
            when (authentication) {
                is Authentication.Password -> client.authPassword(endpoint.username, authentication.secret)
                is Authentication.PrivateKey -> {
                    val finder = PasswordUtils.createOneOff(authentication.passphrase.takeIf { it.isNotEmpty() })
                    val provider = client.loadKeys(authentication.pem, null, finder)
                    client.authPublickey(endpoint.username, provider)
                }
            }
            client.connection.keepAlive.keepAliveInterval = 15
        } catch (_: UserAuthException) {
            throw AuthenticationFailedException(endpoint)
        } finally {
            authentication.clear()
        }
    }

    private fun keyError(endpoint: Endpoint, pin: String, verifier: PinnedVerifier): HostKeyChangedException? {
        val presented = verifier.rejected ?: return null
        val expected = runCatching { HostKeySnapshot("", pin).fingerprintSha256 }.getOrDefault("неизвестен")
        return HostKeyChangedException(expected, presented.fingerprintSha256, endpoint)
    }

    /** Opens Hub on the verified destination SSH host's loopback, optionally through a verified gateway. */
    fun openHubPanel(endpoint: Endpoint, pinnedWireBase64: String, authentication: Authentication,
                     jump: JumpHost? = null): LocalForwardConnection {
        val verifier = PinnedVerifier(endpoint, pinnedWireBase64)
        val client = newClient()
        client.addHostKeyVerifier(verifier)
        var socket: ServerSocket? = null
        var gateway: SSHClient? = null
        var channel: DirectConnection? = null
        try {
            if (jump == null) {
                client.connect(endpoint.host, endpoint.port)
            } else {
                val route = connectGateway(jump, endpoint)
                gateway = route.first
                channel = route.second
                client.connectVia(channel)
            }
            authenticate(client, endpoint, authentication)
            socket = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
            val parameters = Parameters("127.0.0.1", socket.localPort, "127.0.0.1", 8766)
            val forwarder = client.newLocalPortForwarder(parameters, socket)
            return LocalForwardConnection(client, socket, forwarder, gateway, channel)
        } catch (error: Exception) {
            runCatching { socket?.close() }
            runCatching { client.disconnect() }
            runCatching { channel?.close() }
            runCatching { gateway?.disconnect() }
            throw keyError(endpoint, pinnedWireBase64, verifier) ?: error
        } finally {
            authentication.clear()
            jump?.authentication?.clear()
        }
    }

    /** Uses the same pinned destination and optional pinned gateway as the terminal. */
    fun openFiles(endpoint: Endpoint, pinnedWireBase64: String, authentication: Authentication,
                  jump: JumpHost? = null): SftpConnection {
        val verifier = PinnedVerifier(endpoint, pinnedWireBase64)
        val client = newClient()
        client.addHostKeyVerifier(verifier)
        var gateway: SSHClient? = null
        var channel: DirectConnection? = null
        var sftp: SFTPClient? = null
        try {
            if (jump == null) client.connect(endpoint.host, endpoint.port)
            else {
                val route = connectGateway(jump, endpoint)
                gateway = route.first
                channel = route.second
                client.connectVia(channel)
            }
            authenticate(client, endpoint, authentication)
            sftp = client.newSFTPClient()
            return SftpConnection(client, sftp, gateway, channel)
        } catch (error: Exception) {
            runCatching { sftp?.close() }
            runCatching { client.disconnect() }
            runCatching { channel?.close() }
            runCatching { gateway?.disconnect() }
            throw keyError(endpoint, pinnedWireBase64, verifier) ?: error
        } finally {
            authentication.clear()
            jump?.authentication?.clear()
        }
    }

    /** Opens a live shell only after the pinned key has passed verification. */
    fun openShell(
        endpoint: Endpoint,
        pinnedWireBase64: String,
        authentication: Authentication,
        onOutput: (String) -> Unit,
        onClosed: () -> Unit,
        jump: JumpHost? = null,
        columns: Int = 80,
        rows: Int = 24
    ): ShellConnection {
        require(columns in 2..500 && rows in 2..300) { "Invalid PTY dimensions" }
        val verifier = PinnedVerifier(endpoint, pinnedWireBase64)
        val client = newClient()
        client.addHostKeyVerifier(verifier)
        var session: Session? = null
        var shell: Session.Shell? = null
        var gateway: SSHClient? = null
        var channel: DirectConnection? = null
        try {
            if (jump == null) {
                client.connect(endpoint.host, endpoint.port)
            } else {
                val tunnel = connectGateway(jump, endpoint)
                gateway = tunnel.first
                channel = tunnel.second
                client.connectVia(channel)
            }
            authenticate(client, endpoint, authentication)
            session = client.startSession()
            session.allocatePTY("xterm-256color", columns, rows, 0, 0, emptyMap())
            shell = session.startShell()
            return ShellConnection(client, session, shell, gateway, channel, onOutput, onClosed)
        } catch (error: Exception) {
            runCatching { shell?.close() }
            runCatching { session?.close() }
            runCatching { client.disconnect() }
            runCatching { channel?.close() }
            runCatching { gateway?.disconnect() }
            keyError(endpoint, pinnedWireBase64, verifier)?.let { throw it }
            throw error
        } finally {
            authentication.clear()
            jump?.authentication?.clear()
        }
    }
}

class LocalForwardConnection internal constructor(
    private val client: SSHClient,
    private val socket: ServerSocket,
    private val forwarder: LocalPortForwarder,
    private val gateway: SSHClient?,
    private val channel: DirectConnection?
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    val localPort: Int = socket.localPort
    val isOpen: Boolean get() = !closed.get() && client.isConnected && gateway?.isConnected != false

    /** A bounded check through this connection's loopback forward before showing an unverified panel. */
    fun probeHubHealth(): Boolean {
        if (!isOpen) return false
        val connection = try {
            URL("http://127.0.0.1:$localPort/healthz").openConnection(Proxy.NO_PROXY) as HttpURLConnection
        } catch (_: Exception) { return false }
        return try {
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.requestMethod = "GET"
            connection.responseCode == HttpURLConnection.HTTP_OK
        } catch (_: Exception) { false }
        finally { connection.disconnect() }
    }
    private val listener = Thread({
        try {
            forwarder.listen()
        } catch (_: IOException) {
            // Closing the socket intentionally ends the listener too.
        } finally {
            close()
        }
    }, "sovagrid-hub-forward").apply { isDaemon = true }

    init { listener.start() }

    /** Failure to execute the fixed probe never implies a clean server. */
    fun readDeploymentStatus(): ServerDeployment {
        if (!isOpen) return ServerDeployment.UNKNOWN
        val session = try { client.startSession() } catch (_: Exception) { return ServerDeployment.UNKNOWN }
        try {
            val command = try { session.exec(ServerDeploymentProbe.READ_COMMAND) }
                catch (_: Exception) { return ServerDeployment.UNKNOWN }
            try {
                command.join(12, TimeUnit.SECONDS)
                if (command.isOpen) return ServerDeployment.UNKNOWN
                val bytes = ByteArray(ServerDeployment.MAX_OUTPUT_BYTES + 1)
                return try {
                    var count = 0
                    while (count < bytes.size) {
                        val read = command.inputStream.read(bytes, count, bytes.size - count)
                        if (read < 0) break
                        count += read
                    }
                    ServerDeployment.parse(bytes, count, command.exitStatus)
                } catch (_: Exception) { ServerDeployment.UNKNOWN }
                finally { bytes.fill(0) }
            } finally {
                runCatching { command.close() }
            }
        } finally {
            runCatching { session.close() }
        }
    }

    /** Read-only reattachment to the root-private job state. Unknown never permits a new install. */
    fun readFirstInstallJob(): FirstInstallJob {
        if (!isOpen) return FirstInstallJob(FirstInstallState.UNKNOWN)
        val session = try { client.startSession() } catch (_: Exception) { return FirstInstallJob(FirstInstallState.UNKNOWN) }
        try {
            val command = try { session.exec(ServerBootstrap.STATUS_COMMAND) }
                catch (_: Exception) { return FirstInstallJob(FirstInstallState.UNKNOWN) }
            try {
                command.join(12, TimeUnit.SECONDS)
                if (command.isOpen) return FirstInstallJob(FirstInstallState.UNKNOWN)
                val bytes = ByteArray(ServerBootstrap.MAX_OUTPUT_BYTES + 1)
                return try {
                    var count = 0
                    while (count < bytes.size) {
                        val read = command.inputStream.read(bytes, count, bytes.size - count)
                        if (read < 0) break
                        count += read
                    }
                    ServerBootstrap.parseStatus(bytes, count, command.exitStatus)
                } catch (_: Exception) { FirstInstallJob(FirstInstallState.UNKNOWN) }
                finally { bytes.fill(0) }
            } finally {
                runCatching { command.close() }
            }
        } finally {
            runCatching { session.close() }
        }
    }

    /** Starts the fixed transient systemd service; SSH closure does not stop the installation. */
    fun startDetachedInstall(): FirstInstallJob {
        check(isOpen) { "SSH tunnel is closed" }
        if (readFirstInstallJob().state != FirstInstallState.NONE ||
            readDeploymentStatus() != ServerDeployment.MISSING) {
            throw ServerBootstrapException("Сервер больше не свободен для первой установки")
        }
        val session = client.startSession()
        var accepted = false
        try {
            val command = session.exec(ServerBootstrap.START_COMMAND)
            try {
                command.join(20, TimeUnit.SECONDS)
                if (!command.isOpen && command.exitStatus == 0) {
                    val bytes = ByteArray(64)
                    try {
                        var count = 0
                        while (count < bytes.size) {
                            val read = command.inputStream.read(bytes, count, bytes.size - count)
                            if (read < 0) break
                            count += read
                        }
                        accepted = String(bytes, 0, count, StandardCharsets.US_ASCII) == "SG_INSTALL_START_V1:OK\n"
                    } finally { bytes.fill(0) }
                }
            } finally { runCatching { command.close() } }
        } catch (_: Exception) {
            // SSH may close after systemd accepted the detached job.
        } finally { runCatching { session.close() } }
        // The acknowledgement may be lost after systemd accepted the job. Read state before reporting failure.
        repeat(5) {
            val job = readFirstInstallJob()
            if (job.state == FirstInstallState.RUNNING || job.state == FirstInstallState.DONE ||
                job.state == FirstInstallState.FAILED) return job
            Thread.sleep(500)
        }
        if (!accepted) throw ServerBootstrapException("Не удалось запустить установку на сервере")
        throw ServerBootstrapException("Сервер не подтвердил запуск установки")
    }

    /** Grants are kept in memory for one WebView handoff; stdout is bounded and never logged. */
    fun readSSHGrantResponse(): String? {
        if (!isOpen) return null
        val session = try { client.startSession() } catch (_: Exception) { return null }
        try {
            val command = try { session.exec(SshGrantCommand.READ_COMMAND) }
                catch (_: Exception) { return null }
            try {
                command.join(25, TimeUnit.SECONDS)
                if (command.isOpen || command.exitStatus != 0) return null
                val bytes = ByteArray(SshGrantCommand.MAX_RESPONSE_BYTES + 1)
                return try {
                    var count = 0
                    while (count < bytes.size) {
                        val read = command.inputStream.read(bytes, count, bytes.size - count)
                        if (read < 0) break
                        count += read
                    }
                    if (count !in 2..SshGrantCommand.MAX_RESPONSE_BYTES) return null
                    val line = String(bytes, 0, count, StandardCharsets.UTF_8).removeSuffix("\n")
                    if (line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0 || line.indexOf('\u0000') >= 0) null
                    else line
                } catch (_: Exception) { null }
                finally { bytes.fill(0) }
            } finally {
                runCatching { command.close() }
            }
        } finally {
            runCatching { session.close() }
        }
    }

    /** Read the installer's password only over this already authenticated, pinned SSH client. */
    fun readBootstrapPassword(): CharArray {
        check(isOpen) { "SSH tunnel is closed" }
        val session = client.startSession()
        try {
            check(isOpen) { "SSH tunnel is closed" }
            val command = session.exec(BootstrapPassword.READ_COMMAND)
            try {
                command.join(10, TimeUnit.SECONDS)
                if (command.isOpen || command.exitStatus != 0) {
                    throw IOException("Initial password unavailable or SSH command timed out")
                }
                val bytes = ByteArray(258)
                try {
                    var count = 0
                    while (count < bytes.size) {
                        val read = command.inputStream.read(bytes, count, bytes.size - count)
                        if (read < 0) break
                        count += read
                    }
                    if (count > 257) throw IOException("Initial password output is too large")
                    return BootstrapPassword.parse(bytes, count)
                } finally {
                    bytes.fill(0)
                }
            } finally {
                runCatching { command.close() }
            }
        } finally {
            runCatching { session.close() }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { socket.close() }
        listener.interrupt()
        runCatching { client.disconnect() }
        runCatching { channel?.close() }
        runCatching { gateway?.disconnect() }
    }
}

class ShellConnection internal constructor(
    private val client: SSHClient,
    private val session: Session,
    private val shell: Session.Shell,
    private val gateway: SSHClient?,
    private val channel: DirectConnection?,
    private val onOutput: (String) -> Unit,
    private val onClosed: () -> Unit
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val readers = Executors.newFixedThreadPool(2)

    val isOpen: Boolean get() = !closed.get()

    init {
        readers.execute { pump(shell.inputStream, true) }
        readers.execute { pump(shell.errorStream, false) }
    }

    fun sendLine(line: String) {
        sendInput(line + "\n")
    }

    /** Send terminal keystrokes verbatim, including ESC, Ctrl and bracketed paste. */
    fun sendInput(input: String) {
        check(isOpen) { "Shell is closed" }
        synchronized(shell) {
            val bytes = input.toByteArray(StandardCharsets.UTF_8)
            shell.outputStream.write(bytes)
            shell.outputStream.flush()
        }
    }

    fun resize(columns: Int, rows: Int) {
        require(columns in 2..500 && rows in 2..300) { "Invalid PTY dimensions" }
        check(isOpen) { "Shell is closed" }
        synchronized(shell) {
            shell.changeWindowDimensions(columns, rows, 0, 0)
        }
    }

    private fun pump(input: InputStream, primary: Boolean) {
        try {
            InputStreamReader(input, StandardCharsets.UTF_8).use { reader ->
                val chunk = CharArray(4096)
                while (!closed.get()) {
                    val count = reader.read(chunk)
                    if (count < 0) break
                    onOutput(String(chunk, 0, count))
                }
            }
        } catch (_: IOException) {
            // Closing a shell also closes its streams; callers receive onClosed below.
        } finally {
            if (primary && !closed.get()) {
                close()
                onClosed()
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { shell.close() }
        runCatching { session.close() }
        runCatching { client.disconnect() }
        runCatching { channel?.close() }
        runCatching { gateway?.disconnect() }
        readers.shutdownNow()
    }
}
