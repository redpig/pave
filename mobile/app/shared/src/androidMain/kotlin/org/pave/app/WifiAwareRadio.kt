package org.pave.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkInfo
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ServerSocket
import java.net.Socket

/**
 * A [Radio] over Wi-Fi Aware: the phone that showed the invite publishes
 * the invite's service and the other subscribes. The subscriber knows it
 * has the right phone when the service-specific info is the invite's
 * token. They open a data path, with the token as its passphrase, and
 * carry length-prefixed frames over a socket on it. What crosses is
 * sealed by the link anyway; the passphrase adds link-layer encryption
 * under it.
 *
 * Android 10 and later. Needs NEARBY_WIFI_DEVICES (Android 13+) or
 * location before.
 */
class WifiAwareRadio(
    private val context: Context,
    private val service: String,
    private val token: String,
    private val publishing: Boolean,
) : Radio {
    private var socket: Socket? = null
    private var server: ServerSocket? = null
    private var session: WifiAwareSession? = null
    private var network: ConnectivityManager.NetworkCallback? = null
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    private suspend fun connected(): Socket {
        socket?.let { return it }
        val aware = context.getSystemService(WifiAwareManager::class.java) ?: throw PaveFailure("this phone has no Wi-Fi Aware")
        if (!aware.isAvailable) throw PaveFailure("Wi-Fi Aware is off")
        val attached = CompletableDeferred<WifiAwareSession>()
        aware.attach(object : AttachCallback() {
            override fun onAttached(s: WifiAwareSession) { attached.complete(s) }
            override fun onAttachFailed() { attached.completeExceptionally(PaveFailure("couldn't start Wi-Fi Aware")) }
        }, null)
        val s = attached.await().also { session = it }
        val sock = if (publishing) publish(s) else subscribe(s)
        socket = sock
        return sock
    }

    private fun request(specifier: WifiAwareNetworkSpecifier, onAvailable: (Network, NetworkCapabilities) -> Unit) {
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
            .setNetworkSpecifier(specifier)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(n: Network, caps: NetworkCapabilities) = onAvailable(n, caps)
        }
        network = cb
        connectivity.requestNetwork(req, cb)
    }

    /** Showing phone: publish, and accept the one subscriber that says hello. */
    private suspend fun publish(s: WifiAwareSession): Socket {
        val srv = ServerSocket(0).also { server = it }
        val done = CompletableDeferred<Unit>()
        var pub: PublishDiscoverySession? = null
        s.publish(PublishConfig.Builder().setServiceName(service).setServiceSpecificInfo(token.toByteArray()).build(), object : DiscoverySessionCallback() {
            override fun onPublishStarted(p: PublishDiscoverySession) { pub = p }
            override fun onMessageReceived(peer: PeerHandle, message: ByteArray) {
                if (!message.contentEquals(token.toByteArray())) return
                val spec = WifiAwareNetworkSpecifier.Builder(pub!!, peer).setPskPassphrase(token).setPort(srv.localPort).build()
                request(spec) { _, _ -> done.complete(Unit) }
            }
        }, null)
        done.await()
        return withContext(Dispatchers.IO) { srv.accept() }
    }

    /** Scanning phone: find the publisher with the invite's token, say hello, connect. */
    private suspend fun subscribe(s: WifiAwareSession): Socket {
        val got = CompletableDeferred<Socket>()
        var sub: SubscribeDiscoverySession? = null
        s.subscribe(SubscribeConfig.Builder().setServiceName(service).build(), object : DiscoverySessionCallback() {
            override fun onSubscribeStarted(p: SubscribeDiscoverySession) { sub = p }
            override fun onServiceDiscovered(peer: PeerHandle, info: ByteArray, filter: List<ByteArray>) {
                if (!info.contentEquals(token.toByteArray())) return
                sub!!.sendMessage(peer, 0, token.toByteArray())
                val spec = WifiAwareNetworkSpecifier.Builder(sub!!, peer).setPskPassphrase(token).build()
                request(spec) { n, caps ->
                    val info2 = caps.transportInfo as? WifiAwareNetworkInfo ?: return@request
                    val addr = info2.peerIpv6Addr ?: return@request
                    if (!got.isCompleted) {
                        runCatching { n.socketFactory.createSocket(addr, info2.port) }.onSuccess { got.complete(it) }
                    }
                }
            }
        }, null)
        return got.await()
    }

    override suspend fun send(bytes: ByteArray) = withContext(Dispatchers.IO) {
        val out = DataOutputStream(connected().getOutputStream())
        out.writeInt(bytes.size)
        out.write(bytes)
        out.flush()
    }

    override suspend fun receive(): ByteArray = withContext(Dispatchers.IO) {
        val input = DataInputStream(connected().getInputStream())
        val n = input.readInt()
        if (n < 0 || n > 1 shl 20) throw PaveFailure("a frame too large")
        ByteArray(n).also { input.readFully(it) }
    }

    override fun close() {
        runCatching { socket?.close() }
        runCatching { server?.close() }
        network?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        runCatching { session?.close() }
    }
}
