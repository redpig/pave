package org.pave.app

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

/**
 * An in-person link (board/src/link.rs): one phone shows an invite as a QR
 * code, the other scans it, and every message between them is sealed under
 * the key the code carries. The wallet seals and opens; the app moves the
 * bytes, over a [Radio] or in QR frames.
 */
class Link(private val wallet: PaveWallet, val id: String) {
    suspend fun seal(kind: String, bodyHex: String): String =
        wallet.call("link_seal", mapOf("link" to str(id), "kind" to str(kind), "body" to str(bodyHex))).text("sealed")

    /** Open a sealed message: its kind and body. */
    suspend fun open(sealedHex: String): Pair<String, String> {
        val r = wallet.call("link_open", mapOf("link" to str(id), "sealed" to str(sealedHex)))
        return r.text("kind") to r.text("body")
    }

    /** QR codes to show in a loop for one sealed message. */
    suspend fun frames(sealedHex: String): List<String> =
        wallet.call("link_frames", mapOf("link" to str(id), "sealed" to str(sealedHex)))["frames"]!!.jsonArray.map { it.jsonPrimitive.content }

    /** Take a scanned frame; the sealed message once all its frames are in. */
    suspend fun collect(frame: String): String? {
        val r = wallet.call("link_collect", mapOf("link" to str(id), "frame" to str(frame)))
        return r["sealed"]?.takeIf { it != JsonNull }?.jsonPrimitive?.content
    }
}

/** An invite: shown as a QR code by one phone, read by the other. */
data class Invite(val code: String, val radios: List<JsonObject>, val token: String)

/** Show an invite, listening on `radios` ({"wifi_aware": name} or {"ble": uuid}). */
suspend fun PaveWallet.showInvite(radios: List<JsonObject>): Pair<Link, Invite> {
    val r = call("link_show", mapOf("radios" to JsonArray(radios), "ttl" to kotlinx.serialization.json.JsonPrimitive(120)))
    val id = r.text("link")
    return Link(this, id) to Invite(r.text("code"), radios, id)
}

/** Read an invite another phone showed. */
suspend fun PaveWallet.scanInvite(code: String): Pair<Link, Invite> {
    val r = call("link_scan", mapOf("code" to str(code)))
    val id = r.text("link")
    return Link(this, id) to Invite(code, r["radios"]!!.jsonArray.map { it as JsonObject }, id)
}

/** A full-duplex byte channel between the two phones: Wi-Fi Aware or Bluetooth. */
interface Radio {
    suspend fun send(bytes: ByteArray)
    suspend fun receive(): ByteArray
    fun close()
}

suspend fun Link.send(radio: Radio, kind: String, bodyHex: String) = radio.send(seal(kind, bodyHex).hexToBytes())

suspend fun Link.receive(radio: Radio, kind: String): String {
    val (k, body) = open(radio.receive().toHex())
    if (k != kind) throw PaveFailure("expected $kind, got $k")
    return body
}

/**
 * A meet over a radio: each side sends what it has, then what the other
 * lacks, and absorbs what it's sent. Both sides run the same steps; the
 * radio is full-duplex, so neither waits on the other to go first.
 */
suspend fun meet(wallet: PaveWallet, link: Link, radio: Radio) {
    link.send(radio, "have", wallet.call("have").text("have"))
    val theirs = link.receive(radio, "have")
    link.send(radio, "bundle", wallet.call("bundle_for", mapOf("have" to str(theirs))).text("bundle"))
    wallet.call("absorb", mapOf("bundle" to str(link.receive(radio, "bundle"))))
}

fun String.hexToBytes(): ByteArray = ByteArray(length / 2) { substring(2 * it, 2 * it + 2).toInt(16).toByte() }

fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
