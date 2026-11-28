package org.pave.app

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** A command the wallet refused, with its reason. */
class PaveFailure(message: String) : Exception(message)

/**
 * The wallet, as the shared screens see it: the JSON commands pave-node
 * takes ({"cmd": "help"} lists them). Each platform implements it over the
 * UniFFI bindings to the Rust library; calls block, so implementations run
 * them off the main thread.
 */
interface PaveWallet {
    /** The raw JSON reply to one command. */
    suspend fun callJson(json: String): String

    /** Run `cmd` with `args`; the reply, or a [PaveFailure]. */
    suspend fun call(cmd: String, args: Map<String, JsonElement> = emptyMap()): JsonObject {
        val body = buildJsonObject {
            put("cmd", JsonPrimitive(cmd))
            args.forEach { (k, v) -> put(k, v) }
        }
        val r = Json.parseToJsonElement(callJson(body.toString())).jsonObject
        if (r["ok"]?.jsonPrimitive?.booleanOrNull != true) {
            throw PaveFailure(r["error"]?.jsonPrimitive?.content ?: "the wallet refused $cmd")
        }
        return r
    }
}

/** Joining a town: the request to take to the town office, and finishing with its reply. */
interface PaveJoin {
    /** The request (hex) and the challenge (hex) an attestation must bind. */
    fun request(): Pair<String, String>

    /** Have the platform attest a hardware key binding `challenge`, and attach it. */
    suspend fun attest(challenge: String)

    /** Finish with the town's reply (hex): the wallet, sealed by the platform keystore. */
    suspend fun finish(replyHex: String, name: String): PaveWallet
}

/** What each platform provides. */
interface Platform {
    /** The wallet saved on this device, if there is one. */
    suspend fun openWallet(): PaveWallet?

    fun beginJoin(): PaveJoin

    /** A radio for an in-person link, from the invite's radios and token. */
    fun radio(invite: Invite, showing: Boolean): Radio?
}

fun str(s: String): JsonElement = JsonPrimitive(s)

fun JsonObject.text(k: String): String = this[k]?.jsonPrimitive?.content ?: throw PaveFailure("the reply has no $k")
