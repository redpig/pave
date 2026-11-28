package org.pave.app

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject

/**
 * The in-person steps of a food delivery (spec/food.md), as the two phones
 * run them. Over a radio each side runs its function to the end; in QR
 * frames the screens alternate turns, each showing what the other scans.
 */
object Counter {
    /** What the cafe's tablet learns from the courier's badge. */
    data class Badge(val courier: String, val key: String)

    /**
     * Cafe: check the courier's badge against the dispatch, meet, hand the
     * bag to the badge key, send the manifest, and meet again so the
     * courier has the handoff.
     */
    suspend fun cafe(wallet: PaveWallet, link: Link, radio: Radio, dispatch: String, manifest: String, confirm: suspend (Badge) -> Boolean): Badge {
        val ticket = link.receive(radio, "badge")
        val learned = wallet.call("learn_ticket", mapOf("ticket" to str(ticket), "dispatch" to str(dispatch)))
        val courier = (learned["badge"] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw PaveFailure("that isn't this dispatch's badge")
        val key = link.receive(radio, "badge_key")
        val badge = Badge(courier, key)
        meet(wallet, link, radio)
        if (!confirm(badge)) throw PaveFailure("the cafe didn't hand it over")
        wallet.call("act", mapOf("action" to str("hand_off"), "manifest" to str(manifest), "to" to str(key)))
        link.send(radio, "manifest", manifest)
        meet(wallet, link, radio)
        return badge
    }

    /** Courier: show the badge, meet, receive the manifest, meet, and take the bag. Returns the manifest. */
    suspend fun courier(wallet: PaveWallet, link: Link, radio: Radio, badgeKey: String): String {
        link.send(radio, "badge", wallet.call("present", mapOf("key" to str(badgeKey))).text("ticket"))
        link.send(radio, "badge_key", badgeKey)
        meet(wallet, link, radio)
        val manifest = link.receive(radio, "manifest")
        meet(wallet, link, radio)
        wallet.call("act", mapOf("action" to str("take"), "manifest" to str(manifest)))
        return manifest
    }
}

/**
 * A turn in a QR-only exchange: the sealed messages one phone shows, as a
 * loop of frames, until the other has scanned them all and shows its own.
 */
class QrTurn(private val link: Link) {
    /** The frames to show for `messages`, (kind, body hex) in order. */
    suspend fun show(messages: List<Pair<String, String>>): List<String> =
        messages.flatMap { (kind, body) -> link.frames(link.seal(kind, body)) }

    private val got = mutableListOf<Pair<String, String>>()
    private val lock = Mutex()
    private var complete = false

    /**
     * Take a scanned frame; true, once, when `count` messages are in. The
     * camera reads each code many times and scans may overlap: frames are
     * taken one at a time, and a message already read (its loop still on
     * the other screen) is ignored.
     */
    suspend fun scanned(frame: String, count: Int): Boolean = lock.withLock {
        if (complete) return@withLock false
        val sealed = runCatching { link.collect(frame) }.getOrNull() ?: return@withLock false
        runCatching { link.open(sealed) }.onSuccess { got += it }
        complete = got.size >= count
        complete
    }

    /** The messages scanned this turn, and start the next. */
    fun take(): List<Pair<String, String>> = got.toList().also { got.clear(); complete = false }
}

/**
 * At the door, in QR frames alone. The customer shows the invite; then:
 *
 * 1. Courier shows: have.
 * 2. Customer shows: have, and what the courier lacks.
 * 3. Courier hands the bag to the customer's key and shows: the manifest,
 *    and what the customer lacks (the handoff among it).
 * 4. Customer confirms.
 */
object Door {
    suspend fun courierFirst(wallet: PaveWallet, turn: QrTurn): List<String> =
        turn.show(listOf("have" to wallet.call("have").text("have")))

    suspend fun customerAnswer(wallet: PaveWallet, turn: QrTurn): List<String> {
        val theirs = turn.take().single { it.first == "have" }.second
        return turn.show(listOf("have" to wallet.call("have").text("have"), "bundle" to wallet.call("bundle_for", mapOf("have" to str(theirs))).text("bundle")))
    }

    suspend fun courierHandOver(wallet: PaveWallet, turn: QrTurn, manifest: String): List<String> {
        val got = turn.take().toMap()
        wallet.call("absorb", mapOf("bundle" to str(got.getValue("bundle"))))
        val customer = wallet.call("manifest", mapOf("manifest" to str(manifest))).text("addressee")
        wallet.call("act", mapOf("action" to str("hand_off"), "manifest" to str(manifest), "to" to str(customer)))
        return turn.show(listOf("manifest" to manifest, "bundle" to wallet.call("bundle_for", mapOf("have" to str(got.getValue("have")))).text("bundle")))
    }

    suspend fun customerConfirm(wallet: PaveWallet, turn: QrTurn): JsonObject {
        val got = turn.take().toMap()
        wallet.call("absorb", mapOf("bundle" to str(got.getValue("bundle"))))
        wallet.call("act", mapOf("action" to str("confirm"), "manifest" to str(got.getValue("manifest"))))
        return wallet.call("food_custody", mapOf("manifest" to str(got.getValue("manifest"))))
    }
}
