package org.pave.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The wallet's state sealed under Android Keystore AES-GCM keys: a fresh
 * key per save, older ones deleted on commit. Keys are rollback-resistant
 * where the device supports it, so a deleted key can't come back with a
 * restored backup (docs/phone-keys.md).
 */
class AndroidVault(private val prefix: String) : uniffi.pave.Keystore {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun versions(): List<Int> =
        ks.aliases().toList().filter { it.startsWith("$prefix.v") }.mapNotNull { it.removePrefix("$prefix.v").toIntOrNull() }.sorted()

    private fun newKey(v: Int): SecretKey {
        val spec = KeyGenParameterSpec.Builder("$prefix.v$v", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRollbackResistant(true)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }

    private fun fail(e: Exception): Nothing = throw uniffi.pave.PaveException.Failed(e.message ?: e.toString())

    override fun seal(data: ByteArray): ByteArray = try {
        val v = (versions().lastOrNull() ?: 0) + 1
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, newKey(v)) }
        val ct = c.doFinal(data)
        byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte()) + c.iv + ct
    } catch (e: Exception) { fail(e) }

    override fun open(sealed: ByteArray): ByteArray = try {
        val v = ((sealed[0].toInt() and 0xff) shl 24) or ((sealed[1].toInt() and 0xff) shl 16) or ((sealed[2].toInt() and 0xff) shl 8) or (sealed[3].toInt() and 0xff)
        val key = ks.getKey("$prefix.v$v", null) as? SecretKey ?: throw IllegalStateException("sealed under a retired key: an old copy")
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed, 4, 12)) }.doFinal(sealed, 16, sealed.size - 16)
    } catch (e: Exception) { fail(e) }

    override fun commit() = try {
        versions().dropLast(1).forEach { ks.deleteEntry("$prefix.v$it") }
    } catch (e: Exception) { fail(e) }

    override fun rollbackResistant(): Boolean = true

    /**
     * A hardware key attested by Android Key Attestation, binding
     * `challenge`: its certificate chain, leaf first. StrongBox where the
     * device has it, else the TEE. The town checks it (board/src/attest.rs).
     */
    fun attest(challenge: ByteArray): List<ByteArray> {
        val alias = "$prefix.attest"
        fun make(strongBox: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .setIsStrongBoxBacked(strongBox)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair()
        }
        try { make(true) } catch (e: StrongBoxUnavailableException) { make(false) }
        return ks.getCertificateChain(alias).map { it.encoded }
    }
}

class AndroidWallet(private val w: uniffi.pave.Wallet) : PaveWallet {
    override suspend fun callJson(json: String): String = withContext(Dispatchers.IO) { w.call(json) }
}

class AndroidJoin(private val dir: File, private val vault: AndroidVault) : PaveJoin {
    private val j = uniffi.pave.Join()
    private var current = parse(j.request())

    private fun parse(json: String): Pair<String, String> {
        val o = kotlinx.serialization.json.Json.parseToJsonElement(json) as JsonObject
        return o["request"]!!.jsonPrimitive.content to o["challenge"]!!.jsonPrimitive.content
    }

    override fun request() = current

    override suspend fun attest(challenge: String) = withContext(Dispatchers.IO) {
        val chain = vault.attest(challenge.hexToBytes()).map { JsonPrimitive(it.toHex()) }
        val body = JsonObject(mapOf("android" to JsonObject(mapOf("chain" to JsonArray(chain)))))
        current = parse(j.attest(body.toString()))
    }

    override suspend fun finish(replyHex: String, name: String): PaveWallet = withContext(Dispatchers.IO) {
        AndroidWallet(j.finish(replyHex, name, File(dir, "wallet.pave").path, vault))
    }
}

class AndroidPlatform(private val context: Context) : Platform {
    private val dir = context.filesDir
    private val vault = AndroidVault("pave.wallet")

    override suspend fun openWallet(): PaveWallet? = withContext(Dispatchers.IO) {
        val f = File(dir, "wallet.pave")
        if (f.exists()) AndroidWallet(uniffi.pave.Wallet.open(f.path, vault)) else null
    }

    override fun beginJoin(): PaveJoin = AndroidJoin(dir, vault)

    override fun radio(invite: Invite, showing: Boolean): Radio? {
        val service = invite.radios.firstNotNullOfOrNull { it["wifi_aware"]?.jsonPrimitive?.content } ?: return null
        return WifiAwareRadio(context, service, invite.token, showing)
    }
}
