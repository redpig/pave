// The pave wallet from Kotlin, through pave.h with JNA.
//
// NOT BUILT HERE: the Android SDK and NDK aren't reachable from the machine
// this was written on. It follows mobile/include/pave.h and the Python
// demo (demo/phone_demo.py), which runs the same calls. Build the library
// with `cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release -p
// pave-mobile`, and add `net.java.dev.jna:jna:5.14.0@aar` to the app.
package pave

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.PointerByReference
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The calls in pave.h. */
interface PaveLib : Library {
    fun pave_version(): Pointer
    fun pave_join_begin(request: PointerByReference): Pointer
    fun pave_join_finish(join: Pointer, reply: String, name: String, path: String, ks: PaveKeystore.ByValue, err: PointerByReference): Pointer?
    fun pave_open_with(path: String, ks: PaveKeystore.ByValue, err: PointerByReference): Pointer?
    fun pave_call(w: Pointer, json: String): Pointer
    fun pave_string_free(s: Pointer)
    fun pave_close(w: Pointer)

    companion object {
        val lib: PaveLib = Native.load("pave_mobile", PaveLib::class.java)
    }
}

/** One keystore callback: seal or open. 0 ok, 1 too small, else fail. */
interface Transform : Callback {
    fun invoke(ctx: Pointer?, data: Pointer, len: Long, out: Pointer, cap: Long, outLen: Pointer): Int
}

interface Commit : Callback {
    fun invoke(ctx: Pointer?): Int
}

@Structure.FieldOrder("ctx", "seal", "open", "commit", "rollback_resistant")
open class PaveKeystore : Structure() {
    @JvmField var ctx: Pointer? = null
    @JvmField var seal: Transform? = null
    @JvmField var open: Transform? = null
    @JvmField var commit: Commit? = null
    @JvmField var rollback_resistant: Int = 0

    class ByValue : PaveKeystore(), Structure.ByValue
}

/**
 * The wallet's state sealed under Android Keystore AES-GCM keys, a fresh key
 * per save, older ones deleted on commit. Asks for rollback resistance,
 * which makes a deleted key unrecoverable where the device supports it
 * (see docs/phone-keys.md).
 */
class AndroidVault(private val prefix: String) {
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun versions(): List<Int> =
        ks.aliases().toList().filter { it.startsWith("$prefix.") }.mapNotNull { it.removePrefix("$prefix.").toIntOrNull() }.sorted()

    private fun newKey(v: Int): SecretKey {
        val spec = KeyGenParameterSpec.Builder("$prefix.$v", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRollbackResistant(true)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }

    fun seal(data: ByteArray): ByteArray {
        val v = (versions().lastOrNull() ?: 0) + 1
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, newKey(v)) }
        val ct = c.doFinal(data)
        return byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte()) + c.iv + ct
    }

    fun open(sealed: ByteArray): ByteArray {
        val v = ((sealed[0].toInt() and 0xff) shl 24) or ((sealed[1].toInt() and 0xff) shl 16) or ((sealed[2].toInt() and 0xff) shl 8) or (sealed[3].toInt() and 0xff)
        val key = ks.getKey("$prefix.$v", null) as? SecretKey ?: error("sealed under a retired key: an old copy")
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed, 4, 12)) }
        return c.doFinal(sealed, 16, sealed.size - 16)
    }

    fun commit() {
        val vs = versions()
        vs.dropLast(1).forEach { ks.deleteEntry("$prefix.$it") }
    }

    /** The callbacks pave.h takes. Keep the returned struct referenced while the wallet is open. */
    fun callbacks(): PaveKeystore.ByValue {
        fun transform(f: (ByteArray) -> ByteArray) = object : Transform {
            override fun invoke(ctx: Pointer?, data: Pointer, len: Long, out: Pointer, cap: Long, outLen: Pointer): Int = try {
                val r = f(data.getByteArray(0, len.toInt()))
                outLen.setLong(0, r.size.toLong())
                if (r.size > cap) 1 else { out.write(0, r, 0, r.size); 0 }
            } catch (e: Exception) { 2 }
        }
        return PaveKeystore.ByValue().apply {
            seal = transform(::seal)
            open = transform(::open)
            commit = object : Commit { override fun invoke(ctx: Pointer?): Int = try { this@AndroidVault.commit(); 0 } catch (e: Exception) { 2 } }
            rollback_resistant = 1
        }
    }
}

/** An open wallet. Calls are blocking: run them off the main thread. */
class Wallet private constructor(private val w: Pointer, private val keystore: PaveKeystore.ByValue) : AutoCloseable {
    fun call(cmd: String, args: Map<String, Any?> = emptyMap()): JSONObject {
        val r = take(PaveLib.lib.pave_call(w, JSONObject(args + ("cmd" to cmd)).toString()))
        if (!r.optBoolean("ok")) throw IllegalStateException(r.optString("error"))
        return r
    }

    override fun close() = PaveLib.lib.pave_close(w)

    companion object {
        private fun take(p: Pointer): JSONObject = JSONObject(p.getString(0)).also { PaveLib.lib.pave_string_free(p) }

        fun open(path: String, vault: AndroidVault): Wallet {
            val ks = vault.callbacks()
            val err = PointerByReference()
            val w = PaveLib.lib.pave_open_with(path, ks, err) ?: throw IllegalStateException(take(err.value).optString("error"))
            return Wallet(w, ks)
        }

        /** Start joining: the request (hex) to take to the town, and a function to finish with its reply. */
        fun join(name: String, path: String, vault: AndroidVault): Pair<String, (String) -> Wallet> {
            val req = PointerByReference()
            val j = PaveLib.lib.pave_join_begin(req)
            val request = take(req.value).getString("request")
            return request to { reply: String ->
                val ks = vault.callbacks()
                val err = PointerByReference()
                val w = PaveLib.lib.pave_join_finish(j, reply, name, path, ks, err) ?: throw IllegalStateException(take(err.value).optString("error"))
                Wallet(w, ks)
            }
        }
    }
}
