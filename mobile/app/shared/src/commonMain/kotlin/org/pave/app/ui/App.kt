package org.pave.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.pave.app.Counter
import org.pave.app.Door
import org.pave.app.PaveJoin
import org.pave.app.PaveWallet
import org.pave.app.Platform
import org.pave.app.QrTurn
import org.pave.app.scanInvite
import org.pave.app.showInvite
import org.pave.app.text

/** What a platform draws: a QR code, and a camera that reads them until told to stop. */
class Qr(val image: @Composable (String) -> Unit, val scanner: @Composable (onScan: (String) -> Boolean) -> Unit)

private enum class Screen { Home, Join, CounterCafe, CounterCourier, DoorCourier, DoorCustomer }

/**
 * The app: join a town, then the in-person steps of a delivery. The cafe's
 * tablet and the courier at the counter, over Wi-Fi Aware; the courier and
 * the customer at the door, in QR frames.
 */
@Composable
fun App(platform: Platform, qr: Qr) {
    var wallet by remember { mutableStateOf<PaveWallet?>(null) }
    var screen by remember { mutableStateOf(Screen.Home) }
    var status by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { wallet = runCatching { platform.openWallet() }.getOrNull() }
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                val w = wallet
                when {
                    w == null || screen == Screen.Join -> JoinScreen(platform) { wallet = it; screen = Screen.Home }
                    screen == Screen.Home -> Home(w) { screen = it }
                    screen == Screen.CounterCafe -> CounterCafe(w, platform, qr) { status = it; screen = Screen.Home }
                    screen == Screen.CounterCourier -> CounterCourier(w, platform, qr) { status = it; screen = Screen.Home }
                    screen == Screen.DoorCourier -> DoorCourier(w, qr) { status = it; screen = Screen.Home }
                    screen == Screen.DoorCustomer -> DoorCustomer(w, qr) { status = it; screen = Screen.Home }
                }
                if (status.isNotEmpty()) Text(status, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun Home(w: PaveWallet, go: (Screen) -> Unit) {
    var who by remember { mutableStateOf<JsonObject?>(null) }
    LaunchedEffect(w) { who = runCatching { w.call("whoami") }.getOrNull() }
    Text(who?.let { "${it.text("name")}: ${it.text("balance")} credit, class ${it.text("class")}" } ?: "…", style = MaterialTheme.typography.titleMedium)
    Text("At the counter", style = MaterialTheme.typography.labelLarge)
    Button(onClick = { go(Screen.CounterCafe) }, Modifier.fillMaxWidth()) { Text("Hand a bag to a courier") }
    Button(onClick = { go(Screen.CounterCourier) }, Modifier.fillMaxWidth()) { Text("Pick up a bag") }
    Text("At the door", style = MaterialTheme.typography.labelLarge)
    Button(onClick = { go(Screen.DoorCourier) }, Modifier.fillMaxWidth()) { Text("Hand over a bag") }
    Button(onClick = { go(Screen.DoorCustomer) }, Modifier.fillMaxWidth()) { Text("Receive a bag") }
}

@Composable
private fun JoinScreen(platform: Platform, joined: (PaveWallet) -> Unit) {
    val scope = rememberCoroutineScope()
    val join: PaveJoin = remember { platform.beginJoin() }
    var request by remember { mutableStateOf(join.request()) }
    var attested by remember { mutableStateOf(false) }
    var reply by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    Text("Join a town", style = MaterialTheme.typography.titleMedium)
    Text("Take this request to the town office. A town grants the hardware class only with this device's attestation.")
    OutlinedButton(onClick = {
        scope.launch { runCatching { join.attest(request.second); request = join.request(); attested = true }.onFailure { error = it.message ?: "$it" } }
    }, enabled = !attested) { Text(if (attested) "Attested" else "Attest this device") }
    Text(request.first.take(48) + "…", style = MaterialTheme.typography.bodySmall)
    OutlinedTextField(name, { name = it }, label = { Text("Your name in this wallet") }, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(reply, { reply = it.trim() }, label = { Text("The town's reply") }, modifier = Modifier.fillMaxWidth())
    Button(onClick = { scope.launch { runCatching { joined(join.finish(reply, name.ifBlank { "me" })) }.onFailure { error = it.message ?: "$it" } } }, enabled = reply.isNotEmpty()) { Text("Finish joining") }
    if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
}

/** The cafe's tablet: show an invite, check the courier's badge over the radio, hand over the bag. */
@Composable
private fun CounterCafe(w: PaveWallet, platform: Platform, qr: Qr, done: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var manifest by remember { mutableStateOf("") }
    var dispatch by remember { mutableStateOf("") }
    var code by remember { mutableStateOf<String?>(null) }
    var badge by remember { mutableStateOf<Counter.Badge?>(null) }
    var proceed by remember { mutableStateOf<kotlinx.coroutines.CompletableDeferred<Boolean>?>(null) }
    Text("Hand a bag to a courier", style = MaterialTheme.typography.titleMedium)
    if (code == null) {
        OutlinedTextField(manifest, { manifest = it.trim() }, label = { Text("The bag's manifest") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(dispatch, { dispatch = it.trim() }, label = { Text("The co-op's dispatch") }, modifier = Modifier.fillMaxWidth())
        Button(onClick = {
            scope.launch {
                runCatching {
                    val (link, invite) = w.showInvite(listOf(JsonObject(mapOf("wifi_aware" to JsonPrimitive("pave-pickup")))))
                    code = invite.code
                    val radio = platform.radio(invite, showing = true) ?: error("this phone has no radio for that")
                    try {
                        Counter.cafe(w, link, radio, dispatch, manifest) { b -> badge = b; kotlinx.coroutines.CompletableDeferred<Boolean>().also { proceed = it }.await() }
                    } finally { radio.close() }
                }.onSuccess { done("Handed to ${it.courier}") }.onFailure { done("Not handed over: ${it.message}") }
            }
        }, enabled = manifest.isNotEmpty() && dispatch.isNotEmpty()) { Text("Show the code") }
    } else {
        val b = badge
        if (b == null) {
            Text("The courier scans this:")
            qr.image(code!!)
        } else {
            Text("Badge: ${b.courier}, from the co-op", style = MaterialTheme.typography.titleMedium)
            Button(onClick = { proceed?.complete(true) }) { Text("Hand over the bag") }
            OutlinedButton(onClick = { proceed?.complete(false) }) { Text("Don't") }
        }
    }
}

/** The courier at the counter: scan the tablet's invite, show the badge over the radio, take the bag. */
@Composable
private fun CounterCourier(w: PaveWallet, platform: Platform, qr: Qr, done: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var badgeKey by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var working by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { badgeKey = runCatching { w.call("identity", mapOf("label" to JsonPrimitive("courier"))).text("credential") }.getOrDefault("") }
    Text("Pick up a bag", style = MaterialTheme.typography.titleMedium)
    if (working) Text("Connected; showing your badge…")
    else if (!scanning) Button(onClick = { scanning = true }, enabled = badgeKey.isNotEmpty()) { Text("Scan the cafe's code") }
    else qr.scanner { code ->
        scanning = false
        working = true
        scope.launch {
            runCatching {
                val (link, invite) = w.scanInvite(code)
                val radio = platform.radio(invite, showing = false) ?: error("this phone has no radio for that")
                try { Counter.courier(w, link, radio, badgeKey) } finally { radio.close() }
            }.onSuccess { done("You have the bag") }.onFailure { done("No bag: ${it.message}") }
        }
        true
    }
}

/** A turn at the door: show frames in a loop, or scan the other screen's. */
@Composable
private fun FrameLoop(frames: List<String>, qr: Qr) {
    var i by remember(frames) { mutableStateOf(0) }
    LaunchedEffect(frames) { while (true) { delay(250); i = (i + 1) % frames.size } }
    Text("Frame ${i + 1} of ${frames.size}", style = MaterialTheme.typography.bodySmall)
    qr.image(frames[i])
}

/** The courier at the door: scan the customer's invite, then alternate turns. */
@Composable
private fun DoorCourier(w: PaveWallet, qr: Qr, done: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var manifest by remember { mutableStateOf("") }
    var turn by remember { mutableStateOf<QrTurn?>(null) }
    var showing by remember { mutableStateOf<List<String>?>(null) }
    var step by remember { mutableStateOf(0) }
    Text("Hand over a bag", style = MaterialTheme.typography.titleMedium)
    when (step) {
        0 -> {
            OutlinedTextField(manifest, { manifest = it.trim() }, label = { Text("The bag's manifest") }, modifier = Modifier.fillMaxWidth())
            if (manifest.isNotEmpty()) qr.scanner { code ->
                scope.launch { val (link, _) = w.scanInvite(code); turn = QrTurn(link); showing = Door.courierFirst(w, turn!!); step = 1 }
                true
            }
        }
        1 -> {
            Text("Show the customer; then scan theirs.")
            showing?.let { FrameLoop(it, qr) }
            OutlinedButton(onClick = { step = 2 }) { Text("Scan the customer's screen") }
        }
        2 -> qr.scanner { f ->
            val t = turn!!
            scope.launch { if (t.scanned(f, 2)) { showing = Door.courierHandOver(w, t, manifest); step = 3 } }
            false
        }
        else -> {
            Text("Handed over. Show the customer this, then you're done.")
            showing?.let { FrameLoop(it, qr) }
            Button(onClick = { done("Handed over at the door") }) { Text("Done") }
        }
    }
}

/** The customer at the door: show an invite, then alternate turns, and confirm. */
@Composable
private fun DoorCustomer(w: PaveWallet, qr: Qr, done: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var invite by remember { mutableStateOf<String?>(null) }
    var turn by remember { mutableStateOf<QrTurn?>(null) }
    var showing by remember { mutableStateOf<List<String>?>(null) }
    var step by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) { val (link, inv) = w.showInvite(emptyList()); turn = QrTurn(link); invite = inv.code }
    Text("Receive a bag", style = MaterialTheme.typography.titleMedium)
    when (step) {
        0 -> {
            Text("The courier scans this; then scan theirs.")
            invite?.let { qr.image(it) }
            OutlinedButton(onClick = { step = 1 }) { Text("Scan the courier's screen") }
        }
        1 -> qr.scanner { f ->
            val t = turn!!
            scope.launch { if (t.scanned(f, 1)) { showing = Door.customerAnswer(w, t); step = 2 } }
            false
        }
        2 -> {
            Text("Show the courier; then scan theirs.")
            showing?.let { FrameLoop(it, qr) }
            OutlinedButton(onClick = { step = 3 }) { Text("Scan the courier's screen") }
        }
        else -> qr.scanner { f ->
            val t = turn!!
            scope.launch {
                if (t.scanned(f, 2)) {
                    runCatching { Door.customerConfirm(w, t) }
                        .onSuccess { done("Received and confirmed") }
                        .onFailure { done("Not confirmed: ${it.message}") }
                }
            }
            false
        }
    }
}
