package org.pave.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.pave.app.ui.App
import org.pave.app.ui.Qr

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val platform = AndroidPlatform(applicationContext)
        setContent { App(platform, Qr(image = { AndroidQrImage(it) }, scanner = { AndroidQrScanner(it) })) }
    }
}
