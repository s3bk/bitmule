package net.bitmule

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.fillMaxSize

class MainActivity : ComponentActivity() {

    // Cold-start deep-link handling: if the app was launched by an
    // ACTION_VIEW intent (system opened a bitmule.qdat.net link), the
    // URL is here; otherwise null.  Kept as State so Compose recomposes
    // when a warm-start VIEW intent arrives via onNewIntent().
    private val initialUrl = mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        initialUrl.value = pickUrl(intent)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val url = remember { initialUrl }
                    BitmuleApp(initialUrl = url.value, onConsumedUrl = { url.value = null })
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // App was already running when a new bitmule URL was tapped.
        pickUrl(intent)?.let { initialUrl.value = it }
    }

    // Extract the bitmule share URL from either an ACTION_VIEW (deep
    // link) or an ACTION_SEND text share.  Returns null for any other
    // intent shape.
    private fun pickUrl(intent: Intent?): String? {
        if (intent == null) return null
        return when (intent.action) {
            Intent.ACTION_VIEW -> intent.dataString
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            else -> null
        }
    }
}
