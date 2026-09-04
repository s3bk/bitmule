package net.bitmule

import android.content.Intent
import android.os.Environment
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

// Minimal Compose UI for the bitmule Android shell.  Two tabs:
//   Receive — paste URL / arrive via VIEW intent, download, share
//   Send    — TODO in a follow-up PR; wired to a stub for shape
//
// Rust core (bitmule-mobile-ffi) is loaded via UniFFI-generated
// Kotlin bindings (net.bitmule.uniffi.*) which are emitted by the
// `uniffi-bindgen generate` step from the FFI crate README.  The
// bindings aren't checked in — they're a build artifact.  Until
// the first `cargo ndk` build has run, this file references types
// that don't yet exist; that's expected and matches the M1-then-M2
// staging in the FFI crate README.

@Composable
fun BitmuleApp(
    initialUrl: String?,
    onConsumedUrl: () -> Unit,
) {
    var tab by remember { mutableStateOf(if (initialUrl != null) 1 else 0) }
    Column(modifier = Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = tab) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Send") })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Receive") })
        }
        when (tab) {
            0 -> SendPane()
            else -> ReceivePane(initialUrl = initialUrl, onConsumedUrl = onConsumedUrl)
        }
    }
}

@Composable
private fun SendPane() {
    // Placeholder — full send flow lands in M3 (file picker → SAF →
    // bitmule-mobile-ffi.send_file → QR + share URL surfaces here).
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text("Send: coming next PR", style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun ReceivePane(
    initialUrl: String?,
    onConsumedUrl: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var urlText by remember { mutableStateOf(initialUrl ?: "") }
    var status by remember { mutableStateOf<String>("idle") }
    var progress by remember { mutableStateOf(0f) }
    var completedFile by remember { mutableStateOf<File?>(null) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    // Auto-kick if we got launched via VIEW intent.
    LaunchedEffect(initialUrl) {
        if (!initialUrl.isNullOrEmpty()) {
            urlText = initialUrl
            onConsumedUrl()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = urlText,
            onValueChange = { urlText = it },
            label = { Text("bitmule URL") },
            placeholder = { Text("https://bitmule.qdat.net/#…") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )

        Button(
            enabled = urlText.isNotBlank() && status != "receiving",
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                scope.launch {
                    status = "receiving"
                    progress = 0f
                    errorMsg = null
                    completedFile = null
                    try {
                        val outDir = File(
                            context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS),
                            "bitmule",
                        ).apply { mkdirs() }
                        val outcome = withContext(Dispatchers.IO) {
                            // Bindings emitted by uniffi-bindgen live under
                            // net.bitmule.uniffi.  Signature per the UDL:
                            //   recvFile(url: String, outDir: String,
                            //            onProgress: ProgressListener): RecvOutcome
                            uniffi.bitmule_mobile_ffi.recvFile(
                                url = urlText,
                                outDir = outDir.absolutePath,
                                onProgress = object : uniffi.bitmule_mobile_ffi.ProgressListener {
                                    override fun onProgress(received: ULong, total: ULong, name: String) {
                                        progress =
                                            if (total > 0uL) received.toFloat() / total.toFloat() else 0f
                                    }
                                },
                            )
                        }
                        completedFile = File(outcome.path)
                        status = "complete"
                        progress = 1f
                    } catch (e: Throwable) {
                        errorMsg = e.message ?: e::class.java.simpleName
                        status = "error"
                    }
                }
            },
        ) {
            Text(if (status == "receiving") "Receiving…" else "Fetch")
        }

        if (status == "receiving") {
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth(),
            )
        }

        errorMsg?.let { Text("error: $it", color = MaterialTheme.colorScheme.error) }

        completedFile?.let { file ->
            Text("✓ ${file.name}")
            Text(file.absolutePath, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    // FileProvider URI so other apps can read the file
                    // without a broad storage permission.
                    val uri = FileProvider.getUriForFile(
                        context,
                        "${context.packageName}.fileprovider",
                        file,
                    )
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = context.contentResolver.getType(uri) ?: "*/*"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    context.startActivity(Intent.createChooser(send, "Share ${file.name}"))
                }) { Text("Share") }
            }
        }
    }
}
