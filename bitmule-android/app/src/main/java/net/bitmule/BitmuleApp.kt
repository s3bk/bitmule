package net.bitmule

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Environment
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
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
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pickedName by remember { mutableStateOf<String?>(null) }
    var pickedPath by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf("idle") }        // idle | sending | complete | error
    var shareUrl by remember { mutableStateOf<String?>(null) }
    var qrBytes by remember { mutableStateOf<ByteArray?>(null) }
    var errorMsg by remember { mutableStateOf<String?>(null) }
    var multiSend by remember { mutableStateOf(false) }

    // SAF picker — returns a content:// URI that we must copy to a
    // real file path (the Rust core needs a filesystem path, not
    // a Uri).  Copy runs on Dispatchers.IO in the launcher callback.
    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val (name, path) = withContext(Dispatchers.IO) {
                copyPickedUriToCache(context, uri)
            }
            pickedName = name
            pickedPath = path
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Button(
            enabled = status != "sending",
            modifier = Modifier.fillMaxWidth(),
            onClick = { picker.launch(arrayOf("*/*")) },
        ) {
            Text(pickedName?.let { "Pick file — currently: $it" } ?: "Pick file")
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = multiSend, onCheckedChange = { multiSend = it })
            Text("Keep URL live for multiple receivers")
        }

        Button(
            enabled = pickedPath != null && status != "sending",
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                val path = pickedPath ?: return@Button
                scope.launch {
                    status = "sending"
                    shareUrl = null
                    qrBytes = null
                    errorMsg = null
                    try {
                        withContext(Dispatchers.IO) {
                            uniffi.bitmule_mobile_ffi.sendFile(
                                server = DEFAULT_SERVER,
                                filePath = path,
                                multi = multiSend,
                                onUrl = object : uniffi.bitmule_mobile_ffi.UrlListener {
                                    override fun onUrl(
                                        url: String,
                                        sessionHex: String,
                                        fileName: String,
                                        fileSize: ULong,
                                    ) {
                                        // Marshaled back onto the main thread
                                        // by Compose the moment we touch a
                                        // MutableState; safe from any thread.
                                        shareUrl = url
                                        qrBytes = try {
                                            uniffi.bitmule_mobile_ffi.qrPngBytes(url, 12u)
                                        } catch (_: Throwable) { null }
                                    }
                                },
                            )
                        }
                        status = "complete"
                    } catch (e: Throwable) {
                        errorMsg = e.message ?: e::class.java.simpleName
                        status = "error"
                    }
                }
            },
        ) {
            Text(if (status == "sending") "Sending…" else "Share")
        }

        shareUrl?.let { url ->
            SelectionContainer {
                Text(
                    text = url,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("bitmule url", url))
                }) { Text("Copy") }
                OutlinedButton(onClick = {
                    val send = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, url)
                    }
                    context.startActivity(Intent.createChooser(send, "Share URL"))
                }) { Text("Share URL") }
            }
            qrBytes?.let { bytes ->
                val bmp = remember(bytes) { BitmapFactory.decodeByteArray(bytes, 0, bytes.size) }
                if (bmp != null) {
                    Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = "QR code for share URL",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 200.dp, max = 320.dp),
                    )
                }
            }
        }

        errorMsg?.let { Text("error: $it", color = MaterialTheme.colorScheme.error) }

        if (status == "complete") {
            Text("✓ transfer complete", color = MaterialTheme.colorScheme.primary)
        }
    }
}

private const val DEFAULT_SERVER = "https://bitmule.qdat.net"

/** Copy a SAF-picked content:// URI to a private cache file so the
 *  Rust core has a real filesystem path to hash + send.  Returns
 *  (displayName, absolutePath).  Caller runs this on Dispatchers.IO. */
private fun copyPickedUriToCache(context: Context, uri: Uri): Pair<String, String> {
    val name = context.contentResolver.query(uri, null, null, null, null)?.use { c ->
        val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
        if (i >= 0 && c.moveToFirst()) c.getString(i) else null
    } ?: "file.bin"
    val dir = File(context.cacheDir, "outgoing").apply { mkdirs() }
    val dest = File(dir, name)
    context.contentResolver.openInputStream(uri)!!.use { input ->
        dest.outputStream().use { output -> input.copyTo(output) }
    }
    return name to dest.absolutePath
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
