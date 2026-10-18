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
    // `safeDrawingPadding()` inset shifts the whole tree below the
    // display cutout / status bar / IME so the TabRow isn't clipped
    // by the camera notch on phones with a top cutout (where the
    // tap area was being swallowed by the notch region).
    Column(modifier = Modifier
        .fillMaxSize()
        .safeDrawingPadding()) {
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
    // Materialized files: display name + cache path per picked URI.
    // Rust FFI needs real filesystem paths, so every SAF pick is
    // copied to app-scoped cache first.
    var pickedNames by remember { mutableStateOf<List<String>>(emptyList()) }
    var pickedPaths by remember { mutableStateOf<List<String>>(emptyList()) }
    var status by remember { mutableStateOf("idle") }        // idle | sending | complete | error
    var shareUrl by remember { mutableStateOf<String?>(null) }
    var qrBytes by remember { mutableStateOf<ByteArray?>(null) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    // Multi-file SAF picker — returns a list of content:// URIs.
    // Each Uri is copied to a private cache file on Dispatchers.IO
    // so the Rust core has a filesystem path per selected file.
    // F4 does NOT yet accept directory picks (SAF's OpenDocumentTree
    // returns a tree Uri that needs DocumentFile traversal + copy —
    // deferred to a follow-up).
    val picker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris: List<Uri> ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        scope.launch {
            val entries = withContext(Dispatchers.IO) {
                uris.map { copyPickedUriToCache(context, it) }
            }
            pickedNames = entries.map { it.first }
            pickedPaths = entries.map { it.second }
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
            Text(
                when {
                    pickedNames.isEmpty() -> "Pick file(s)"
                    pickedNames.size == 1 -> "Pick file(s) — currently: ${pickedNames[0]}"
                    else -> "Pick file(s) — currently: ${pickedNames.size} files (${pickedNames[0]} + ${pickedNames.size - 1} more)"
                }
            )
        }

        Button(
            enabled = pickedPaths.isNotEmpty() && status != "sending",
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                val paths = pickedPaths
                if (paths.isEmpty()) return@Button
                scope.launch {
                    status = "sending"
                    shareUrl = null
                    qrBytes = null
                    errorMsg = null
                    try {
                        withContext(Dispatchers.IO) {
                            uniffi.bitmule_mobile_ffi.sendFile(
                                server = DEFAULT_SERVER,
                                filePaths = paths,
                                multi = false, // the v2 protocol ends a send once its receivers are done
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
    // `true` when the completed transfer was a zip-store bundle
    // already unpacked into a directory by the FFI. Share intent
    // switches to ACTION_SEND_MULTIPLE listing the dir's files.
    var completedIsBundle by remember { mutableStateOf(false) }
    var completedName by remember { mutableStateOf<String?>(null) }
    var errorMsg by remember { mutableStateOf<String?>(null) }

    // Auto-kick if we got launched via VIEW intent.
    LaunchedEffect(initialUrl) {
        if (!initialUrl.isNullOrEmpty()) {
            urlText = initialUrl
            onConsumedUrl()
        }
    }

    var scanning by remember { mutableStateOf(false) }
    if (scanning) {
        QrScanner(
            onResult = { urlText = it; scanning = false },
            onClose = { scanning = false },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedButton(
            modifier = Modifier.fillMaxWidth(),
            onClick = { scanning = true },
        ) { Text("Scan QR") }

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
                        completedIsBundle = outcome.isBundle
                        completedName = outcome.name
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
            Text("✓ ${completedName ?: file.name}")
            Text(file.absolutePath, style = MaterialTheme.typography.bodySmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    if (completedIsBundle && file.isDirectory) {
                        // Bundle: multi-share every extracted file via
                        // ACTION_SEND_MULTIPLE. FileProvider grants a
                        // per-uri read scope; the receiver app picks
                        // which files to save.
                        val uris = file.listFiles()?.filter { it.isFile }?.map { child ->
                            FileProvider.getUriForFile(
                                context,
                                "${context.packageName}.fileprovider",
                                child,
                            )
                        } ?: emptyList()
                        if (uris.isNotEmpty()) {
                            val send = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
                                type = "*/*"
                                putParcelableArrayListExtra(
                                    Intent.EXTRA_STREAM,
                                    ArrayList(uris),
                                )
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                            context.startActivity(
                                Intent.createChooser(send, "Share ${uris.size} file(s)")
                            )
                        }
                    } else {
                        // Single file: standard FileProvider + ACTION_SEND.
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
                    }
                }) { Text(if (completedIsBundle) "Share files" else "Share") }
            }
        }
    }
}
