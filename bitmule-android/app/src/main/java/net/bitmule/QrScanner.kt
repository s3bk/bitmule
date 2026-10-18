package net.bitmule

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Full-screen camera view that looks for a QR code in every frame (the whole
 * frame, any rotation; decoding is `decodeQr` in the FFI crate) and hands the
 * first text it reads to [onResult].
 */
@Composable
fun QrScanner(onResult: (String) -> Unit, onClose: () -> Unit) {
    val context = LocalContext.current
    var allowed by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var denied by remember { mutableStateOf(false) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        allowed = it
        denied = !it
    }
    LaunchedEffect(Unit) { if (!allowed) ask.launch(Manifest.permission.CAMERA) }

    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            if (allowed) {
                CameraPreview(onResult)
            } else if (denied) {
                Text(
                    "The camera permission is needed to scan a code.",
                    color = Color.White,
                    modifier = Modifier.align(Alignment.Center).padding(32.dp),
                )
            }
            Text(
                "Scan a bitmule QR code",
                color = Color.White,
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 96.dp),
            )
            OutlinedButton(
                onClick = onClose,
                modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 32.dp),
            ) { Text("Cancel", color = Color.White) }
        }
    }
}

@Composable
private fun CameraPreview(onResult: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current
    val found = remember { AtomicBoolean(false) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    DisposableEffect(Unit) { onDispose { executor.shutdown() } }

    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { ctx ->
            // a TextureView: the default SurfaceView stays black inside a dialog window
            val view = PreviewView(ctx).apply { implementationMode = PreviewView.ImplementationMode.COMPATIBLE }
            val providerFuture = ProcessCameraProvider.getInstance(ctx)
            providerFuture.addListener({
                val provider = providerFuture.get()
                val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                analysis.setAnalyzer(executor) { frame ->
                    try {
                        if (!found.get()) {
                            // the Y plane is the grayscale picture
                            val plane = frame.planes[0]
                            val gray = ByteArray(plane.buffer.remaining()).also { plane.buffer.get(it) }
                            val text = uniffi.bitmule_mobile_ffi.decodeQr(
                                gray, frame.width.toUInt(), frame.height.toUInt(), plane.rowStride.toUInt(),
                            )
                            if (text != null && found.compareAndSet(false, true)) {
                                view.post { onResult(text.trim()) }
                            }
                        }
                    } finally {
                        frame.close()
                    }
                }
                provider.unbindAll()
                provider.bindToLifecycle(lifecycle, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }, ContextCompat.getMainExecutor(ctx))
            view
        },
    )
}
