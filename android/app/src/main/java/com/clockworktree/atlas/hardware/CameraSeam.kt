package com.clockworktree.atlas.hardware

import android.content.Context

/**
 * CameraSeam ↔ iOS camera (`CaptureController` / `AudioCaptureController`).
 *
 * CameraX (ImageCapture / VideoCapture) for photo + video, and MediaRecorder/AudioRecord for
 * audio. Captured bytes go straight into the persona's vault folder (AtlasSession.addItem).
 *
 * PROVENANCE note (mirror of iOS): capture should be ATTESTED at the point of capture so the
 * item carries verified-human authorship. That attestation is a node + KeystoreSeam concern and
 * is a TODO here — this seam only produces the media bytes.
 *
 * STATUS: SCAFFOLD. Binding a camera use-case needs a lifecycle owner + PreviewView; stubbed.
 */
class CameraSeam(@Suppress("unused") private val context: Context) {

    /** Capture a still. TODO: ImageCapture.takePicture -> bytes; requires CAMERA permission +
     *  a bound CameraX lifecycle. */
    suspend fun capturePhoto(): ByteArray {
        TODO("Wire CameraX ImageCapture.takePicture; return JPEG bytes for the vault")
    }

    /** Record video to a temp file. TODO: VideoCapture + Recorder; return the file/bytes. */
    suspend fun recordVideo(@Suppress("UNUSED_PARAMETER") maxSeconds: Int): ByteArray {
        TODO("Wire CameraX VideoCapture Recorder; return MP4 bytes for the vault")
    }

    /** Record audio. TODO: MediaRecorder (AAC/m4a) or AudioRecord; return the bytes. */
    suspend fun recordAudio(@Suppress("UNUSED_PARAMETER") maxSeconds: Int): ByteArray {
        TODO("Wire MediaRecorder AAC capture; return m4a bytes for the vault")
    }
}
