package com.clockworktree.atlas.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.clockworktree.atlas.session.AtlasSession

/**
 * CAPTURE — the SwiftUI `CaptureTabView` equivalent. Records photo/video/audio straight into
 * the persona's default vault folder. The actual capture is a CameraSeam TODO; each button here
 * appends a placeholder item so the vault flow is exercisable end-to-end in the UI.
 */
@Composable
fun CaptureScreen(session: AtlasSession, modifier: Modifier = Modifier) {
    val folder = session.defaultCaptureFolder()
    if (folder == null) {
        EmptyState("Pick a persona", "Select a persona on Home to capture.", modifier); return
    }

    Column(modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Saving to: ${folder.name}", style = MaterialTheme.typography.titleMedium)
        SeamTodo("CameraSeam — CameraX ImageCapture / VideoCapture + MediaRecorder audio")

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CaptureButton("Photo", Icons.Filled.PhotoCamera, Modifier.weight(1f)) {
                session.addItem("photo-${folder.items.size + 1}.jpg", "image", folder)
            }
            CaptureButton("Video", Icons.Filled.Videocam, Modifier.weight(1f)) {
                session.addItem("clip-${folder.items.size + 1}.mp4", "video", folder)
            }
            CaptureButton("Audio", Icons.Filled.Mic, Modifier.weight(1f)) {
                session.addItem("audio-${folder.items.size + 1}.m4a", "audio", folder)
            }
        }

        Text("Recent in ${folder.name} (${folder.items.size})", style = MaterialTheme.typography.titleSmall)
        LazyColumn(Modifier.fillMaxWidth()) {
            items(folder.items, key = { it.id }) { it2 ->
                ListItem(headlineContent = { Text(it2.vaultName) }, supportingContent = { Text(it2.kind) })
            }
        }
    }
}

@Composable
private fun CaptureButton(label: String, icon: ImageVector, modifier: Modifier, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, modifier = modifier) {
        Icon(icon, null, Modifier.padding(end = 6.dp)); Text(label)
    }
}
