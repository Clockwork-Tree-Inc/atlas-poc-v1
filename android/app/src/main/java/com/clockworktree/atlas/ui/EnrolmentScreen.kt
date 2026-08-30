package com.clockworktree.atlas.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.clockworktree.atlas.config.AtlasFlags
import com.clockworktree.atlas.session.AtlasSession

/**
 * Setup wizard — the SwiftUI `EnrolView` equivalent, condensed to the honest steps that the
 * thin client can actually stage:
 *   0 name · 1 anti-bot human proof (SensorSeam) · 2 ring bind (BleSeam) · 3 create identity
 *   (BiometricSeam + KeystoreSeam) · 4 done.
 *
 * Each hardware step is a STUB with a clear TODO — see the referenced seams. The ambient-only
 * path (skip the ring) is honoured, exactly as on iOS.
 */
@Composable
fun EnrolmentScreen(session: AtlasSession) {
    var step by remember { mutableIntStateOf(0) }
    val scroll = rememberScrollState()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Spacer(Modifier.height(24.dp))

        when (step) {
            0 -> {
                Big("🌳", "Welcome to Atlas", "One identity — live-present, anonymous, recoverable.")
                OutlinedTextField(
                    value = session.username,
                    onValueChange = { session.username = it },
                    label = { Text("Your name (e.g. aun)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                DisclaimerCard()
                Button(
                    onClick = { step = 1 },
                    enabled = session.username.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Continue") }
            }
            1 -> {
                Big("📳", "Prove you're human",
                    "Shake the phone a random number of times. Real motion from the attested " +
                        "sensor is what proves a live person — a bot can't fake it.")
                SeamTodo("SensorSeam.shakeChallenge() — SensorManager accelerometer, exact-count target")
                Button(onClick = { step = 2 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Continue (stubbed pass)")
                }
            }
            2 -> {
                Big("💍", "Wear your ring",
                    "Your ring proves you're a live person; the handshake binds it to this phone. " +
                        "Ambient (phone sensors) always runs — a ring ADDS biological liveness on top.")
                SeamTodo("BleSeam.scan()/connect()/pulse() — BluetoothLeScanner + GATT; same-hand tap bind")
                Button(onClick = { step = 3 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Continue — ring bound (stub)")
                }
                Button(onClick = { step = 3 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Continue with ambient (skip ring)")
                }
            }
            3 -> {
                Big("🫆", "Create your identity",
                    "A biometric prompt binds your identity, keys, vault, and recovery in one motion. " +
                        "The private key never leaves the hardware Keystore/StrongBox.")
                SeamTodo("BiometricSeam.authenticate() ↔ KeystoreSeam.createIdentityKey(strongBox=true)")
                Button(onClick = { step = 4 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Continue with biometric (stub)")
                }
            }
            else -> {
                Big("✅", "You're all set",
                    "Your identity is staged. In the full build it's live under your biometric + " +
                        "live presence, and the node runs the session crypto.")
                Button(onClick = { session.completeEnrolment() }, modifier = Modifier.fillMaxWidth()) {
                    Text("Enter Atlas")
                }
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun Big(emoji: String, title: String, subtitle: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(emoji, style = MaterialTheme.typography.displayMedium)
        Text(title, style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
        Text(subtitle, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
    }
}

@Composable
private fun DisclaimerCard() {
    Card(Modifier.fillMaxWidth()) {
        Text(
            AtlasFlags.disclaimerShort,
            Modifier.padding(14.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** A visible marker that this step is a scaffold, not a wired seam. */
@Composable
internal fun SeamTodo(text: String) {
    Card(Modifier.fillMaxWidth()) {
        Text(
            "TODO (stub): $text",
            Modifier.padding(12.dp),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.tertiary,
        )
    }
}
