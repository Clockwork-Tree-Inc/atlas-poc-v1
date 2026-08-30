package com.clockworktree.atlas.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.PersonOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.clockworktree.atlas.model.Persona
import com.clockworktree.atlas.model.PersonaTier
import com.clockworktree.atlas.session.AtlasSession

/**
 * HOME — the SwiftUI `HomeView`/`HomeTabView` equivalent: system status, the ONE Real-ID slot,
 * N pseudonyms, and a "+" to add more. The base persona is anonymous.
 *
 * Honesty invariant: NOTHING renders "verified". The Real-ID slot is a reserved slot only —
 * `isVerified` is hard-wired false because verification isn't built.
 */
@Composable
fun HomeScreen(session: AtlasSession, modifier: Modifier = Modifier) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { SectionHeader("System status") }
        item { StatusRow("Enrolled", session.enrolled) }
        item {
            StatusRow("Live presence", session.presenceLive && !session.presenceLocked,
                detail = if (session.presenceLocked) "LOCKED" else if (session.presenceLive) "present" else "waiting (TODO: SensorSeam)")
        }
        item { StatusRow("Session running", session.running, "${session.ratchetTicks} ticks") }
        item {
            StatusRow("Node / peers", session.nodeConnected,
                detail = if (session.nodeConnected) session.nodeUrl else "off (TODO: NodeClient)")
        }

        item { SectionHeader("Real ID — one per person, optional") }
        item {
            val rid = session.realIdPersona
            if (rid != null) {
                PersonaRow(session, rid, kind = "Real ID · unverified")
            } else {
                ListItem(
                    headlineContent = { Text("Set up your Real ID") },
                    supportingContent = {
                        Text("Optional. Verification (ePassport/NFC) arrives with the eID reader — " +
                            "not available yet, so no persona can be marked verified.")
                    },
                    leadingContent = { Icon(Icons.Filled.AddCircle, null) },
                    modifier = Modifier.clickable { session.createPersona("real-id", PersonaTier.REAL_ID) },
                )
            }
        }

        item { SectionHeader("Pseudonyms") }
        if (session.pseudonyms.isEmpty()) {
            item { Text("no pseudonyms yet", color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        items(session.pseudonyms, key = { it.codeHex(8) }) { p ->
            PersonaRow(session, p, kind = "pseudonym")
        }
        item {
            ListItem(
                headlineContent = { Text("Add pseudonym") },
                supportingContent = { Text("Each is unlinkable and owns its own vault, chats, and history.") },
                leadingContent = { Icon(Icons.Filled.AddCircle, null) },
                modifier = Modifier.clickable {
                    session.createPersona("pseudonym-${session.pseudonyms.size}", PersonaTier.ANONYMOUS)
                },
            )
        }
    }
}

@Composable
private fun PersonaRow(session: AtlasSession, p: Persona, kind: String) {
    val active = p == session.currentPersona
    ListItem(
        headlineContent = { Text(p.codeHex()) },          // the CODE is the persona identity
        supportingContent = { Text(kind) },
        leadingContent = { Icon(Icons.Filled.PersonOutline, null) },
        trailingContent = {
            if (active) Icon(Icons.Filled.CheckCircle, "active", tint = MaterialTheme.colorScheme.primary)
            else Text("switch", color = MaterialTheme.colorScheme.primary)
        },
        modifier = Modifier.clickable { session.switchPersona(p) },
    )
}

@Composable
private fun StatusRow(title: String, ok: Boolean, detail: String? = null) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Surface(
            color = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
            shape = CircleShape,
            modifier = Modifier.size(10.dp).clip(CircleShape),
        ) {}
        Text(title, Modifier.padding(start = 10.dp))
        if (detail != null) {
            Text(detail, Modifier.padding(start = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
internal fun SectionHeader(text: String) {
    Text(text, style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 12.dp, bottom = 2.dp))
}
