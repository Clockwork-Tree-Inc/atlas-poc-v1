package com.clockworktree.atlas.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.clockworktree.atlas.model.AppSpace
import com.clockworktree.atlas.session.AtlasSession

/**
 * DOCUMENT EDITOR — the SwiftUI `DocumentEditorView` equivalent. Exactly ONE writing surface:
 *   - a Title field,
 *   - an Author shown READ-ONLY from the signing persona (never a typed field, no "add block" UI),
 *   - one body text area.
 * On save it would be sealed + provenance-attested by the node; here it stores a local item and
 * logs the TODO. Authorship is bound to the identity, not typed.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DocumentEditorScreen(
    session: AtlasSession,
    space: AppSpace,
    existingVaultName: String?,
    onClose: () -> Unit,
) {
    var title by remember { mutableStateOf(existingVaultName?.removeSuffix(".atlasdoc") ?: "Untitled") }
    var body by remember { mutableStateOf("") }
    val author = session.username.trim().ifEmpty { "this persona" }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (existingVaultName == null) "New document" else "Edit") },
                navigationIcon = { IconButton(onClick = onClose) { Icon(Icons.Filled.Close, "Close") } },
                actions = {
                    TextButton(onClick = {
                        session.saveDocument(space, title, body, existingVaultName)
                        onClose()
                    }) { Text("Save") }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            OutlinedTextField(
                value = title, onValueChange = { title = it },
                label = { Text("Title") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            )
            // Author is READ-ONLY — it is the signing identity, never typed. No verified badge:
            // Real-ID verification isn't built.
            Row(Modifier.fillMaxWidth().padding(vertical = 12.dp)) {
                Text("Author: ", style = MaterialTheme.typography.bodyMedium)
                Text(author, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            OutlinedTextField(
                value = body, onValueChange = { body = it },
                label = { Text("Document") },
                modifier = Modifier.fillMaxWidth().weight(1f),
            )
            Text(
                "Signed as “$author” and provenanced on save — authorship is bound to your " +
                    "identity, not typed. (Sealing + attestation are a node TODO.)",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
    }
}

/** OFFICE tab — create documents and see every document across the active persona's spaces. */
@Composable
fun OfficeScreen(session: AtlasSession, modifier: Modifier = Modifier) {
    val root = session.currentRoot
    if (root == null) {
        EmptyState("Pick a persona", "Select a persona on Home.", modifier); return
    }
    var editing by remember { mutableStateOf<Pair<AppSpace, String?>?>(null) }

    val e = editing
    if (e != null) {
        DocumentEditorScreen(session, e.first, e.second) { editing = null }
        return
    }

    val docs = root.allFolders().flatMap { it.items }.filter { it.kind in setOf("doc", "text", "pdf") }
    LazyColumn(modifier.fillMaxSize()) {
        item {
            ListItem(
                headlineContent = { Text("New document") },
                leadingContent = { Icon(Icons.Filled.Add, null) },
                modifier = Modifier.clickable { editing = root to null },
            )
        }
        if (docs.isEmpty()) {
            item {
                Text("No documents", Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        items(docs, key = { it.id }) { d ->
            ListItem(
                headlineContent = { Text(d.vaultName) },
                modifier = if (d.kind == "doc")
                    Modifier.clickable { editing = root to d.vaultName } else Modifier,
            )
        }
    }
}
