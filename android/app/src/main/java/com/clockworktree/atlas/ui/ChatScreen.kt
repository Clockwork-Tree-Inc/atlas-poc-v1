package com.clockworktree.atlas.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.PersonAddAlt
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.clockworktree.atlas.model.AppSpace
import com.clockworktree.atlas.model.ChatMessage
import com.clockworktree.atlas.session.AtlasSession

/**
 * A CHAT — the SwiftUI `MessagingView` equivalent. Works immediately (self-chat); add people/
 * companies or an AI-agent "librarian". The librarian SURFACES + CITES from your library and
 * never invents answers (see AtlasSession.aiReplyIfPresent — retrieval is a TODO stub).
 */
@Composable
fun MessagingView(session: AtlasSession, chat: AppSpace, modifier: Modifier = Modifier) {
    var draft by remember { mutableStateOf("") }
    var menuOpen by remember { mutableStateOf(false) }
    var showAddMember by remember { mutableStateOf(false) }
    var newMember by remember { mutableStateOf("") }
    val listState = rememberLazyListState()

    LaunchedEffect(chat.messages.size) {
        if (chat.messages.isNotEmpty()) listState.animateScrollToItem(chat.messages.lastIndex)
    }

    Column(modifier.fillMaxSize()) {
        // members bar + add menu
        Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                buildString {
                    append(session.username.ifBlank { "you" })
                    chat.members.forEach { append(" · $it") }
                },
                Modifier.weight(1f),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            IconButton(onClick = { menuOpen = true }) { Icon(Icons.Filled.PersonAddAlt, "Add") }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(text = { Text("Add person / company") }, onClick = {
                    menuOpen = false; showAddMember = true
                })
                DropdownMenuItem(text = { Text("Add AI agent (librarian)") }, onClick = {
                    menuOpen = false; session.addAgent(chat)
                })
            }
        }

        LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = listState,
            contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp)) {
            if (chat.messages.isEmpty()) {
                items(listOf("empty")) { Text("No messages", Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(chat.messages, key = { it.id }) { Bubble(session, it) }
        }

        Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = draft, onValueChange = { draft = it },
                placeholder = { Text("Message") },
                modifier = Modifier.weight(1f),
            )
            IconButton(
                onClick = { if (draft.isNotBlank()) { session.sendMessage(chat, draft.trim()); draft = "" } },
                enabled = draft.isNotBlank(),
            ) { Icon(Icons.AutoMirrored.Filled.Send, "Send") }
        }
    }

    if (showAddMember) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { showAddMember = false; newMember = "" },
            title = { Text("Add to chat") },
            text = {
                OutlinedTextField(value = newMember, onValueChange = { newMember = it },
                    label = { Text("Name or company") }, singleLine = true)
            },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = {
                    session.addChatMember(chat, newMember.trim()); newMember = ""; showAddMember = false
                }) { Text("Add") }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = {
                    showAddMember = false; newMember = ""
                }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun Bubble(session: AtlasSession, m: ChatMessage) {
    val mine = m.sender == session.username.ifBlank { "you" }
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start) {
        Column(
            Modifier
                .widthIn(max = 300.dp)
                .background(
                    if (mine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                    RoundedCornerShape(14.dp),
                )
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            if (!mine) Text(m.sender, style = MaterialTheme.typography.labelSmall,
                color = if (m.isAgent) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant)
            Text(m.text, color = if (mine) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
        }
    }
}

/** CHATS tab — the consolidated list of every chat across the active persona's space tree. */
@Composable
fun ChatsListScreen(session: AtlasSession, modifier: Modifier = Modifier) {
    val root = session.currentRoot
    if (root == null) {
        EmptyState("No persona selected", "Pick a persona on Home.", modifier); return
    }
    val chats = root.allChats()
    var open by remember { mutableStateOf<AppSpace?>(null) }

    val chat = open
    if (chat != null) {
        MessagingView(session, chat, modifier)
        androidx.activity.compose.BackHandler { open = null }
        return
    }

    if (chats.isEmpty()) {
        EmptyState("No chats", "Start one inside a space (Spaces tab -> + -> New chat).", modifier)
        return
    }
    LazyColumn(modifier.fillMaxSize()) {
        items(chats, key = { it.id }) { c ->
            ListItem(
                headlineContent = { Text(c.name) },
                supportingContent = { Text(c.messages.lastOrNull()?.text ?: "no messages yet") },
                modifier = Modifier.clickable { open = c },
            )
        }
    }
}
