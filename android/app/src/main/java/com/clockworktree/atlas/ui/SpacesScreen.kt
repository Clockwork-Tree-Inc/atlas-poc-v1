package com.clockworktree.atlas.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.clockworktree.atlas.model.AppSpace
import com.clockworktree.atlas.model.SpaceItem
import com.clockworktree.atlas.model.SpaceKind
import com.clockworktree.atlas.session.AtlasSession

/**
 * SPACES — the SwiftUI `SpacesTabView` + `SpaceNavigatorView` equivalent: a navigable recursive
 * space tree for the active persona. Vault (root) -> folders / chats / market -> nested spaces.
 * A per-tab back-stack (mirrors iOS `path`) drives navigation without serialising AppSpace.
 */
@Composable
fun SpacesScreen(session: AtlasSession, modifier: Modifier = Modifier) {
    val root = session.currentRoot
    if (root == null) {
        EmptyState("No persona selected", "Pick a persona on Home to open its spaces.", modifier)
        return
    }
    // Back-stack of spaces; index 0 is the vault root.
    val stack = remember(session.currentPersona?.codeHex(8)) { mutableStateListOf(root) }
    val current = stack.last()

    BackHandler(enabled = stack.size > 1) { stack.removeAt(stack.lastIndex) }

    SpaceNavigator(
        session = session,
        space = current,
        modifier = modifier,
        canGoBack = stack.size > 1,
        onBack = { if (stack.size > 1) stack.removeAt(stack.lastIndex) },
        onOpen = { stack.add(it) },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SpaceNavigator(
    session: AtlasSession,
    space: AppSpace,
    modifier: Modifier,
    canGoBack: Boolean,
    onBack: () -> Unit,
    onOpen: (AppSpace) -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Pair<AppSpace, String?>?>(null) }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(space.name) },
                navigationIcon = {
                    if (canGoBack) IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                actions = {
                    if (space.kind == SpaceKind.VAULT || space.kind == SpaceKind.FOLDER) {
                        IconButton(onClick = { menuOpen = true }) { Icon(Icons.Filled.Add, "Add") }
                        DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                            DropdownMenuItem(text = { Text("New folder") }, onClick = {
                                menuOpen = false
                                session.createSpace(SpaceKind.FOLDER, "Folder", space)
                            })
                            DropdownMenuItem(text = { Text("New chat") }, onClick = {
                                menuOpen = false
                                session.createSpace(SpaceKind.CHAT, "Chat", space)
                            })
                            DropdownMenuItem(text = { Text("New market") }, onClick = {
                                menuOpen = false
                                session.createSpace(SpaceKind.MARKET, "Market", space)
                            })
                            DropdownMenuItem(text = { Text("New document") }, onClick = {
                                menuOpen = false
                                editing = space to null
                            })
                            DropdownMenuItem(text = { Text("Set as default capture folder") }, onClick = {
                                menuOpen = false
                                session.setDefaultCaptureFolder(space.id)
                            })
                        }
                    }
                },
            )
        },
    ) { padding ->
        val inner = Modifier.padding(padding)
        when (space.kind) {
            SpaceKind.VAULT, SpaceKind.FOLDER -> Cascade(session, space, inner, onOpen) { editing = space to it }
            SpaceKind.CHAT -> MessagingView(session, space, inner)
            SpaceKind.MARKET -> MarketWall(inner)
        }
    }

    editing?.let { (sp, name) ->
        DocumentEditorScreen(session, sp, name) { editing = null }
    }
}

@Composable
private fun Cascade(
    session: AtlasSession,
    space: AppSpace,
    modifier: Modifier,
    onOpen: (AppSpace) -> Unit,
    onEditDoc: (String) -> Unit,
) {
    LazyColumn(modifier.fillMaxSize()) {
        if (space.children.isNotEmpty()) {
            items(space.children, key = { it.id }) { child ->
                ListItem(
                    headlineContent = { Text(child.name) },
                    supportingContent = { Text(subtitle(child)) },
                    modifier = Modifier.clickable { onOpen(child) },
                )
            }
        }
        if (space.items.isNotEmpty()) {
            items(space.items, key = { it.id }) { item ->
                ItemRow(item, onEditDoc)
            }
        }
    }
}

@Composable
private fun ItemRow(item: SpaceItem, onEditDoc: (String) -> Unit) {
    ListItem(
        headlineContent = { Text(item.vaultName) },
        supportingContent = { Text(item.kind) },
        modifier = if (item.kind == "doc") Modifier.clickable { onEditDoc(item.vaultName) } else Modifier,
    )
}

private fun subtitle(s: AppSpace): String = when (s.kind) {
    SpaceKind.CHAT -> "chat · ${s.members.size + 1} member(s)"
    else -> "${s.kind.name.lowercase()} · ${s.children.size} space(s), ${s.items.size} item(s)"
}

/** MARKET — ID-gated. Verification isn't built, so it is ALWAYS closed here (no black market). */
@Composable
private fun MarketWall(modifier: Modifier) {
    Column(
        modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Filled.Lock, null, tint = MaterialTheme.colorScheme.tertiary)
        Text("Market — ID-verified personas only", style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center)
        Text("Government-ID verification isn't available yet (it arrives with the eID reader), " +
            "so no persona can be verified and the Market stays closed for now.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
    }
}

@Composable
internal fun EmptyState(title: String, detail: String, modifier: Modifier = Modifier) {
    Column(
        modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        Text(detail, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
    }
}
