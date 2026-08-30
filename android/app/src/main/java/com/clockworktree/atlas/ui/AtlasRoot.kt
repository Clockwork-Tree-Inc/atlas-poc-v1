package com.clockworktree.atlas.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.clockworktree.atlas.session.AtlasSession

/** Primary tabs, mirroring the iOS `ContentView` TabView (Home / Spaces / Chats / Capture / Office). */
private enum class Tab(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Filled.Home),
    SPACES("Spaces", Icons.Outlined.Layers),
    CHATS("Chats", Icons.Filled.Chat),
    CAPTURE("Capture", Icons.Filled.CameraAlt),
    OFFICE("Office", Icons.Filled.Description),
}

/**
 * App root — the SwiftUI `ContentView` equivalent. One enrolment gate in front of everything;
 * once enrolled, the primary tabs lead. Market/Contacts/Email/Developer live behind an overflow
 * in the iOS build; here we scaffold the five core surfaces the task called for.
 */
@Composable
fun AtlasRoot(session: AtlasSession) {
    if (!session.enrolled) {
        EnrolmentScreen(session)
        return
    }

    var tab by remember { mutableStateOf(Tab.HOME) }

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(t.icon, contentDescription = t.label) },
                        label = { Text(t.label) },
                    )
                }
            }
        }
    ) { padding ->
        val inner = Modifier.padding(padding)
        when (tab) {
            Tab.HOME -> HomeScreen(session, inner)
            Tab.SPACES -> SpacesScreen(session, inner)
            Tab.CHATS -> ChatsListScreen(session, inner)
            Tab.CAPTURE -> CaptureScreen(session, inner)
            Tab.OFFICE -> OfficeScreen(session, inner)
        }
    }
}
