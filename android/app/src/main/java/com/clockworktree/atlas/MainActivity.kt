package com.clockworktree.atlas

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.viewmodel.compose.viewModel
import com.clockworktree.atlas.session.AtlasSession
import com.clockworktree.atlas.ui.AtlasRoot
import com.clockworktree.atlas.ui.theme.AtlasTheme

/**
 * Single-activity host. The whole app is Compose; `AtlasRoot` is the SwiftUI `ContentView`
 * equivalent — one enrolment gate in front of everything, then the primary tabs.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AtlasTheme {
                val session: AtlasSession = viewModel()
                AtlasRoot(session)
            }
        }
    }
}
