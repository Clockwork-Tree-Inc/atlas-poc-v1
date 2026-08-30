package com.clockworktree.atlas

import android.app.Application
import android.util.Log
import com.clockworktree.atlas.config.AtlasFlags

/**
 * App entry point. Emits the honesty banner once at startup — same discipline as the iOS
 * build (see ios/AtlasApp/Config/AtlasFlags.swift `logHonesty()`): every stand-in stays LOUD.
 */
class AtlasApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AtlasFlags.honestyBanner.forEach { Log.i("ATLAS-HONESTY", it) }
    }
}
