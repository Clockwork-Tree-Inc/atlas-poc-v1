package com.clockworktree.atlas.hardware

import android.content.Context
import android.hardware.SensorManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

/**
 * SensorSeam ↔ iOS CoreMotion (`AmbientSensorSource`).
 *
 * The phone's fused ambient sensors (accelerometer / gyroscope / magnetometer / barometer).
 *
 * TWO distinct roles — kept distinct on purpose (see MEMORY: ambient-entropy-role):
 *   1. ENGINE ENTROPY: the ambient stream HARVESTS sensor entropy to run the timing/gating
 *      engine. It is NOT presence detection and is never folded into any key.
 *   2. ANTI-BOT PROOF: an exact-count shake challenge — real attested motion a bot/emulator
 *      can't fake (mirror of iOS `ShakeChallengeStep`).
 *
 * STATUS: SCAFFOLD. Registration is stubbed; wiring uses SensorManager.registerListener.
 */
class SensorSeam(private val context: Context) {

    private val sensorManager: SensorManager? =
        context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager

    val available: Boolean
        get() = sensorManager?.getDefaultSensor(android.hardware.Sensor.TYPE_ACCELEROMETER) != null

    /** Ambient entropy/timing stream. TODO: registerListener on accel/gyro/mag/baro; fold the
     *  quantised samples into the engine's timing (NOT into any key). */
    fun ambientStream(): Flow<FloatArray> = flowOf(floatArrayOf())

    /**
     * Anti-bot human proof: count high-impulse shakes within a window, target an EXACT random N.
     *
     * TODO: registerListener(TYPE_ACCELEROMETER, SENSOR_DELAY_GAME); threshold ~0.9g with a
     *       ~0.25s refractory so each shake counts once; return the count for exact comparison.
     */
    fun shakeChallenge(
        @Suppress("UNUSED_PARAMETER") windowSeconds: Double,
        @Suppress("UNUSED_PARAMETER") onCount: (Int) -> Unit,
    ) {
        TODO("Wire SensorManager accelerometer listener; exact-count shake detection")
    }

    /** Phone tap timestamps for the same-hand ring bind (cross-check with BleSeam.ringTapTimes). */
    fun phoneTapTimes(@Suppress("UNUSED_PARAMETER") windowSeconds: Double): List<Double> = emptyList()
}
