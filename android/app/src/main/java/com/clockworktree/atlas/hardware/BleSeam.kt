package com.clockworktree.atlas.hardware

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

/**
 * BleSeam ↔ iOS CoreBluetooth (`RingProbe` / `R10BLEClient`).
 *
 * Scans for, connects to, and streams the biological pulse from the wearable (ring). The pulse
 * is the fail-closed liveness signal; the same-hand tap handshake (phone IMU + ring IMU seeing
 * the same taps) binds the ring to THIS phone at enrolment.
 *
 * STATUS: SCAFFOLD. Requires BLUETOOTH_SCAN / BLUETOOTH_CONNECT runtime permissions (API 31+)
 * and a real GATT client. All methods below are stubs with TODOs.
 */
class BleSeam {

    data class Device(val name: String, val address: String, val rssi: Int)

    /** Scan for nearby BLE devices. TODO: BluetoothLeScanner.startScan with a ScanFilter/Settings. */
    fun scan(): Flow<List<Device>> {
        // TODO: emit live scan results; request runtime BLE permissions first.
        return flowOf(emptyList())
    }

    /** Connect + discover services. TODO: device.connectGatt(...); onServicesDiscovered. */
    fun connect(@Suppress("UNUSED_PARAMETER") address: String) {
        TODO("Wire BluetoothGatt connect + service discovery for the ring's HR/IMU characteristics")
    }

    /** Live pulse stream (bpm > 0 == present). TODO: subscribe to the HR characteristic via
     *  setCharacteristicNotification + a CCCD write. */
    fun pulse(): Flow<Int> = flowOf(0)

    /** Tap timestamps from the ring IMU, for the same-hand bind cross-check with the phone IMU
     *  (SensorSeam). TODO: parse the ring's high-rate IMU notifications. */
    fun ringTapTimes(@Suppress("UNUSED_PARAMETER") windowSeconds: Double): List<Double> = emptyList()
}
