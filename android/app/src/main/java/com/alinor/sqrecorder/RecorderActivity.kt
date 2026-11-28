package com.alinor.sqrecorder

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Accessible native entry point; recording is always user-initiated. */
public class RecorderActivity : Activity() {
 private lateinit var status: TextView
 override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  status = TextView(this).apply {
   text = "SQRecorder • Offline encrypted audio capture\nSQVE v2 · WAV payload · 48 kHz mono PCM"
   textSize = 18f; contentDescription = "Recorder status and capture format"
   setPadding(32, 32, 32, 24)
  }
  val start = Button(this).apply { text = "Start recording"; setOnClickListener { requestCapturePermissionAndStart() } }
  val stop = Button(this).apply {
   text = "Stop and finalize"
   setOnClickListener {
    startService(Intent(this@RecorderActivity, CaptureForegroundService::class.java).setAction(CaptureForegroundService.ACTION_STOP))
    status.text = "Stop requested · finalizing encrypted SQVE"
   }
  }
  setContentView(LinearLayout(this).apply {
   orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24)
   addView(status); addView(start); addView(stop)
  })
 }
 private fun requestCapturePermissionAndStart() {
  if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
   requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO), REQUEST_MIC); return
  }
  startCapture()
 }
 private fun startCapture() {
  if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
   status.text = "Encrypted capture requires Android 6/API 23 or newer. Plaintext fallback is disabled."
   return
  }
  val intent = Intent(this, CaptureForegroundService::class.java).setAction(CaptureForegroundService.ACTION_START)
  try {
   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
   status.text = "Recording · foreground notification active"
  } catch (_: SecurityException) { status.text = "Capture blocked by permission/foreground-service policy" }
 }
 override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
  super.onRequestPermissionsResult(requestCode, permissions, grantResults)
  if (requestCode == REQUEST_MIC && grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) startCapture()
  else if (requestCode == REQUEST_MIC) status.text = "Microphone permission denied · not recording"
 }
 private companion object { const val REQUEST_MIC = 410 }
}
