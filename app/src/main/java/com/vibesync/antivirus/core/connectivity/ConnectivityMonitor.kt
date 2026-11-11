package com.vibesync.antivirus.core.connectivity
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Tracks validated internet availability only; it does not send or inspect application data. */
class ConnectivityMonitor(context: Context) {
 private val manager = context.getSystemService(ConnectivityManager::class.java)
 private val mutableOnline = MutableStateFlow(isValidated())
 val online: StateFlow<Boolean> = mutableOnline.asStateFlow()
 private val callback = object : ConnectivityManager.NetworkCallback() {
  override fun onAvailable(network: Network) { mutableOnline.value = isValidated() }
  override fun onLost(network: Network) { mutableOnline.value = isValidated() }
  override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
   mutableOnline.value = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
  }
 }
 fun start() {
  runCatching { manager.registerDefaultNetworkCallback(callback) }
  mutableOnline.value = isValidated()
 }
 fun stop() { runCatching { manager.unregisterNetworkCallback(callback) } }
 private fun isValidated(): Boolean {
  val network = manager.activeNetwork ?: return false
  val caps = manager.getNetworkCapabilities(network) ?: return false
  return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
   caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
 }
}
