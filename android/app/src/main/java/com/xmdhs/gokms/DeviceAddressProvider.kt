package com.xmdhs.gokms

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

object DeviceAddressProvider {
    fun listenAddresses(port: String): List<String> {
        val addresses = mutableListOf<String>()
        val interfaces = runCatching { NetworkInterface.getNetworkInterfaces() }.getOrNull() ?: return emptyList()

        while (interfaces.hasMoreElements()) {
            val networkInterface = interfaces.nextElement()
            if (!runCatching { networkInterface.isUp }.getOrDefault(false)) continue
            if (runCatching { networkInterface.isLoopback }.getOrDefault(false)) continue

            val inetAddresses = networkInterface.inetAddresses
            while (inetAddresses.hasMoreElements()) {
                val address = inetAddresses.nextElement()
                if (address.isLoopbackAddress || address.isLinkLocalAddress) continue

                val host = address.hostAddress?.substringBefore('%') ?: continue
                val formatted = when (address) {
                    is Inet4Address -> "$host:$port"
                    is Inet6Address -> "[$host]:$port"
                    else -> continue
                }
                addresses += formatted
            }
        }

        return addresses.distinct().sortedWith(compareBy<String> { it.startsWith("[") }.thenBy { it })
    }
}
