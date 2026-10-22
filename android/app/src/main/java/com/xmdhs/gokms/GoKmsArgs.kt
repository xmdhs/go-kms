package com.xmdhs.gokms

import android.content.Context

private val hwidRegex = Regex("(?i)^(RANDOM|0x[0-9a-f]{16}|[0-9a-f]{16})$")

val ProductModes = listOf(
    "WindowsVista",
    "Windows7",
    "Windows8",
    "Windows8.1",
    "Windows10",
    "Office2010",
    "Office2013",
    "Office2016",
    "Office2019",
)

data class ServerArgs(
    val ip: String = "0.0.0.0",
    val port: String = "1688",
    val epid: String = "",
    val count: String = "0",
    val hwid: String = "364F463A8863D35F",
) {
    /** 返回本地化的错误描述，参数合法时返回 null。 */
    fun validate(context: Context): String? {
        if (ip.isBlank()) return context.getString(R.string.error_server_ip_blank)
        validatePort(context, port)?.let { return it }
        validateNonNegativeInt(
            context,
            count,
            R.string.error_count_not_number,
            R.string.error_count_negative,
        )?.let { return it }
        if (!hwidRegex.matches(hwid.trim())) return context.getString(R.string.error_hwid_invalid)
        return null
    }

    fun displayAddress(): String = "${ip.trim()}:${port.trim()}"
}

data class ClientArgs(
    val ip: String = "127.0.0.1",
    val port: String = "1688",
    val mode: String = "Windows8.1",
    val cmid: String = "",
    val name: String = "",
) {
    /** 返回本地化的错误描述，参数合法时返回 null。 */
    fun validate(context: Context): String? {
        if (ip.isBlank()) return context.getString(R.string.error_client_ip_blank)
        validatePort(context, port)?.let { return it }
        if (mode !in ProductModes) {
            return context.getString(R.string.error_unknown_mode, mode)
        }
        return null
    }
}

private fun validatePort(context: Context, value: String): String? {
    val port = value.trim().toIntOrNull() ?: return context.getString(R.string.error_port_not_number)
    return if (port in 1..65535) null else context.getString(R.string.error_port_range)
}

private fun validateNonNegativeInt(
    context: Context,
    value: String,
    notNumberRes: Int,
    negativeRes: Int,
): String? {
    val number = value.trim().toIntOrNull() ?: return context.getString(notNumberRes)
    return if (number >= 0) null else context.getString(negativeRes)
}
