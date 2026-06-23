package com.xmdhs.gokms

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
    val lcid: String = "1033",
    val count: String = "0",
    val activation: String = "120",
    val renewal: String = "10080",
    val hwid: String = "364F463A8863D35F",
) {
    fun validate(): String? {
        if (ip.isBlank()) return "监听 IP 不能为空"
        validatePort(port)?.let { return it }
        validateNonNegativeInt(lcid, "LCID")?.let { return it }
        validateNonNegativeInt(count, "客户端数量")?.let { return it }
        validateNonNegativeInt(activation, "激活间隔")?.let { return it }
        validateNonNegativeInt(renewal, "续订间隔")?.let { return it }
        if (!hwidRegex.matches(hwid.trim())) return "HWID 必须是 RANDOM 或 16 位十六进制字符串"
        return null
    }

    fun toCommandLine(): List<String> = buildList {
        add("server")
        add("-ip")
        add(ip.trim())
        add("-port")
        add(port.trim())
        if (epid.isNotBlank()) {
            add("-epid")
            add(epid.trim())
        }
        add("-lcid")
        add(lcid.trim())
        add("-count")
        add(count.trim())
        add("-activation")
        add(activation.trim())
        add("-renewal")
        add(renewal.trim())
        add("-hwid")
        add(hwid.trim())
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
    fun validate(): String? {
        if (ip.isBlank()) return "服务器 IP 不能为空"
        validatePort(port)?.let { return it }
        if (mode !in ProductModes) return "未知产品模式：$mode"
        return null
    }

    fun toCommandLine(): List<String> = buildList {
        add("client")
        add("-ip")
        add(ip.trim())
        add("-port")
        add(port.trim())
        add("-mode")
        add(mode)
        if (cmid.isNotBlank()) {
            add("-cmid")
            add(cmid.trim())
        }
        if (name.isNotBlank()) {
            add("-name")
            add(name.trim())
        }
    }
}

private fun validatePort(value: String): String? {
    val port = value.trim().toIntOrNull() ?: return "端口必须是数字"
    return if (port in 1..65535) null else "端口范围必须是 1..65535"
}

private fun validateNonNegativeInt(value: String, label: String): String? {
    val number = value.trim().toIntOrNull() ?: return "$label 必须是数字"
    return if (number >= 0) null else "$label 不能为负数"
}
