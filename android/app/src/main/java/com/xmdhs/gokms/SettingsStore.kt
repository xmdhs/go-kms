package com.xmdhs.gokms

import android.content.Context

class SettingsStore(context: Context) {
    private val preferences = context.getSharedPreferences("go_kms_settings", Context.MODE_PRIVATE)

    fun loadServer(): ServerArgs {
        return ServerArgs(
            ip = preferences.getString(ServerIp, "0.0.0.0") ?: "0.0.0.0",
            port = preferences.getString(ServerPort, "1688") ?: "1688",
            epid = preferences.getString(ServerEpid, "") ?: "",
            count = preferences.getString(ServerCount, "0") ?: "0",
            hwid = preferences.getString(ServerHwid, "364F463A8863D35F") ?: "364F463A8863D35F",
        )
    }

    fun saveServer(args: ServerArgs) {
        preferences.edit()
            .putString(ServerIp, args.ip)
            .putString(ServerPort, args.port)
            .putString(ServerEpid, args.epid)
            .putString(ServerCount, args.count)
            .putString(ServerHwid, args.hwid)
            .apply()
    }

    fun loadClient(): ClientArgs {
        return ClientArgs(
            ip = preferences.getString(ClientIp, "127.0.0.1") ?: "127.0.0.1",
            port = preferences.getString(ClientPort, "1688") ?: "1688",
            mode = preferences.getString(ClientMode, "Windows8.1") ?: "Windows8.1",
            cmid = preferences.getString(ClientCmid, "") ?: "",
            name = preferences.getString(ClientName, "") ?: "",
        )
    }

    fun saveClient(args: ClientArgs) {
        preferences.edit()
            .putString(ClientIp, args.ip)
            .putString(ClientPort, args.port)
            .putString(ClientMode, args.mode)
            .putString(ClientCmid, args.cmid)
            .putString(ClientName, args.name)
            .apply()
    }

    private companion object {
        const val ServerIp = "server_ip"
        const val ServerPort = "server_port"
        const val ServerEpid = "server_epid"
        const val ServerCount = "server_count"
        const val ServerHwid = "server_hwid"

        const val ClientIp = "client_ip"
        const val ClientPort = "client_port"
        const val ClientMode = "client_mode"
        const val ClientCmid = "client_cmid"
        const val ClientName = "client_name"
    }
}
