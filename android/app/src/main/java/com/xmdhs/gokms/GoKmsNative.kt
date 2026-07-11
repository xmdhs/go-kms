package com.xmdhs.gokms

object GoKmsNative {
    init {
        System.loadLibrary("go_kms")
    }

    external fun startServer(
        ip: String,
        port: Int,
        epid: String,
        count: Int,
        hwid: String,
    ): Long

    external fun stopServer(handle: Long)

    external fun runClient(
        ip: String,
        port: Int,
        mode: String,
        cmid: String,
        name: String,
    ): String

    external fun drainServerLogs(): String
}
