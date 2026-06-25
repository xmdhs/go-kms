package com.xmdhs.gokms

import android.content.Context
import android.os.Build
import java.io.File

object GoKmsProcessRunner {
    fun binaryFile(context: Context): File {
        return File(context.applicationInfo.nativeLibraryDir, "libgo_kms.so")
    }

    fun start(
        context: Context,
        arguments: List<String>,
        onLine: (String) -> Unit,
    ): Process {
        val binary = binaryFile(context)
        if (!binary.exists()) {
            error("未找到 go-kms 二进制：${binary.absolutePath}")
        }
        if (!binary.canExecute()) {
            error("go-kms 二进制不可执行：${binary.absolutePath}")
        }

        onLine("$ ${binary.absolutePath} ${arguments.joinToString(" ")}")
        return ProcessBuilder(listOf(binary.absolutePath) + arguments)
            .directory(context.filesDir)
            .redirectErrorStream(true)
            .start()
    }

    fun readOutput(process: Process, onLine: (String) -> Unit) {
        process.inputStream.bufferedReader().useLines { lines ->
            lines.forEach { line -> onLine(line) }
        }
    }

    fun isAlive(process: Process): Boolean {
        return try {
            process.exitValue()
            false
        } catch (_: IllegalThreadStateException) {
            true
        }
    }

    fun exitCode(process: Process): Int? {
        return try {
            process.exitValue()
        } catch (_: IllegalThreadStateException) {
            null
        }
    }

    fun stop(process: Process, onLine: (String) -> Unit = {}) {
        if (!isAlive(process)) return

        process.destroy()
        repeat(20) {
            if (!isAlive(process)) return
            Thread.sleep(50)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            process.destroyForcibly()
            onLine("已强制终止 go-kms 进程")
        } else {
            process.destroy()
            onLine("已请求终止 go-kms 进程")
        }
        closeStreams(process)
    }

    /** 确保进程的 I/O 流被显式关闭，防止文件描述符泄漏 */
    private fun closeStreams(process: Process) {
        try {
            process.inputStream.close()
        } catch (_: Exception) { }
        try {
            process.outputStream.close()
        } catch (_: Exception) { }
        try {
            process.errorStream.close()
        } catch (_: Exception) { }
    }
}
