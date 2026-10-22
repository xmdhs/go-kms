package com.xmdhs.gokms

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 客户端调用是阻塞的 JNI 调用，放在进程级作用域里执行，
 * 这样切换 Tab 或旋转屏幕不会中断运行中的客户端。
 */
object ClientRunner {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    fun run(context: Context, args: ClientArgs) {
        if (_running.value) return
        val port = args.port.trim().toIntOrNull() ?: return
        val appContext = context.applicationContext

        _running.value = true
        scope.launch {
            val output = withContext(Dispatchers.IO) {
                try {
                    GoKmsNative.runClient(
                        args.ip.trim(),
                        port,
                        args.mode,
                        args.cmid.trim(),
                        args.name.trim(),
                    )
                } catch (t: Throwable) {
                    val reason = t.message.orEmpty()
                    LogBuffer.appendClient(
                        appContext.getString(R.string.log_client_run_failed, reason),
                    )
                    null
                }
            }
            output
                ?.lineSequence()
                ?.filter { it.isNotBlank() }
                ?.forEach(LogBuffer::appendClient)

            _running.value = false
        }
    }
}
