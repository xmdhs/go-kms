package com.xmdhs.gokms

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class GoKmsForegroundService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var process: Process? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopServer()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_START -> startServer(GoKmsForegroundService.serverArgsFromIntent(intent))
            else -> LogBuffer.appendServer("未知服务命令：${intent?.action}")
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopServer()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startServer(args: ServerArgs) {
        process?.let { existing ->
            if (GoKmsProcessRunner.isAlive(existing)) {
                LogBuffer.appendServer("go-kms server 已在运行：${args.displayAddress()}")
                return
            }
        }

        val address = args.displayAddress()
        createNotificationChannel()
        startForegroundCompat(address)

        try {
            val started = GoKmsProcessRunner.start(applicationContext, args.toCommandLine(), LogBuffer::appendServer)
            process = started
            GoKmsServiceState.setRunning(true, address)
            LogBuffer.appendServer("已启动 go-kms server：$address")

            serviceScope.launch {
                try {
                    GoKmsProcessRunner.readOutput(started, LogBuffer::appendServer)
                    val exit = started.waitFor()
                    LogBuffer.appendServer("go-kms server 已退出，exit code=$exit")
                } catch (t: Throwable) {
                    LogBuffer.appendServer("读取 go-kms server 输出失败：${t.message}")
                } finally {
                    if (process === started) {
                        process = null
                        GoKmsServiceState.setRunning(false)
                        stopSelf()
                    }
                }
            }
        } catch (t: Throwable) {
            LogBuffer.appendServer("启动 go-kms server 失败：${t.message}")
            GoKmsServiceState.setRunning(false)
            stopSelf()
        }
    }

    private fun stopServer() {
        val running = process ?: return
        process = null
        GoKmsProcessRunner.stop(running, LogBuffer::appendServer)
        GoKmsServiceState.setRunning(false)
        LogBuffer.appendServer("已停止 go-kms server")
    }

    private fun startForegroundCompat(address: String) {
        val notification = buildNotification(address)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NotificationId,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NotificationId, notification)
        }
    }

    private fun buildNotification(address: String): Notification {
        val stopIntent = stopIntent(this)
        val stopPendingIntent = PendingIntent.getService(
            this,
            0,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val openIntent = Intent(this, MainActivity::class.java)
        val openPendingIntent = PendingIntent.getActivity(
            this,
            1,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, ChannelId)
            .setSmallIcon(R.drawable.ic_notification)
            .setColor(ContextCompat.getColor(this, R.color.notification_icon_color))
            .setContentTitle("go-kms server 正在运行")
            .setContentText(address)
            .setContentIntent(openPendingIntent)
            .setOngoing(true)
            .addAction(R.drawable.ic_notification, "停止", stopPendingIntent)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            ChannelId,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    companion object {
        const val ACTION_START = "com.xmdhs.gokms.action.START"
        const val ACTION_STOP = "com.xmdhs.gokms.action.STOP"

        private const val ChannelId = "go_kms_server"
        private const val NotificationId = 1688

        private const val EXTRA_IP = "ip"
        private const val EXTRA_PORT = "port"
        private const val EXTRA_EPID = "epid"
        private const val EXTRA_COUNT = "count"
        private const val EXTRA_HWID = "hwid"

        fun startIntent(context: Context, args: ServerArgs): Intent {
            return Intent(context, GoKmsForegroundService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_IP, args.ip)
                putExtra(EXTRA_PORT, args.port)
                putExtra(EXTRA_EPID, args.epid)
                putExtra(EXTRA_COUNT, args.count)
                putExtra(EXTRA_HWID, args.hwid)
            }
        }

        fun stopIntent(context: Context): Intent {
            return Intent(context, GoKmsForegroundService::class.java).apply {
                action = ACTION_STOP
            }
        }

        fun serverArgsFromIntent(intent: Intent): ServerArgs {
            return ServerArgs(
                ip = intent.getStringExtra(EXTRA_IP) ?: "0.0.0.0",
                port = intent.getStringExtra(EXTRA_PORT) ?: "1688",
                epid = intent.getStringExtra(EXTRA_EPID) ?: "",
                count = intent.getStringExtra(EXTRA_COUNT) ?: "0",
                hwid = intent.getStringExtra(EXTRA_HWID) ?: "364F463A8863D35F",
            )
        }
    }
}
