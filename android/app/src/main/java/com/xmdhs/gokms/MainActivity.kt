package com.xmdhs.gokms

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    GoKmsApp()
                }
            }
        }
    }
}

@Composable
private fun GoKmsApp() {
    val logs by LogBuffer.lines.collectAsStateWithLifecycle()
    var selectedTab by remember { mutableIntStateOf(0) }

    Column(modifier = Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = selectedTab) {
            Tab(selected = selectedTab == 0, onClick = { selectedTab = 0 }, text = { Text("Server") })
            Tab(selected = selectedTab == 1, onClick = { selectedTab = 1 }, text = { Text("Client") })
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            if (selectedTab == 0) {
                ServerPanel()
            } else {
                ClientPanel()
            }

            Spacer(modifier = Modifier.height(16.dp))
            LogPanel(logs)
        }
    }
}

@Composable
private fun ServerPanel() {
    val context = LocalContext.current
    val settings = remember(context) { SettingsStore(context.applicationContext) }
    val initialArgs = remember(settings) { settings.loadServer() }
    val running by GoKmsServiceState.running.collectAsStateWithLifecycle()
    val address by GoKmsServiceState.address.collectAsStateWithLifecycle()

    var ip by remember { mutableStateOf(initialArgs.ip) }
    var port by remember { mutableStateOf(initialArgs.port) }
    var epid by remember { mutableStateOf(initialArgs.epid) }
    var count by remember { mutableStateOf(initialArgs.count) }
    var hwid by remember { mutableStateOf(initialArgs.hwid) }
    var addressRefreshKey by remember { mutableIntStateOf(0) }
    var notificationGranted by remember { mutableStateOf(isNotificationGranted(context)) }

    fun currentArgs(): ServerArgs {
        return ServerArgs(
            ip = ip,
            port = port,
            epid = epid,
            count = count,
            hwid = hwid,
        )
    }

    fun saveCurrentArgs() {
        settings.saveServer(currentArgs())
    }

    val deviceAddresses = remember(port, addressRefreshKey) {
        DeviceAddressProvider.listenAddresses(port.trim().ifBlank { "1688" })
    }

    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        notificationGranted = granted
        if (granted) {
            LogBuffer.append("通知权限已授予")
        } else {
            LogBuffer.append("通知权限被拒绝：Android 13+ 上前台服务通知可能无法显示")
        }
    }

    Text("服务端", style = MaterialTheme.typography.titleLarge)
    Text(if (running) "状态：运行中 $address" else "状态：已停止")
    Spacer(modifier = Modifier.height(8.dp))

    NotificationPanel(
        granted = notificationGranted,
        onRequest = {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        },
    )

    Spacer(modifier = Modifier.height(8.dp))
    ListenAddressPanel(
        bindAddress = "${ip.trim()}:${port.trim()}",
        deviceAddresses = deviceAddresses,
        onRefresh = { addressRefreshKey++ },
    )

    Spacer(modifier = Modifier.height(8.dp))
    TextFieldRow("监听 IP", ip) {
        ip = it
        saveCurrentArgs()
    }
    NumberFieldRow("端口", port) {
        port = it
        saveCurrentArgs()
    }
    TextFieldRow("ePID（可空）", epid) {
        epid = it
        saveCurrentArgs()
    }
    NumberFieldRow("客户端数量", count) {
        count = it
        saveCurrentArgs()
    }
    TextFieldRow("HWID", hwid) {
        hwid = it
        saveCurrentArgs()
    }

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(onClick = {
            hwid = "RANDOM"
            saveCurrentArgs()
        }) {
            Text("使用 RANDOM")
        }
        OutlinedButton(onClick = {
            hwid = "364F463A8863D35F"
            saveCurrentArgs()
        }) {
            Text("默认 HWID")
        }
    }

    Spacer(modifier = Modifier.height(12.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            enabled = !running,
            onClick = {
                val args = currentArgs()
                args.validate()?.let {
                    LogBuffer.append("参数错误：$it")
                    return@Button
                }
                settings.saveServer(args)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationGranted) {
                    notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    LogBuffer.append("请授予通知权限后再次启动服务")
                    return@Button
                }

                val displayAddresses = DeviceAddressProvider.listenAddresses(args.port)
                if (displayAddresses.isNotEmpty()) {
                    LogBuffer.append("设备当前可访问地址：${displayAddresses.joinToString(", ")}")
                }

                ContextCompat.startForegroundService(
                    context,
                    GoKmsForegroundService.startIntent(context, args),
                )
            },
        ) {
            Text("启动服务")
        }

        Button(
            enabled = running,
            onClick = { context.startService(GoKmsForegroundService.stopIntent(context)) },
        ) {
            Text("停止服务")
        }

        TextButton(onClick = LogBuffer::clear) {
            Text("清空日志")
        }
    }
}

@Composable
private fun ClientPanel() {
    val context = LocalContext.current
    val settings = remember(context) { SettingsStore(context.applicationContext) }
    val initialArgs = remember(settings) { settings.loadClient() }
    val scope = rememberCoroutineScope()

    var ip by remember { mutableStateOf(initialArgs.ip) }
    var port by remember { mutableStateOf(initialArgs.port) }
    var mode by remember { mutableStateOf(initialArgs.mode) }
    var cmid by remember { mutableStateOf(initialArgs.cmid) }
    var machine by remember { mutableStateOf(initialArgs.name) }
    var running by remember { mutableStateOf(false) }

    fun currentArgs(): ClientArgs {
        return ClientArgs(
            ip = ip,
            port = port,
            mode = mode,
            cmid = cmid,
            name = machine,
        )
    }

    fun saveCurrentArgs() {
        settings.saveClient(currentArgs())
    }

    Text("客户端", style = MaterialTheme.typography.titleLarge)
    Spacer(modifier = Modifier.height(8.dp))

    TextFieldRow("服务器 IP", ip) {
        ip = it
        saveCurrentArgs()
    }
    NumberFieldRow("端口", port) {
        port = it
        saveCurrentArgs()
    }
    ModeDropdown(mode) {
        mode = it
        saveCurrentArgs()
    }
    TextFieldRow("CMID（可空）", cmid) {
        cmid = it
        saveCurrentArgs()
    }
    TextFieldRow("机器名（可空）", machine) {
        machine = it
        saveCurrentArgs()
    }

    Spacer(modifier = Modifier.height(12.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            enabled = !running,
            onClick = {
                val args = currentArgs()
                args.validate()?.let {
                    LogBuffer.append("参数错误：$it")
                    return@Button
                }
                settings.saveClient(args)

                running = true
                scope.launch {
                    val exit = withContext(Dispatchers.IO) {
                        try {
                            val process = GoKmsProcessRunner.start(context, args.toCommandLine(), LogBuffer::append)
                            GoKmsProcessRunner.readOutput(process, LogBuffer::append)
                            process.waitFor()
                        } catch (t: Throwable) {
                            LogBuffer.append("运行 go-kms client 失败：${t.message}")
                            -1
                        }
                    }
                    LogBuffer.append("go-kms client 已退出，exit code=$exit")
                    running = false
                }
            },
        ) {
            Text(if (running) "运行中" else "运行客户端")
        }

        TextButton(onClick = LogBuffer::clear) {
            Text("清空日志")
        }
    }
}

@Composable
private fun NotificationPanel(granted: Boolean, onRequest: () -> Unit) {
    Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("通知栏", style = MaterialTheme.typography.titleMedium)
            Text("服务端以前台服务运行，通知栏会显示运行状态，并提供停止入口。")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Text(if (granted) "通知权限：已允许" else "通知权限：未允许")
                if (!granted) {
                    OutlinedButton(onClick = onRequest) {
                        Text("授予通知权限")
                    }
                }
            } else {
                Text("通知权限：当前 Android 版本无需运行时授权")
            }
        }
    }
}

@Composable
private fun ListenAddressPanel(bindAddress: String, deviceAddresses: List<String>, onRefresh: () -> Unit) {
    Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("监听地址", style = MaterialTheme.typography.titleMedium)
            Text("绑定参数：$bindAddress")
            if (deviceAddresses.isEmpty()) {
                Text("当前未获取到非回环设备 IP")
            } else {
                Text("设备当前可访问地址：")
                deviceAddresses.forEach { address -> Text(address) }
            }
            OutlinedButton(onClick = onRefresh) {
                Text("刷新 IP")
            }
        }
    }
}

@Composable
private fun TextFieldRow(label: String, value: String, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        singleLine = true,
    )
}

@Composable
private fun NumberFieldRow(label: String, value: String, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        singleLine = true,
    )
}

@Composable
private fun ModeDropdown(value: String, onValueChange: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text("产品模式", style = MaterialTheme.typography.labelLarge)
        Row {
            OutlinedButton(onClick = { expanded = true }) {
                Text(value)
            }
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                ProductModes.forEach { mode ->
                    DropdownMenuItem(
                        text = { Text(mode) },
                        onClick = {
                            onValueChange(mode)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun LogPanel(logs: List<String>) {
    Text("日志", style = MaterialTheme.typography.titleMedium)
    Spacer(modifier = Modifier.height(8.dp))
    Surface(
        tonalElevation = 2.dp,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            if (logs.isEmpty()) {
                Text("暂无日志")
            } else {
                logs.takeLast(200).forEach { line ->
                    Text(line, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

private fun isNotificationGranted(context: Context): Boolean {
    return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
}
