package com.xmdhs.gokms

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.Process

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            GoKmsTheme {
                Surface(
                    color = MaterialTheme.colorScheme.background,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    GoKmsApp()
                }
            }
        }
    }
}

@Composable
private fun GoKmsTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> darkColorScheme()
        else -> lightColorScheme()
    }
    val view = LocalView.current

    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.background.toArgb()
            window.navigationBarColor = colorScheme.background.toArgb()
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = !darkTheme
            controller.isAppearanceLightNavigationBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content,
    )
}

@Composable
private fun GoKmsApp() {
    val serverLogs by LogBuffer.serverLines.collectAsStateWithLifecycle()
    val clientLogs by LogBuffer.clientLines.collectAsStateWithLifecycle()
    val pagerState = rememberPagerState(pageCount = { 2 })
    val scope = rememberCoroutineScope()
    var blockPageVerticalScroll by remember { mutableStateOf(false) }
    val onLogInteractionChange: (Boolean) -> Unit = remember {
        { active -> blockPageVerticalScroll = active }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .systemBarsPadding(),
    ) {
        TabRow(selectedTabIndex = pagerState.currentPage) {
            Tab(
                selected = pagerState.currentPage == 0,
                onClick = {
                    scope.launch { pagerState.animateScrollToPage(0) }
                },
                text = { Text("服务端") },
            )
            Tab(
                selected = pagerState.currentPage == 1,
                onClick = {
                    scope.launch { pagerState.animateScrollToPage(1) }
                },
                text = { Text("客户端") },
            )
        }

        HorizontalPager(
            state = pagerState,
            modifier = Modifier.weight(1f),
        ) { page ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(
                        state = rememberScrollState(),
                        enabled = !blockPageVerticalScroll,
                    )
                    .padding(16.dp),
            ) {
                when (page) {
                    0 -> ServerPanel(
                        logs = serverLogs,
                        onLogInteractionChange = onLogInteractionChange,
                    )
                    1 -> ClientPanel(
                        logs = clientLogs,
                        onLogInteractionChange = onLogInteractionChange,
                    )
                }
            }
        }
    }
}

@Composable
private fun ServerPanel(
    logs: List<String>,
    onLogInteractionChange: (Boolean) -> Unit,
) {
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
            LogBuffer.appendServer("通知权限已授予")
        } else {
            LogBuffer.appendServer("通知权限被拒绝：Android 13+ 上前台服务通知可能无法显示")
        }
    }

    // Header
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.Dns,
            contentDescription = null,
            tint = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(28.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text(
            "服务端",
            style = MaterialTheme.typography.titleLarge,
        )
    }
    Text(
        if (running) "状态：运行中 $address" else "状态：已停止",
        style = MaterialTheme.typography.bodyMedium,
        color = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(modifier = Modifier.height(12.dp))

    // Listen Address Panel
    ListenAddressPanel(
        bindAddress = "${ip.trim()}:${port.trim()}",
        deviceAddresses = deviceAddresses,
        onRefresh = { addressRefreshKey++ },
    )

    Spacer(modifier = Modifier.height(12.dp))

    // Configuration Card
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("服务配置", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

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

            Spacer(Modifier.height(4.dp))
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
        }
    }

    Spacer(modifier = Modifier.height(12.dp))

    // Action Buttons
    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Button(
            enabled = !running,
            onClick = {
                val args = currentArgs()
                args.validate()?.let {
                    LogBuffer.appendServer("参数错误：$it")
                    return@Button
                }
                settings.saveServer(args)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationGranted) {
                    notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    LogBuffer.appendServer("请授予通知权限后再次启动服务")
                    return@Button
                }

                val displayAddresses = DeviceAddressProvider.listenAddresses(args.port)
                if (displayAddresses.isNotEmpty()) {
                    LogBuffer.appendServer("设备当前可访问地址：${displayAddresses.joinToString(", ")}")
                }

                ContextCompat.startForegroundService(
                    context,
                    GoKmsForegroundService.startIntent(context, args),
                )
            },
        ) {
            Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text("启动服务")
        }

        Button(
            enabled = running,
            onClick = { context.startService(GoKmsForegroundService.stopIntent(context)) },
        ) {
            Icon(Icons.Filled.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text("停止服务")
        }
    }

    Spacer(modifier = Modifier.height(16.dp))
    HorizontalDivider()
    Spacer(modifier = Modifier.height(8.dp))

    // Log Panel - embedded in each tab
    LogPanel(
        logs = logs,
        onClear = { LogBuffer.clearServer() },
        onInteractionChange = onLogInteractionChange,
    )
}

@Composable
private fun ClientPanel(
    logs: List<String>,
    onLogInteractionChange: (Boolean) -> Unit,
) {
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
    val clientProcess = remember { mutableStateOf<Process?>(null) }

    // 当 ClientPanel 离开组合时，自动清理客户端进程，防止僵尸进程
    DisposableEffect(Unit) {
        onDispose {
            clientProcess.value?.let { proc ->
                if (GoKmsProcessRunner.isAlive(proc)) {
                    GoKmsProcessRunner.stop(proc, LogBuffer::appendClient)
                }
            }
        }
    }

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

    // Header
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.Computer,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(28.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text("客户端", style = MaterialTheme.typography.titleLarge)
    }
    Spacer(modifier = Modifier.height(12.dp))

    // Configuration Card
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("客户端配置", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))

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
        }
    }

    Spacer(modifier = Modifier.height(12.dp))

    // Action Buttons
    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Button(
            enabled = !running,
            onClick = {
                val args = currentArgs()
                args.validate()?.let {
                    LogBuffer.appendClient("参数错误：$it")
                    return@Button
                }
                settings.saveClient(args)

                running = true
                scope.launch {
                    val process = withContext(Dispatchers.IO) {
                        try {
                            GoKmsProcessRunner.start(context, args.toCommandLine(), LogBuffer::appendClient)
                        } catch (t: Throwable) {
                            LogBuffer.appendClient("运行 go-kms client 失败：${t.message}")
                            null
                        }
                    }
                    if (process == null) {
                        running = false
                        return@launch
                    }
                    clientProcess.value = process
                    GoKmsProcessRunner.readOutput(process, LogBuffer::appendClient)
                    val exit = process.waitFor()
                    clientProcess.value = null
                    LogBuffer.appendClient("go-kms client 已退出，exit code=$exit")
                    running = false
                }
            },
        ) {
            Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text(if (running) "运行中" else "运行客户端")
        }
    }

    Spacer(modifier = Modifier.height(16.dp))
    HorizontalDivider()
    Spacer(modifier = Modifier.height(8.dp))

    // Log Panel - embedded in each tab
    LogPanel(
        logs = logs,
        onClear = { LogBuffer.clearClient() },
        onInteractionChange = onLogInteractionChange,
    )
}

@Composable
private fun ListenAddressPanel(bindAddress: String, deviceAddresses: List<String>, onRefresh: () -> Unit) {
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Filled.Router,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text("监听地址", style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(8.dp))
            SelectionContainer {
                Text(
                    "绑定参数：$bindAddress",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(4.dp))
            if (deviceAddresses.isEmpty()) {
                Text(
                    "当前未获取到非回环设备 IP",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    "设备当前可访问地址：",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                SelectionContainer {
                    Column {
                        deviceAddresses.forEach { address ->
                            Text(
                                address,
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                    }
                }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onRefresh) {
                Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(4.dp))
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModeDropdown(value: String, onValueChange: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text("产品模式", style = MaterialTheme.typography.labelLarge)
        Spacer(Modifier.height(4.dp))
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
        ) {
            OutlinedTextField(
                value = value,
                onValueChange = {},
                readOnly = true,
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(),
                singleLine = true,
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
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
private fun LogPanel(
    logs: List<String>,
    onClear: () -> Unit,
    onInteractionChange: (Boolean) -> Unit,
) {
    val isDark = isSystemInDarkTheme()

    DisposableEffect(Unit) {
        onDispose { onInteractionChange(false) }
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("日志", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${logs.size} 条",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = onClear) {
                Icon(
                    Icons.Filled.DeleteSweep,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(4.dp))
                Text("清空")
            }
        }
    }
    Spacer(modifier = Modifier.height(8.dp))

    Surface(
        tonalElevation = 1.dp,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (logs.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 120.dp)
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Filled.Article,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                        modifier = Modifier.size(36.dp),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "暂无日志",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                    )
                }
            }
        } else {
            val listState = rememberLazyListState()
            val displayLogs = remember(logs) { logs.takeLast(200) }
            val displayStartIndex = logs.size - displayLogs.size
            var autoScrollToBottom by remember { mutableStateOf(true) }
            var isTouchingLog by remember { mutableStateOf(false) }
            val isNearBottom by remember {
                derivedStateOf {
                    val layoutInfo = listState.layoutInfo
                    val total = layoutInfo.totalItemsCount
                    if (total == 0) {
                        true
                    } else {
                        val lastVisible = layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
                        lastVisible >= total - 2
                    }
                }
            }
            val blockParentVerticalScroll = remember(listState) {
                object : NestedScrollConnection {
                    private fun canScrollLog(deltaY: Float): Boolean {
                        return when {
                            deltaY < 0f -> listState.canScrollForward
                            deltaY > 0f -> listState.canScrollBackward
                            else -> false
                        }
                    }

                    override fun onPreScroll(
                        available: Offset,
                        source: NestedScrollSource,
                    ): Offset {
                        if (source != NestedScrollSource.UserInput) return Offset.Zero
                        return if (!canScrollLog(available.y)) Offset(0f, available.y) else Offset.Zero
                    }

                    override fun onPostScroll(
                        consumed: Offset,
                        available: Offset,
                        source: NestedScrollSource,
                    ): Offset {
                        return if (source == NestedScrollSource.UserInput) Offset(0f, available.y) else Offset.Zero
                    }

                    override suspend fun onPreFling(available: Velocity): Velocity {
                        return if (!canScrollLog(available.y)) Velocity(0f, available.y) else Velocity.Zero
                    }

                    override suspend fun onPostFling(
                        consumed: Velocity,
                        available: Velocity,
                    ): Velocity {
                        return available.copy(x = 0f)
                    }
                }
            }

            LaunchedEffect(isTouchingLog) {
                if (isTouchingLog) {
                    onInteractionChange(true)
                } else {
                    delay(300)
                    onInteractionChange(false)
                }
            }

            LaunchedEffect(isNearBottom, listState.isScrollInProgress) {
                if (isNearBottom) {
                    autoScrollToBottom = true
                } else if (listState.isScrollInProgress) {
                    autoScrollToBottom = false
                }
            }

            LaunchedEffect(logs.size) {
                if (displayLogs.isNotEmpty() && autoScrollToBottom) {
                    listState.animateScrollToItem(displayLogs.lastIndex)
                }
            }

            SelectionContainer {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 350.dp)
                        .pointerInput(Unit) {
                            awaitEachGesture {
                                try {
                                    awaitFirstDown(requireUnconsumed = false)
                                    isTouchingLog = true
                                    do {
                                        val event = awaitPointerEvent()
                                    } while (event.changes.any { it.pressed })
                                } finally {
                                    isTouchingLog = false
                                }
                            }
                        }
                        .nestedScroll(blockParentVerticalScroll),
                ) {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxWidth(),
                        contentPadding = PaddingValues(12.dp),
                    ) {
                        itemsIndexed(
                            items = displayLogs,
                            key = { index, line -> "${displayStartIndex + index}-$line" },
                        ) { _, line ->
                            val logColor = logLineColor(line, isDark)
                            Surface(
                                color = logColor.copy(alpha = 0.08f),
                                shape = RoundedCornerShape(6.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 2.dp),
                            ) {
                                Text(
                                    text = line,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = logColor,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun logLineColor(line: String, isDark: Boolean): Color {
    val lower = line.lowercase()
    return when {
        "error" in lower || "失败" in lower -> MaterialTheme.colorScheme.error
        "warn" in lower -> if (isDark) Color(0xFFFFB74D) else Color(0xFFE65100)
        "已启动" in line || "started" in lower -> Color(0xFF2E7D32)
        "已停止" in line || "已退出" in line || "已强制终止" in line || "已请求终止" in line ->
            if (isDark) Color(0xFF90CAF9) else Color(0xFF1565C0)
        "debug" in lower -> if (isDark) Color(0xFFA5D6A7) else Color(0xFF558B2F)
        else -> MaterialTheme.colorScheme.onSurface
    }
}

private fun isNotificationGranted(context: Context): Boolean {
    return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
}