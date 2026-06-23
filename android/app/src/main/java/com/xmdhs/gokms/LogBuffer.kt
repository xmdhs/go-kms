package com.xmdhs.gokms

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

object LogBuffer {
    private const val MaxLines = 1_000

    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines.asStateFlow()

    fun append(line: String) {
        _lines.update { current ->
            (current + line).takeLast(MaxLines)
        }
    }

    fun clear() {
        _lines.value = emptyList()
    }
}

object GoKmsServiceState {
    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _address = MutableStateFlow("")
    val address: StateFlow<String> = _address.asStateFlow()

    fun setRunning(running: Boolean, address: String = "") {
        _running.value = running
        _address.value = if (running) address else ""
    }
}
