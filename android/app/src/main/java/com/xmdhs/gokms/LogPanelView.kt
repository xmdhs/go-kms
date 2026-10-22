package com.xmdhs.gokms

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.view.doOnNextLayout
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.xmdhs.gokms.databinding.ItemLogBinding
import com.xmdhs.gokms.databinding.ViewLogPanelBinding
import java.util.Locale

/**
 * 日志面板。
 *
 * 列表是固定高度、开启嵌套滚动的 RecyclerView，嵌在 NestedScrollView 里时：
 * 列表自身还能滚就由列表处理手势，滚到边界后未消费的滑动通过
 * nested scrolling 交给外层页面，两边互不影响地各自滚动。
 */
class LogPanelView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private val binding: ViewLogPanelBinding
    private val adapter = LogAdapter()
    private var autoScrollToBottom = true

    var onClear: (() -> Unit)? = null

    init {
        orientation = VERTICAL
        binding = ViewLogPanelBinding.inflate(LayoutInflater.from(context), this)
        binding.logList.layoutManager = LinearLayoutManager(context)
        binding.logList.adapter = adapter
        binding.logList.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                if (dy != 0) autoScrollToBottom = isNearBottom()
            }
        })
        binding.clearLogButton.setOnClickListener { onClear?.invoke() }
    }

    fun submitLogs(logs: List<String>) {
        val stickToBottom = autoScrollToBottom || isNearBottom()
        val displayLogs = logs.takeLast(MaxDisplayLines)

        adapter.submit(displayLogs)
        binding.logCountText.text = context.resources.getQuantityString(
            R.plurals.log_count,
            logs.size,
            logs.size,
        )

        val empty = displayLogs.isEmpty()
        binding.emptyLogState.isVisible = empty
        binding.logList.isVisible = !empty

        if (!empty && stickToBottom) {
            autoScrollToBottom = true
            val lastIndex = displayLogs.lastIndex
            binding.logList.post {
                binding.logList.scrollToPosition(lastIndex)
                binding.logList.doOnNextLayout {
                    // scrollToPosition 会把目标项对齐到顶部，再向下滚一段让列表贴底。
                    binding.logList.scrollBy(0, binding.logList.height)
                }
            }
        }
    }

    private fun isNearBottom(): Boolean {
        val layoutManager = binding.logList.layoutManager as? LinearLayoutManager ?: return true
        if (adapter.itemCount == 0) return true
        return layoutManager.findLastVisibleItemPosition() >= adapter.itemCount - 2
    }

    private class LogAdapter : RecyclerView.Adapter<LogAdapter.Holder>() {
        private var lines: List<String> = emptyList()

        fun submit(newLines: List<String>) {
            val oldLines = lines
            if (oldLines == newLines) return
            lines = newLines
            notifyIncremental(oldLines, newLines)
        }

        /**
         * 日志只追加，且列表按 [MaxDisplayLines] 截断，
         * 因此新列表要么是旧列表的追加，要么整体刷新。
         */
        private fun notifyIncremental(oldLines: List<String>, newLines: List<String>) {
            if (newLines.size >= oldLines.size && newLines.subList(0, oldLines.size) == oldLines) {
                notifyItemRangeInserted(oldLines.size, newLines.size - oldLines.size)
            } else {
                notifyDataSetChanged()
            }
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): Holder {
            return Holder(
                ItemLogBinding.inflate(LayoutInflater.from(parent.context), parent, false),
            )
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            holder.bind(lines[position])
        }

        override fun getItemCount(): Int = lines.size

        class Holder(private val binding: ItemLogBinding) : RecyclerView.ViewHolder(binding.root) {

            init {
                // 日志行不能设 textIsSelectable：可选中文本会把拖动当成选词，列表就滚不动了。
                // 改为长按复制整行，保留迁移前“可复制日志”的能力。
                binding.root.setOnLongClickListener {
                    val context = binding.root.context
                    val clipboard =
                        context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(
                        ClipData.newPlainText(
                            context.getString(R.string.log_title),
                            binding.root.text,
                        ),
                    )
                    Toast.makeText(context, R.string.log_copied, Toast.LENGTH_SHORT).show()
                    true
                }
            }

            fun bind(line: String) {
                val context = binding.root.context
                val color = logLineColor(context, line)
                binding.root.text = line
                binding.root.setTextColor(color)
                // 行底色用该行颜色的 8% 叠在卡片背景上，跟随夜间与动态配色。
                binding.root.backgroundTintList = ColorStateList.valueOf(
                    ColorUtils.setAlphaComponent(color, LineBackgroundAlpha),
                )
            }
        }
    }

    private companion object {
        const val MaxDisplayLines = 200
    }
}

/** 0x14 ≈ 8% 透明度，与旧版 Compose 实现的 0.08f 一致。 */
private const val LineBackgroundAlpha = 0x14

private fun logLineColor(context: Context, line: String): Int {
    // 固定用 ROOT locale，避免土耳其语等环境下大小写折叠改变关键字。
    val lower = line.lowercase(Locale.ROOT)
    val errorColor = themeColor(
        context,
        com.google.android.material.R.attr.colorError,
        R.color.log_error,
    )
    return when {
        // slog 输出带 level= 字段，先按级别判断，避免把 "Error reading ..." 这类 WARN 当成错误。
        "level=error" in lower -> errorColor
        "level=warn" in lower -> ContextCompat.getColor(context, R.color.log_warn)
        "level=debug" in lower -> ContextCompat.getColor(context, R.color.log_debug)
        "error" in lower || "failed" in lower || "失败" in line -> errorColor
        "warn" in lower || "警告" in line -> ContextCompat.getColor(context, R.color.log_warn)
        "debug" in lower -> ContextCompat.getColor(context, R.color.log_debug)
        "started" in lower || "已启动" in line -> ContextCompat.getColor(context, R.color.log_success)
        "stopped" in lower || "已停止" in line || "已退出" in line ||
            "已强制终止" in line || "已请求终止" in line ->
            ContextCompat.getColor(context, R.color.log_stopped)

        else -> themeColor(
            context,
            com.google.android.material.R.attr.colorOnSurface,
            R.color.log_default,
        )
    }
}

/** 优先取主题色，取不到时退回固定色（例如宿主 Context 的 Theme 不含 Material 属性）。 */
private fun themeColor(context: Context, attr: Int, fallbackRes: Int): Int {
    val color = MaterialColors.getColor(context, attr, 0)
    return if (color != 0) color else ContextCompat.getColor(context, fallbackRes)
}
