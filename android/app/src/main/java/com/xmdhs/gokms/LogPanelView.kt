package com.xmdhs.gokms

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.core.content.ContextCompat
import androidx.core.view.doOnNextLayout
import androidx.core.view.isVisible
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.xmdhs.gokms.databinding.ItemLogBinding
import com.xmdhs.gokms.databinding.ViewLogPanelBinding

class LogPanelView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private val binding = ViewLogPanelBinding.inflate(LayoutInflater.from(context), this, true)
    private val adapter = LogAdapter()
    private var autoScrollToBottom = true

    var onClear: (() -> Unit)? = null

    init {
        orientation = VERTICAL
        binding.logList.layoutManager = LinearLayoutManager(context)
        binding.logList.adapter = adapter
        binding.logList.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                if (dy != 0) autoScrollToBottom = isNearBottom()
            }
        })
        // 日志列表嵌在 NestedScrollView 中：只在日志还能朝拖动方向滚动时
        // 才阻止父容器拦截手势，否则把滑动还给外层页面。
        var lastTouchY = 0f
        binding.logList.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN -> lastTouchY = event.y
                MotionEvent.ACTION_MOVE -> {
                    val dy = event.y - lastTouchY
                    val canScroll = if (dy > 0) {
                        view.canScrollVertically(-1)
                    } else {
                        view.canScrollVertically(1)
                    }
                    view.parent?.requestDisallowInterceptTouchEvent(canScroll)
                    lastTouchY = event.y
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL ->
                    view.parent?.requestDisallowInterceptTouchEvent(false)
            }
            false
        }
        binding.clearLogButton.setOnClickListener { onClear?.invoke() }
    }

    fun submitLogs(logs: List<String>) {
        val stickToBottom = autoScrollToBottom || isNearBottom()
        val displayLogs = logs.takeLast(MaxDisplayLines)

        adapter.submit(displayLogs)
        binding.logCountText.text = context.getString(R.string.log_count, logs.size)

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
            val binding = ItemLogBinding.inflate(LayoutInflater.from(parent.context), parent, false)
            return Holder(binding)
        }

        override fun onBindViewHolder(holder: Holder, position: Int) {
            holder.bind(lines[position])
        }

        override fun getItemCount(): Int = lines.size

        class Holder(private val binding: ItemLogBinding) : RecyclerView.ViewHolder(binding.root) {
            fun bind(line: String) {
                binding.root.text = line
                binding.root.setTextColor(logLineColor(binding.root.context, line))
            }
        }
    }

    private companion object {
        const val MaxDisplayLines = 200
    }
}

private fun logLineColor(context: Context, line: String): Int {
    val lower = line.lowercase()
    val colorRes = when {
        "error" in lower || "失败" in lower -> R.color.log_error
        "warn" in lower -> R.color.log_warn
        "已启动" in line || "started" in lower -> R.color.log_success
        "已停止" in line || "已退出" in line || "已强制终止" in line || "已请求终止" in line ->
            R.color.log_stopped
        "debug" in lower -> R.color.log_debug
        else -> R.color.log_default
    }
    return ContextCompat.getColor(context, colorRes)
}
