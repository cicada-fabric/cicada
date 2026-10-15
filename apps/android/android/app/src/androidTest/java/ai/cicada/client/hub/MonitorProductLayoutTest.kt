package ai.cicada.client.hub

import android.content.Intent
import android.graphics.Rect
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.cicadaclient.MainActivity
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.time.Instant

/** Read-only native layout probe for the expanded Monitor product UI. */
@RunWith(AndroidJUnit4::class)
class MonitorProductLayoutTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val runId: String get() = InstrumentationRegistry.getArguments().getString("run_id")
        ?.takeIf { it.matches(Regex("monitor-v13-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A safe Monitor run_id is required")
    private val directory get() = File(target.noBackupFilesDir, "monitor-v13/$runId")

    private data class ProbeNode(
        val label: String,
        val viewClass: String,
        val measuredWidth: Int,
        val measuredHeight: Int,
        val x: Float,
        val y: Float,
        val visibility: String,
        val alpha: Float,
        val nativeId: String?,
        val parentClass: String?,
        val parentMeasuredWidth: Int?,
        val parentMeasuredHeight: Int?,
        val parentNativeId: String?,
        val ancestorNativeIds: List<String>,
        val hasGlobalVisibleRect: Boolean,
        val globalVisibleBounds: Rect,
    ) {
        fun toJson(): JSONObject = JSONObject()
            .put("label", label)
            .put("class", viewClass)
            .put("measuredWidth", measuredWidth)
            .put("measuredHeight", measuredHeight)
            .put("x", x.toDouble())
            .put("y", y.toDouble())
            .put("visibility", visibility)
            .put("alpha", alpha.toDouble())
            .put("nativeId", nativeId ?: JSONObject.NULL)
            .put("parentClass", parentClass ?: JSONObject.NULL)
            .put("parentMeasuredWidth", parentMeasuredWidth ?: JSONObject.NULL)
            .put("parentMeasuredHeight", parentMeasuredHeight ?: JSONObject.NULL)
            .put("parentNativeId", parentNativeId ?: JSONObject.NULL)
            .put("ancestorNativeIds", JSONArray().apply { ancestorNativeIds.forEach { put(it) } })
            .put("hasGlobalVisibleRect", hasGlobalVisibleRect)
            .put("globalVisibleBounds", JSONArray()
                .put(globalVisibleBounds.left)
                .put(globalVisibleBounds.top)
                .put(globalVisibleBounds.right)
                .put(globalVisibleBounds.bottom))
    }

    private val textLabels = mapOf(
        "收起 Monitor 广播 →" to "monitor-action-expanded",
        "Monitor 广播 →" to "monitor-action-collapsed",
        "Monitor 入口已由 v1.3 Hub catalog、加密 session.capabilities 和 Android 安全桥共同授权。Prepare 只向 Control 发送精确正文的 SHA-256；明文仅留在本机内存，Confirm 由安全桥重新核对、加密并签名。" to "monitor-entry-notice",
        "1 · 选择确切 Group" to "monitor-group-selection",
        "2 · 选择该 Group 的 Monitor Endpoint" to "monitor-endpoint-selection",
        "3 · 精确正文" to "monitor-body-section",
        "4 · 核对已验证的完整同意预览" to "monitor-preview-section",
        "5 · Hub 权威审批与逐收件人结果" to "monitor-status-section",
        "Group Endpoint 公钥授权" to "group-key-grants-title",
    )
    private val allowedNativeIds = setOf("monitor-panel-host")
    private val nativeIdTagKey: Int by lazy {
        target.resources.getIdentifier("view_tag_native_id", "id", target.packageName)
    }

    private fun safeNativeId(view: View?): String? {
        if (view == null || nativeIdTagKey == 0) return null
        return (view.getTag(nativeIdTagKey) as? String)?.takeIf { it in allowedNativeIds }
    }

    private fun normalizeLabel(value: String): String =
        value.replace(Regex("\\s+"), " ").trim()

    private fun labelFor(view: View): String? {
        if (safeNativeId(view) == "monitor-panel-host") return "monitor-panel-host"
        if (view is EditText) {
            return when (normalizeLabel(view.hint?.toString().orEmpty())) {
                "输入要交给所选 Monitor 的准确文本" -> "monitor-body-placeholder"
                "Group ID" -> "group-key-id-placeholder"
                else -> null
            }
        }
        if (view is TextView) {
            return textLabels[normalizeLabel(view.text?.toString().orEmpty())]
        }
        return null
    }

    private fun visibilityName(value: Int): String = when (value) {
        View.VISIBLE -> "VISIBLE"
        View.INVISIBLE -> "INVISIBLE"
        View.GONE -> "GONE"
        else -> "UNKNOWN"
    }

    private fun visit(view: View, output: MutableList<ProbeNode>) {
        labelFor(view)?.let { label ->
            val parent = view.parent as? View
            val ancestorNativeIds = mutableListOf<String>()
            var ancestor = parent
            while (ancestor != null) {
                safeNativeId(ancestor)?.let(ancestorNativeIds::add)
                ancestor = ancestor.parent as? View
            }
            val bounds = Rect()
            val visible = view.getGlobalVisibleRect(bounds)
            output.add(ProbeNode(
                label = label,
                viewClass = view.javaClass.name,
                measuredWidth = view.measuredWidth,
                measuredHeight = view.measuredHeight,
                x = view.x,
                y = view.y,
                visibility = visibilityName(view.visibility),
                alpha = view.alpha,
                nativeId = safeNativeId(view),
                parentClass = parent?.javaClass?.name,
                parentMeasuredWidth = parent?.measuredWidth,
                parentMeasuredHeight = parent?.measuredHeight,
                parentNativeId = safeNativeId(parent),
                ancestorNativeIds = ancestorNativeIds,
                hasGlobalVisibleRect = visible,
                globalVisibleBounds = bounds,
            ))
        }
        if (view is ViewGroup) {
            for (index in 0 until view.childCount) visit(view.getChildAt(index), output)
        }
    }

    @Test fun expandedMonitorControlsHaveMeasuredNativeViews() {
        assertTrue("Could not create the private probe directory",
            directory.isDirectory || directory.mkdirs())
        val marker = File(directory, "collect-layout")
        assertTrue("Could not remove a stale layout collection marker",
            !marker.exists() || marker.delete())
        val activity = instrumentation.startActivitySync(
            Intent(target, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        assertTrue("MainActivity did not start", activity.window?.decorView != null)
        instrumentation.sendStatus(0, Bundle().apply {
            putString("product_ui_probe_ready", "true")
        })

        val deadline = SystemClock.elapsedRealtime() + 180_000L
        while (!marker.isFile && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(200L)
        }
        assertTrue("Timed out waiting for the manual layout collection marker", marker.isFile)

        val nodes = mutableListOf<ProbeNode>()
        instrumentation.runOnMainSync {
            visit(activity.window.decorView, nodes)
        }

        val result = JSONObject()
            .put("schema", "cicada.monitor-product-layout-probe.v1")
            .put("capturedAt", Instant.now().toString())
            .put("matchedViewCount", nodes.size)
            .put("views", JSONArray().apply { nodes.forEach { put(it.toJson()) } })
        File(directory, "layout-probe.json").writeText(result.toString())

        val expandedActionCount = nodes.count { it.label == "monitor-action-expanded" }
        val noticeCount = nodes.count { it.label == "monitor-entry-notice" }
        val hostCount = nodes.count { it.label == "monitor-panel-host" }
        instrumentation.sendStatus(0, Bundle().apply {
            putString("monitor_layout_probe_saved", "true")
            putString("monitor_layout_probe_match_count", nodes.size.toString())
            putString("monitor_layout_probe_expanded_action_count", expandedActionCount.toString())
            putString("monitor_layout_probe_notice_count", noticeCount.toString())
            putString("monitor_layout_probe_host_count", hostCount.toString())
        })

        assertTrue("Persistent Monitor host native ID is missing or has zero height",
            nodes.any { it.label == "monitor-panel-host" && it.measuredHeight > 0 })
        assertTrue("Expanded Monitor action label is missing or has zero height",
            nodes.any { it.label == "monitor-action-expanded" && it.measuredHeight > 0 })
        assertTrue("Unconditional Monitor notice is missing or has zero height",
            nodes.any { it.label == "monitor-entry-notice" && it.measuredHeight > 0 })
    }
}
