package ai.cicada.client.hub

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Instrumentation
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.cicadaclient.MainActivity
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/** Drives only the real React Native UI. It never invokes a Hub session or native consent method. */
@RunWith(AndroidJUnit4::class)
class LinkConsentPhoneUiTest {
    private val instrumentation: Instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private var priorAccessibilityFlags: Int? = null
    private val target get() = instrumentation.targetContext
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v164-[A-Za-z0-9_-]{1,72}")) }
        ?: error("A bounded v1.6.4 run ID is required")
    private val directory get() = File(File(target.noBackupFilesDir, "link-v164"), runId)
    private val requestFile get() = File(directory, "phone-ui-signing-request.private.json")
    private val proofFile get() = File(directory, "phone-ui-signed-proof.private.json")
    private val reviewReceipt get() = File(directory, "phone-ui-review.redacted.json")
    private val resultReceipt get() = File(directory, "phone-ui-submit.redacted.json")
    private val submitProgressReceipt get() = File(directory, "phone-ui-submit-progress.redacted.json")
    private val prepareReceipt get() = File(directory, "phone-ui-prepare.redacted.json")
    private val consentReceipt get() = File(directory, "phone-ui-consent.redacted.json")

    private val consentReadyHint = "签名证明格式有效；请核对授权范围后继续。"
    private val consentInvalidHint = "签名证明输入无效，请检查后继续。"
    private val consentBusyHint = "正在核验，请稍候。"

    private fun enableViewIdReporting() {
        val automation = instrumentation.uiAutomation
        val serviceInfo = automation.serviceInfo
        priorAccessibilityFlags = serviceInfo.flags
        serviceInfo.flags = serviceInfo.flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS or
            AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        automation.setServiceInfo(serviceInfo)
    }

    @After
    fun restoreAccessibilityFlags() {
        try {
            observeSubmitProgressViewportIfUnknown()
            LinkConsentDebugObservation.snapshot()?.let { progress ->
                writePrivate(submitProgressReceipt, progress.toString().toByteArray(StandardCharsets.UTF_8))
            }
        } finally {
            LinkConsentDebugObservation.end()
            val flags = priorAccessibilityFlags
            if (flags != null) {
                val automation = instrumentation.uiAutomation
                val serviceInfo = automation.serviceInfo
                serviceInfo.flags = flags
                automation.setServiceInfo(serviceInfo)
                priorAccessibilityFlags = null
            }
        }
    }

    /** Samples only fixed response labels from the package-filtered app root; it performs no UI action. */
    private fun observeSubmitProgressViewportIfUnknown() {
        try {
            val progress = LinkConsentDebugObservation.snapshot() ?: return
            if (progress.get("viewport")?.asString != "UNKNOWN") return
            val root = uiRoot() ?: return
            val responseLabels = setOf(
                "授权响应已返回。请重读双方证明状态；单方接受不代表 Link 已可用。",
                "授权结果未确认。原请求由设备保留；请恢复原包，不要重复提交。",
                "确认已失效，请重新读取证明。",
            )
            val matches = descendants(root).filter { node ->
                node.packageName?.toString() == target.packageName &&
                    listOf(node.text, node.contentDescription).any { it?.toString() in responseLabels }
            }
            when {
                matches.any { it.isVisibleToUser } -> LinkConsentDebugObservation.recordViewport("VISIBLE")
                matches.isNotEmpty() -> LinkConsentDebugObservation.recordViewport("NOT_VISIBLE")
            }
        } catch (_: Exception) {
            // The test receipt can safely keep UNKNOWN if the app window is unavailable.
        }
    }

    private data class Scope(
        val ownerId: String,
        val ownerKeyId: String,
        val ownerFingerprint: String,
        val linkId: String,
        val linkVersion: Long,
    )

    private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun boundedPrivateFile(file: File, limit: Long): ByteArray {
        require(file.exists() && !file.isDirectory && file.length() in 1..limit &&
            !java.nio.file.Files.isSymbolicLink(file.toPath())) { "Private UI handoff file is missing or invalid" }
        val stat = Os.lstat(file.absolutePath)
        require(stat.st_uid == target.applicationInfo.uid &&
            (stat.st_mode and OsConstants.S_IFMT) == OsConstants.S_IFREG &&
            (stat.st_mode and 0x1ff) == 0x180) { "UI handoff must be an app-owned regular mode-0600 file" }
        return file.readBytes().also { require(it.size.toLong() <= limit) }
    }

    private fun exactLong(value: JsonObject, field: String, minimum: Long = 1L): Long {
        val primitive = value.get(field)?.takeIf { it.isJsonPrimitive }?.asJsonPrimitive
        require(primitive != null && primitive.isNumber && primitive.asString.matches(Regex("0|[1-9][0-9]*"))) {
            "UI scope integer is missing or noncanonical"
        }
        return primitive.asString.toLongOrNull()?.takeIf { it >= minimum }
            ?: error("UI scope integer is out of range")
    }

    private fun writePrivate(file: File, raw: ByteArray) {
        require(directory.isDirectory || directory.mkdirs()) { "Could not create Link UI private directory" }
        require(!java.nio.file.Files.isSymbolicLink(directory.toPath())) { "Link UI private directory is invalid" }
        val atomic = AtomicFile(file)
        val stream = atomic.startWrite()
        try {
            stream.write(raw)
            stream.fd.sync()
            atomic.finishWrite(stream)
        } catch (_: Exception) {
            atomic.failWrite(stream)
            error("Could not persist private UI handoff")
        }
        require(file.setReadable(false, false) && file.setReadable(true, true) &&
            file.setWritable(false, false) && file.setWritable(true, true)) {
            "Could not restrict private UI handoff permissions"
        }
    }

    private fun readScope(): Scope {
        val raw = boundedPrivateFile(File(directory, "selection.json"), 64 * 1024)
        val root = JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
        require(root.get("schema")?.asString == "cicada.client-v164-link-consent-selection.v2" &&
            root.get("run_id")?.asString == runId) { "Selection does not match the fixed Link UI run" }
        val ownerId = root.get("owner_id")?.asString ?: error("Selection Owner is missing")
        val sourcePin = root.getAsJsonObject("source_owner_pin")
        val targetPin = root.getAsJsonObject("target_owner_pin")
        require(ownerId == targetPin.get("owner_id")?.asString) {
            "Phone UI selector must use the fresh TARGET Owner profile from the positive chain"
        }
        val identityJson = targetPin.get("public_identity_json")?.asString
            ?: error("Target Owner public identity pin is missing")
        val identity = JsonParser.parseString(identityJson).asJsonObject
        val fingerprint = targetPin.get("fingerprint")?.asString?.removePrefix("sha256:")
            ?: error("Target Owner fingerprint pin is missing")
        require(identity.get("id")?.asString == targetPin.get("key_id")?.asString &&
            fingerprint.matches(Regex("[0-9a-f]{64}"))) { "Target Owner full key pin is malformed" }
        require(sourcePin.get("owner_id")?.asString != ownerId) { "Owner pins are not bilateral" }
        val version = exactLong(root, "expected_link_version")
        require(sourcePin.get("key_id")?.asString != identity.get("id")?.asString) {
            "Source and target Owner public keys must be distinct"
        }
        return Scope(ownerId, identity.get("id").asString, fingerprint,
            root.get("link_id")?.asString ?: error("Link ID is missing"), version)
    }

    private fun descendants(root: AccessibilityNodeInfo): List<AccessibilityNodeInfo> {
        val result = ArrayList<AccessibilityNodeInfo>()
        fun visit(node: AccessibilityNodeInfo) {
            result += node
            for (index in 0 until node.childCount) node.getChild(index)?.let(::visit)
        }
        visit(root)
        return result
    }

    private fun uiRoot(): AccessibilityNodeInfo? = try {
        val automation = instrumentation.uiAutomation
        val active = automation.rootInActiveWindow
        if (active?.packageName?.toString() == target.packageName) {
            active
        } else {
            active?.recycle()
            val appRoots = ArrayList<AccessibilityNodeInfo>()
            for (window in automation.windows) {
                if (window.type != AccessibilityWindowInfo.TYPE_APPLICATION) continue
                val root = window.root ?: continue
                if (root.packageName?.toString() == target.packageName) appRoots += root
                else root.recycle()
            }
            if (appRoots.size == 1) appRoots.single() else {
                appRoots.forEach(AccessibilityNodeInfo::recycle)
                null
            }
        }
    } catch (_: Exception) { null }

    private fun visibleText(root: AccessibilityNodeInfo): List<String> = descendants(root)
        .filter { it.isVisibleToUser }
        .mapNotNull { it.text?.toString()?.takeIf(String::isNotEmpty) }

    private fun awaitRoot(timeoutMs: Long = 20_000, predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            val root = uiRoot()
            if (root != null && predicate(root)) return root
            SystemClock.sleep(200)
        }
        error("Expected real Link consent UI was not reached")
    }

    private fun nearestClickable(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        var current: AccessibilityNodeInfo? = node
        repeat(8) {
            if (current?.isClickable == true) return current
            current = current?.parent
        }
        return null
    }

    private fun nearestConsentSelectorAncestor(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        var current = node.parent
        repeat(8) {
            val candidate = current ?: return null
            if (candidate.packageName?.toString() == target.packageName && isConsentSelector(candidate)) {
                return candidate
            }
            current = candidate.parent
        }
        return null
    }

    private fun consentTarget(node: AccessibilityNodeInfo): AccessibilityNodeInfo {
        if (isConsentViewId(node)) return node
        var current: AccessibilityNodeInfo? = node
        repeat(8) {
            val candidate = current ?: return nearestConsentSelectorAncestor(node) ?: node
            if (candidate.isClickable && isConsentSelector(candidate)) return candidate
            current = candidate.parent
        }
        return nearestConsentSelectorAncestor(node) ?: node
    }

    private fun appScrollableAncestor(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        var current: AccessibilityNodeInfo? = node
        repeat(16) {
            current = current?.parent
            val candidate = current ?: return null
            if (candidate.packageName?.toString() == target.packageName && candidate.isVisibleToUser &&
                candidate.isScrollable && candidate.className?.toString()?.contains("EditText") != true) {
                return candidate
            }
        }
        return null
    }

    private fun pageScrollableNode(root: AccessibilityNodeInfo): AccessibilityNodeInfo? =
        descendants(root).filter { node -> node.packageName?.toString() == target.packageName &&
            node.isVisibleToUser && node.isScrollable &&
            node.className?.toString()?.contains("EditText") != true }
            .maxByOrNull { node ->
                android.graphics.Rect().also { node.getBoundsInScreen(it) }.let { it.width() * it.height() }
            }

    private fun clickLabel(label: String, timeoutMs: Long = 20_000) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            val root = uiRoot()
            if (root != null) {
                val targets = descendants(root).filter { node -> node.isVisibleToUser &&
                    node.packageName?.toString() == target.packageName &&
                    (node.text?.toString() == label || node.contentDescription?.toString() == label) }
                    .mapNotNull(::nearestClickable)
                    .distinctBy { node -> android.graphics.Rect().also { node.getBoundsInScreen(it) }.toShortString() }
                if (targets.size == 1) {
                    check(targets.single().performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                        "Could not activate the visible product control"
                    }
                    return
                }
            }
            SystemClock.sleep(150)
        }
        error("Product control was missing or ambiguous: $label")
    }

    private data class ConsentControl(
        val target: AccessibilityNodeInfo?,
        val stage: String,
        val count: Int,
        val enabledCount: Int,
        val busy: Boolean?,
        val proofReady: Boolean?,
        val visible: Boolean,
    )

    private fun isConsentViewId(node: AccessibilityNodeInfo): Boolean =
        node.packageName?.toString() == target.packageName &&
            node.viewIdResourceName in setOf(
                "link-consent-confirm",
                "${target.packageName}:id/link-consent-confirm",
            )

    private fun consentHint(node: AccessibilityNodeInfo): String? =
        listOf(node.tooltipText?.toString(), node.hintText?.toString())
            .firstOrNull { it in setOf(consentReadyHint, consentInvalidHint, consentBusyHint) }

    private fun isConsentSelector(node: AccessibilityNodeInfo): Boolean {
        return node.packageName?.toString() == target.packageName && (isConsentViewId(node) ||
            node.text?.toString() == "核对并明确授权" ||
            node.contentDescription?.toString() == "核对并明确授权" ||
            consentHint(node) != null)
    }

    private fun consentControl(root: AccessibilityNodeInfo): ConsentControl {
        val appNodes = descendants(root).filter { it.packageName?.toString() == target.packageName }
        val idMatches = appNodes.filter(::isConsentViewId)
        val selectors = if (idMatches.isNotEmpty()) idMatches else appNodes.filter(::isConsentSelector)
        val controls = selectors.map(::consentTarget).distinct()
        if (controls.isEmpty()) return ConsentControl(null, "CONTROL_MISSING", 0, 0, null, null, false)
        if (controls.size > 1) return ConsentControl(null, "CONTROL_MULTIPLE", 2,
            controls.count { it.isEnabled }.coerceAtMost(2), null, null,
            controls.any { it.isVisibleToUser })

        val target = controls.single()
        val visible = target.isVisibleToUser
        val stateHint = descendants(target).firstNotNullOfOrNull(::consentHint)
        return when (stateHint) {
            consentBusyHint -> ConsentControl(target, "CONTROL_BUSY", 1,
                if (target.isEnabled) 1 else 0, true, null, visible)
            consentInvalidHint -> ConsentControl(target, "PROOF_INVALID", 1,
                if (target.isEnabled) 1 else 0, false, false, visible)
            consentReadyHint -> if (target.isEnabled) {
                if (visible && target.isClickable) ConsentControl(target, "CONFIRM_READY", 1, 1, false, true, true)
                else ConsentControl(target, "CONTROL_UNCONFIRMED", 1, 1, null, null, visible)
            } else {
                ConsentControl(target, "CONTROL_DISABLED", 1, 0, false, true, visible)
            }
            else -> ConsentControl(target, "CONTROL_UNCONFIRMED", 1,
                if (target.isEnabled) 1 else 0, null, null, visible)
        }
    }

    /** Receipts contain only fixed stages, bounded counts, and booleans. */
    private fun recordConsentControl(value: ConsentControl) {
        require(value.stage in setOf("CONTROL_MISSING", "CONTROL_MULTIPLE", "CONTROL_BUSY",
            "PROOF_INVALID", "CONTROL_DISABLED", "CONTROL_UNCONFIRMED", "CONFIRM_READY",
            "ACCESSIBILITY_CLICK_FAILED"))
        val record = JsonObject().apply {
            addProperty("schema", "cicada.client-v164-phone-ui-consent.v1")
            addProperty("result", if (value.stage == "CONFIRM_READY") "PASS" else "FAIL")
            addProperty("run_id_sha256", hash(runId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("stage", value.stage)
            addProperty("control_count", value.count.coerceIn(0, 2))
            addProperty("enabled_count", value.enabledCount.coerceIn(0, 2))
            add("busy", value.busy?.let { com.google.gson.JsonPrimitive(it) } ?: JsonNull.INSTANCE)
            add("proof_ready", value.proofReady?.let { com.google.gson.JsonPrimitive(it) } ?: JsonNull.INSTANCE)
            addProperty("native_session_methods_called_by_test", false)
        }
        writePrivate(consentReceipt, record.toString().toByteArray(StandardCharsets.UTF_8))
    }

    private fun awaitEnabledConsentControl(timeoutMs: Long = 20_000): AccessibilityNodeInfo {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        var latest = ConsentControl(null, "CONTROL_MISSING", 0, 0, null, null, false)
        var scrollActions = 0
        while (SystemClock.elapsedRealtime() < deadline) {
            val root = uiRoot()
            if (root != null) {
                latest = consentControl(root)
                if (latest.stage == "CONFIRM_READY" && latest.visible) return latest.target!!
                if (!latest.visible && scrollActions < 12) {
                    val scroll = latest.target?.let(::appScrollableAncestor) ?: pageScrollableNode(root)
                    if (scroll != null) {
                        scrollActions += 1
                        scroll.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
                    }
                }
            }
            SystemClock.sleep(200)
        }
        recordConsentControl(latest)
        error("Consent confirmation control did not become ready: ${latest.stage}")
    }

    private fun scrollToText(needle: String, timeoutMs: Long = 20_000) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        while (SystemClock.elapsedRealtime() < deadline) {
            val root = uiRoot()
            if (root == null) {
                SystemClock.sleep(200)
                continue
            }
            if (descendants(root).any { node -> node.isVisibleToUser &&
                    node.packageName?.toString() == target.packageName &&
                    listOf(node.text, node.contentDescription, node.hintText).any { it?.toString()?.contains(needle) == true } }) return
            val scroll = descendants(root).filter { node -> node.isVisibleToUser && node.isScrollable &&
                node.packageName?.toString() == target.packageName }
                .maxByOrNull { node -> android.graphics.Rect().also { node.getBoundsInScreen(it) }.let { it.width() * it.height() } }
            // A fresh encrypted read may append content after the current page
            // reaches its bottom. Keep polling until the bounded deadline.
            scroll?.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
            SystemClock.sleep(250)
        }
        error("Could not scroll to the requested visible Link review content")
    }

    /** Bounded response-only search; it never clicks or accepts a message without its stable app view ID. */
    private fun scrollToSubmitResponse(timeoutMs: Long = 20_000) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        val planner = LinkConsentViewportSearchPlanner()
        val responsePrefix = "授权响应已返回。请重读双方证明状态"
        val literalViewId = "link-consent-message"
        val qualifiedViewId = "${target.packageName}:id/link-consent-message"
        while (SystemClock.elapsedRealtime() < deadline) {
            val root = uiRoot()
            if (root == null) {
                SystemClock.sleep(200)
                continue
            }
            val matches = descendants(root).filter { node ->
                node.packageName?.toString() == target.packageName && node.isVisibleToUser &&
                    node.viewIdResourceName in setOf(literalViewId, qualifiedViewId) &&
                    listOf(node.text, node.contentDescription).any {
                        it?.toString()?.startsWith(responsePrefix) == true
                    }
            }
            if (matches.size == 1) return
            if (matches.size > 1) error("Submit response view is ambiguous")

            val progress = LinkConsentDebugObservation.snapshot()
            val scrollReady = progress == null || progress.get("last_ui_stage")?.let {
                !it.isJsonNull && it.asString == "UI_RESPONSE_RETURNED"
            } == true
            val direction = planner.nextDirection(contentReady = scrollReady)
            if (direction == null) {
                SystemClock.sleep(200)
                continue
            }
            val scroll = pageScrollableNode(root)
            if (scroll == null) {
                SystemClock.sleep(200)
                continue
            }
            val action = if (direction == LinkConsentViewportSearchPlanner.Direction.BACKWARD)
                AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD else AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
            val moved = try { scroll.performAction(action) } catch (_: Exception) { false }
            planner.recordActionResult(moved)
            SystemClock.sleep(200)
        }
        error("Submit response view was not made visible before the bounded wait elapsed")
    }

    /** Only fixed UI stages are exported; neither the accessibility tree nor errors are saved. */
    private fun recordPreparation(stage: String) {
        require(stage in setOf("REVIEW_READY", "PREPARE_API_REJECTED", "DTO_REJECTED",
            "REVIEW_INVALIDATED", "PREPARE_NOT_STARTED", "PREPARE_TIMEOUT", "REVIEW_NOT_VISIBLE"))
        val record = JsonObject().apply {
            addProperty("schema", "cicada.client-v164-phone-ui-prepare.v1")
            addProperty("result", if (stage == "REVIEW_READY") "PASS" else "FAIL")
            addProperty("run_id_sha256", hash(runId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("stage", stage)
            addProperty("native_session_methods_called_by_test", false)
        }
        writePrivate(prepareReceipt, record.toString().toByteArray(StandardCharsets.UTF_8))
    }

    private fun failPreparation(stage: String): Nothing {
        recordPreparation(stage)
        error("Link consent preparation did not reach a visible review: $stage")
    }

    private fun awaitPreparationSettled(timeoutMs: Long = 20_000) {
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        val prefix = "CICADA_LINK_PREPARE:"
        val rejected = setOf("PREPARE_API_REJECTED", "DTO_REJECTED", "REVIEW_INVALIDATED", "PREPARE_NOT_STARTED")
        while (SystemClock.elapsedRealtime() < deadline) {
            val root = uiRoot()
            val stages = root?.let { descendants(it) }.orEmpty().filter { it.isVisibleToUser }
                .mapNotNull { it.contentDescription?.toString() }
                .filter { it.startsWith(prefix) }
                .map { it.removePrefix(prefix) }
            if (stages.size == 1) {
                val stage = stages.single()
                if (stage == "REVIEW_READY") return
                if (stage in rejected) failPreparation(stage)
            }
            SystemClock.sleep(200)
        }
        failPreparation("PREPARE_TIMEOUT")
    }

    private fun signerRequest(root: AccessibilityNodeInfo): String {
        val marker = "cicada.client.link-consent-signing-request.v1"
        return descendants(root).asSequence().filter { it.isVisibleToUser }
            .mapNotNull { it.text?.toString() }
            .firstOrNull { it.contains(marker) }
            ?: error("Fresh signer request is not present in the real UI")
    }

    private fun validateRequest(raw: String, scope: Scope): JsonObject {
        val value = JsonParser.parseString(raw).asJsonObject
        val fields = setOf("schema", "kind", "owner_id", "owner_key_id", "owner_key_fingerprint", "link_id",
            "link_version", "contract_digest", "side", "max_expiry", "expires_at", "manifest_digest")
        require(value.keySet() == fields && value.get("schema")?.asString ==
            "cicada.client.link-consent-signing-request.v1" && value.get("kind")?.asString == "KEY" &&
            value.get("owner_id")?.asString == scope.ownerId && value.get("owner_key_id")?.asString == scope.ownerKeyId &&
            value.get("owner_key_fingerprint")?.asString == scope.ownerFingerprint &&
            value.get("link_id")?.asString == scope.linkId && exactLong(value, "link_version") == scope.linkVersion &&
            value.get("side")?.asString == "TARGET") { "Fresh UI signing request differs from pinned target Link scope" }
        for (field in listOf("contract_digest", "manifest_digest", "owner_key_fingerprint")) {
            require(value.get(field)?.asString?.matches(Regex("[0-9a-f]{64}")) == true) {
                "Fresh UI signer digest is malformed"
            }
        }
        val maxExpiry = value.get("max_expiry")?.asString?.let { Instant.parse(it) }
            ?: error("Owner signing request maximum expiry is missing")
        val proofExpiry = value.get("expires_at")?.asString?.let { Instant.parse(it) }
            ?: error("Owner signing request expiry is missing")
        require(proofExpiry <= maxExpiry && proofExpiry.isAfter(Instant.now())) {
            "Owner signing request expiry is invalid or already elapsed"
        }
        return value
    }

    private fun proofInput(requestSha: String): Pair<String, String> {
        val raw = boundedPrivateFile(proofFile, 32 * 1024)
        val value = JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
        require(value.keySet() == setOf("schema", "run_id", "signing_request_sha256", "signed_proof_base64", "proof_sha256") &&
            value.get("schema")?.asString == "cicada.client-v164-phone-ui-proof-handoff.v1" &&
            value.get("run_id")?.asString == runId && value.get("signing_request_sha256")?.asString == requestSha) {
            "External proof is not bound to the exact current UI signer request"
        }
        val encoded = value.get("signed_proof_base64")?.asString ?: error("Signed proof is missing")
        val bytes = try { Base64.getDecoder().decode(encoded) }
            catch (_: IllegalArgumentException) { error("Signed proof is not canonical base64") }
        require(bytes.isNotEmpty() && bytes.size <= 16 * 1024 &&
            Base64.getEncoder().encodeToString(bytes) == encoded && value.get("proof_sha256")?.asString == hash(bytes)) {
            "Signed proof bytes or digest are invalid"
        }
        val digest = hash(bytes)
        bytes.fill(0)
        require(proofFile.delete()) { "Could not remove staged public proof after reading" }
        return encoded to digest
    }

    private fun setTextByHint(hint: String, value: String) {
        val root = awaitRoot { tree -> descendants(tree).any { it.isVisibleToUser &&
            it.className?.toString()?.contains("EditText") == true &&
            (it.hintText?.toString() == hint || it.text?.toString() == hint) } }
        val fields = descendants(root).filter { node -> node.isVisibleToUser &&
            node.className?.toString()?.contains("EditText") == true &&
            (node.hintText?.toString() == hint || node.text?.toString() == hint) }
        require(fields.size == 1) { "Expected a single product proof field" }
        val bundle = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        require(fields.single().performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, bundle)) {
            "Android accessibility could not set the signed proof into the product field"
        }
        val refreshed = uiRoot() ?: error("Product UI closed after setting proof")
        require(descendants(refreshed).any { node -> node.isVisibleToUser &&
            node.className?.toString()?.contains("EditText") == true && node.text?.toString() == value }) {
            "Product proof field did not retain the exact signed proof"
        }
    }

    @Test
    fun actualReactNativeLinkConsentAlertUsesCurrentExternallySignedReview() {
        val runHash = hash(runId.toByteArray(StandardCharsets.UTF_8))
        require(!requestFile.exists() && !proofFile.exists() && !reviewReceipt.exists() &&
            !resultReceipt.exists() && !submitProgressReceipt.exists() && !prepareReceipt.exists() &&
            !consentReceipt.exists()) {
            "This UI run already contains a signer handoff; use a fresh run ID instead of replaying it"
        }
        LinkConsentDebugObservation.begin(runHash)
        val scope = readScope()
        enableViewIdReporting()
        val activity = instrumentation.startActivitySync(
            Intent(target, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP),
        )
        assertNotNull("MainActivity did not launch", activity)
        awaitRoot { root -> descendants(root).any { it.isVisibleToUser &&
            it.contentDescription?.toString() == "管理 Hub 连接" } }

        clickLabel("管理")
        scrollToText("跨用户 Link 提案")
        awaitRoot { root -> visibleText(root).any { it == "跨用户 Link 提案" } }
        clickLabel("重读本人提案  →")
        scrollToText(scope.linkId)
        awaitRoot { root ->
            val texts = visibleText(root)
            texts.any { it.contains(scope.linkId) } && texts.any { it.contains("PROPOSED") }
        }

        scrollToText("读取当前证明")
        clickLabel("读取当前证明")
        awaitPreparationSettled()
        try {
            scrollToText(" → ")
        } catch (_: IllegalStateException) {
            failPreparation("REVIEW_NOT_VISIBLE")
        }
        recordPreparation("REVIEW_READY")
        val scopeRoot = uiRoot() ?: error("React Native review UI is unavailable")
        val displayedEndpointScope = visibleText(scopeRoot).firstOrNull { it.contains(" → ") }
            ?: error("Displayed Endpoint and Group scope is missing")
        scrollToText("到期 ")
        val expiryRoot = uiRoot() ?: error("React Native review UI is unavailable")
        val displayedExpiry = visibleText(expiryRoot).firstOrNull { it.startsWith("到期 ") }
            ?: error("Displayed review expiry is missing")
        scrollToText("cicada.client.link-consent-signing-request.v1")
        val visibleReview = uiRoot() ?: error("React Native review UI is unavailable")
        val requestText = signerRequest(visibleReview)
        validateRequest(requestText, scope)
        val requestBytes = requestText.toByteArray(StandardCharsets.UTF_8)
        val requestSha = hash(requestBytes)
        writePrivate(requestFile, requestBytes)
        val reviewRecord = JsonObject().apply {
            addProperty("schema", "cicada.client-v164-phone-ui-review.v1")
            addProperty("result", "WAITING_FOR_EXTERNAL_OWNER_SIGNATURE")
            addProperty("run_id_sha256", hash(runId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("link_id_sha256", hash(scope.linkId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("link_version", scope.linkVersion)
            addProperty("side", "TARGET")
            addProperty("signing_request_sha256", requestSha)
            addProperty("raw_signer_request_exported_from_real_ui", true)
            addProperty("native_session_methods_called_by_test", false)
        }
        writePrivate(reviewReceipt, reviewRecord.toString().toByteArray(StandardCharsets.UTF_8))
        requestBytes.fill(0)

        val proofDeadline = SystemClock.elapsedRealtime() + 180_000
        while (!proofFile.exists() && SystemClock.elapsedRealtime() < proofDeadline) SystemClock.sleep(250)
        require(proofFile.exists()) { "External signed proof handoff did not arrive before the bound wait elapsed" }
        val (signedProof, proofSha) = proofInput(requestSha)

        // Confirm that the component still displays the same review after the host round trip.
        scrollToText("cicada.client.link-consent-signing-request.v1")
        val currentRoot = uiRoot() ?: error("React Native review UI disappeared")
        require(hash(signerRequest(currentRoot).toByteArray(StandardCharsets.UTF_8)) == requestSha) {
            "Current UI review changed while the external Owner signer was working"
        }
        scrollToText("Owner 签名证明 Base64")
        setTextByHint("Owner 签名证明 Base64", signedProof)
        signedProof.toCharArray().fill('\u0000')
        val consentControl = awaitEnabledConsentControl()
        if (!consentControl.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
            recordConsentControl(ConsentControl(consentControl, "ACCESSIBILITY_CLICK_FAILED", 1, 1, false, true, true))
            error("Consent confirmation control could not be activated")
        }
        LinkConsentDebugObservation.recordTestStage("RN_CONFIRM_CLICKED")
        recordConsentControl(ConsentControl(consentControl, "CONFIRM_READY", 1, 1, false, true, true))

        val alertRoot = awaitRoot { root ->
            val texts = visibleText(root)
            texts.any { it == "提交此授权？" } && texts.any { it.contains(scope.linkId) && it.contains("v${scope.linkVersion}") }
        }
        val alertText = visibleText(alertRoot).joinToString("\n")
        require(alertText.contains("TARGET") && alertText.contains(displayedEndpointScope) &&
            alertText.contains("范围：") && alertText.contains(displayedExpiry) &&
            alertText.contains("合约 ${validateRequest(requestText, scope).get("contract_digest").asString}")) {
            "Native Alert does not display the exact Link side and contract reviewed by the signer"
        }
        LinkConsentDebugObservation.recordTestStage("ALERT_VERIFIED")
        clickLabel("明确授权", timeoutMs = 10_000)
        LinkConsentDebugObservation.recordTestStage("ALERT_POSITIVE_CLICKED")
        scrollToSubmitResponse(timeoutMs = 20_000)
        awaitRoot { root -> visibleText(root).any { it.contains("授权响应已返回。请重读双方证明状态") } }
        LinkConsentDebugObservation.recordViewport("VISIBLE")

        scrollToText("重读双方证明状态")
        clickLabel("重读双方证明状态")
        scrollToText("SOURCE ACCEPTED", timeoutMs = 30_000)
        val statusRoot = awaitRoot(30_000) { root -> visibleText(root).any {
            it.contains("SOURCE ACCEPTED") && it.contains("TARGET ACCEPTED") && it.contains("双方当前证明已独立核验")
        } }
        val statusText = visibleText(statusRoot).first { it.contains("SOURCE ACCEPTED") && it.contains("TARGET ACCEPTED") }
        val record = JsonObject().apply {
            addProperty("schema", "cicada.client-v164-phone-ui-submit.v1")
            addProperty("result", "PASS")
            addProperty("run_id_sha256", hash(runId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("link_id_sha256", hash(scope.linkId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("link_version", scope.linkVersion)
            addProperty("side", "TARGET")
            addProperty("signing_request_sha256", requestSha)
            addProperty("proof_sha256", proofSha)
            addProperty("rn_review_button_clicked", true)
            addProperty("android_alert_title_verified", true)
            addProperty("android_alert_scope_verified", true)
            addProperty("android_alert_positive_button_clicked", true)
            addProperty("emulator_accessibility_alert_confirmation_clicked", true)
            addProperty("post_submit_status_sha256", hash(statusText.toByteArray(StandardCharsets.UTF_8)))
            addProperty("source_status", "ACCEPTED")
            addProperty("target_status", "ACCEPTED")
            addProperty("bilateral_verified", true)
            addProperty("phone_ui_alert_clicked_by_automation", true)
            addProperty("emulator_ui_confirmation_observed", true)
            addProperty("human_phone_confirmation_observed", false)
            addProperty("physical_phone_confirmation_observed", false)
            addProperty("native_session_methods_called_by_test", false)
        }
        writePrivate(resultReceipt, record.toString().toByteArray(StandardCharsets.UTF_8))
    }
}
