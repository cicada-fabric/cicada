package ai.cicada.client.hub

import android.os.SystemClock
import com.cicadaclient.BuildConfig
import com.google.gson.JsonArray
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive

/** Debug-only, explicitly activated, in-memory Link consent progress observation. */
internal object LinkConsentDebugObservation {
    private const val MAX_EVENTS = 32
    private const val MAX_ELAPSED_MS = 1_200_000L

    private val uiStages = setOf(
        "CONFIRM_OPENED", "CALLBACK_ENTERED", "SCOPE_GUARD_PASSED", "SCOPE_GUARD_REJECTED",
        "REVIEW_CONSUMED", "REVIEW_INVALIDATED", "UI_SUBMIT_DISPATCHED", "UI_RESPONSE_RETURNED",
        "UI_SUBMIT_REJECTED", "RESPONSE_SCOPE_CHANGED",
    )
    private val testStages = setOf("RN_CONFIRM_CLICKED", "ALERT_VERIFIED", "ALERT_POSITIVE_CLICKED")
    private val errorCodes = setOf(
        "CLIENT_HUB_ERROR", "CLIENT_HUB_UNAVAILABLE", "INVALID_PROFILE_SCOPE", "INVALID_ARGUMENT",
        "LINK_CONSENT_CONFIRMATION_REQUIRED", "BUSINESS_RECONCILIATION_REQUIRED",
        "LINK_CONSENT_REVIEW_EXPIRED", "LINK_CONSENT_REVIEW_STALE", "INVALID_LINK_OWNER_PROOF",
        "LINK_CONSENT_REVIEW_INVALID", "LINK_OWNER_PROOF_INVALID",
        "LINK_CONSENT_PACKET_CONTEXT_INVALID", "LINK_REVIEW_POLICY_RESULT_INVALID", "UNCLASSIFIED",
    )

    private data class Event(
        val elapsedMs: Long,
        val stage: String,
        val nativeOk: Boolean? = null,
        val reconciliationRequired: Boolean? = null,
        val errorCode: String? = null,
    )

    private var active = false
    private var startedAtMs = 0L
    private var lastElapsedMs = 0L
    private var runIdSha256: String? = null
    private val events = ArrayList<Event>(MAX_EVENTS)
    private var truncated = false
    private var viewport = "UNKNOWN"

    @Synchronized
    fun begin(runHash: String) {
        resetLocked()
        if (!BuildConfig.DEBUG || !runHash.matches(Regex("[0-9a-f]{64}"))) return
        runIdSha256 = runHash
        startedAtMs = SystemClock.elapsedRealtime()
        active = true
    }

    @Synchronized
    fun recordUiStage(stage: String) {
        guarded { if (stage in uiStages) appendLocked(stage) }
    }

    @Synchronized
    fun recordTestStage(stage: String) {
        guarded { if (stage in testStages) appendLocked(stage) }
    }

    @Synchronized
    fun recordNativeBridgeEntered() {
        guarded { appendLocked("NATIVE_BRIDGE_ENTERED") }
    }

    @Synchronized
    fun recordNativeCallStarted() {
        guarded { appendLocked("NATIVE_CALL_STARTED") }
    }

    @Synchronized
    fun recordNativeResolved(result: JsonObject) {
        guarded {
            appendLocked(
                stage = "NATIVE_RESOLVED",
                nativeOk = exactBoolean(result.get("ok")),
                reconciliationRequired = exactBoolean(result.get("reconciliationRequired")),
                errorCode = optionalResponseErrorCode(result.get("errorCode")),
            )
        }
    }

    @Synchronized
    fun recordNativeRejected(code: String?) {
        guarded { appendLocked(stage = "NATIVE_REJECTED", errorCode = safeErrorCode(code)) }
    }

    @Synchronized
    fun recordViewport(value: String) {
        guarded { if (value in setOf("VISIBLE", "NOT_VISIBLE", "UNKNOWN")) viewport = value }
    }

    /** Returns null unless debug observation was explicitly begun for this run. */
    @Synchronized
    fun snapshot(): JsonObject? {
        if (!BuildConfig.DEBUG || !active) return null
        return try {
            val eventsJson = JsonArray()
            events.forEach { event ->
                eventsJson.add(JsonObject().apply {
                    addProperty("elapsed_ms", event.elapsedMs)
                    addProperty("stage", event.stage)
                    addNullableBoolean("native_ok", event.nativeOk)
                    addNullableBoolean("reconciliation_required", event.reconciliationRequired)
                    addNullableString("error_code", event.errorCode)
                })
            }
            val lastUi = events.lastOrNull { it.stage in uiStages }?.stage
            var nativeOk: Boolean? = null
            var reconciliationRequired: Boolean? = null
            var errorCode: String? = null
            var promiseInFlight: Boolean? = null
            events.forEach { event ->
                when (event.stage) {
                    "NATIVE_CALL_STARTED" -> {
                        nativeOk = null
                        reconciliationRequired = null
                        errorCode = null
                        promiseInFlight = true
                    }
                    "NATIVE_RESOLVED" -> {
                        nativeOk = event.nativeOk
                        reconciliationRequired = event.reconciliationRequired
                        errorCode = event.errorCode
                        promiseInFlight = false
                    }
                    "NATIVE_REJECTED" -> {
                        nativeOk = null
                        reconciliationRequired = null
                        errorCode = event.errorCode
                        promiseInFlight = false
                    }
                }
            }
            JsonObject().apply {
                addProperty("schema", "cicada.client-v164-phone-ui-submit-progress.v1")
                addProperty("result", "OBSERVED")
                addProperty("run_id_sha256", runIdSha256)
                add("events", eventsJson)
                addNullableString("error_code", errorCode)
                addNullableBoolean("native_ok", nativeOk)
                addNullableBoolean("reconciliation_required", reconciliationRequired)
                addNullableBoolean("promise_in_flight", promiseInFlight)
                addProperty("native_packet_pending", "UNKNOWN")
                addProperty("viewport", viewport)
                addNullableString("last_ui_stage", lastUi)
                addProperty("native_session_methods_called_by_test", false)
                addProperty("truncated", truncated)
            }
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    fun end() {
        resetLocked()
    }

    private fun appendLocked(
        stage: String,
        nativeOk: Boolean? = null,
        reconciliationRequired: Boolean? = null,
        errorCode: String? = null,
    ) {
        if (!BuildConfig.DEBUG || !active) return
        if (events.size >= MAX_EVENTS) {
            truncated = true
            return
        }
        val rawElapsed = SystemClock.elapsedRealtime() - startedAtMs
        if (rawElapsed !in 0..MAX_ELAPSED_MS) {
            truncated = true
            return
        }
        val elapsed = maxOf(lastElapsedMs, rawElapsed)
        lastElapsedMs = elapsed
        events += Event(elapsed, stage, nativeOk, reconciliationRequired, errorCode)
    }

    private fun exactBoolean(value: com.google.gson.JsonElement?): Boolean? = try {
        value?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
    } catch (_: Exception) {
        null
    }

    private fun optionalResponseErrorCode(value: com.google.gson.JsonElement?): String? {
        if (value == null || value.isJsonNull) return null
        return try {
            if (value.isJsonPrimitive && value.asJsonPrimitive.isString) safeErrorCode(value.asString)
            else "UNCLASSIFIED"
        } catch (_: Exception) {
            "UNCLASSIFIED"
        }
    }

    private fun safeErrorCode(code: String?): String = code?.takeIf { it in errorCodes } ?: "UNCLASSIFIED"

    private fun JsonObject.addNullableBoolean(name: String, value: Boolean?) {
        add(name, value?.let(::JsonPrimitive) ?: JsonNull.INSTANCE)
    }

    private fun JsonObject.addNullableString(name: String, value: String?) {
        add(name, value?.let(::JsonPrimitive) ?: JsonNull.INSTANCE)
    }

    private inline fun guarded(action: () -> Unit) {
        try {
            if (BuildConfig.DEBUG && active) action()
        } catch (_: Exception) {
            // Diagnostics are passive and must never change consent behavior.
        }
    }

    private fun resetLocked() {
        active = false
        startedAtMs = 0L
        lastElapsedMs = 0L
        runIdSha256 = null
        events.clear()
        truncated = false
        viewport = "UNKNOWN"
    }
}
