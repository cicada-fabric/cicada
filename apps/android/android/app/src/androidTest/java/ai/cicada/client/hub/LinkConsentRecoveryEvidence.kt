package ai.cicada.client.hub

import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.Strictness
import com.google.gson.JsonPrimitive
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Test-only persisted-state checks; these do not authenticate a Hub response. */
internal object LinkConsentRecoveryEvidence {
    const val CAPTURE_SCHEMA = "cicada.client-v164-link-consent-recovery-capture.v2"
    const val READY_SCHEMA = "cicada.client-v164-link-recovery-ready.v1"
    const val CATALOG_SHA256 = "a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9"
    const val CONTRACT_REVISION = "client-hub-v1.6.5"
    const val CORE_REVISION = "c6887f46c8412e648b8e8e68da371acd80e0b87e"
    const val HUB_IMAGE_ID = "sha256:b7bc42678adf9ab44df2a3c51732b2956d668dd7745a93ec3c2a0387d3fc07c2"
    const val SOURCE_FINGERPRINT = "cc4ae9207a790c30e9b702c378d9a699bfe95f56e80b5ccfe3b748a6aefaf1ef"
    private val HEX_64 = Regex("[0-9a-f]{64}")
    enum class Outcome { COMPLETED, PENDING, UNCERTAIN }

    class Original internal constructor(
        val operation: String,
        val operationId: String,
        val operationIdSha256: String,
        val requestSequence: Long,
        val expectedResponseSequence: Long,
        val packetSha256: String,
        val proofSha256: String,
        val tupleSha256: String,
        internal val pending: JsonObject,
        internal val fence: JsonObject,
        internal val pin: JsonObject,
        internal val enrollment: JsonObject,
        internal val nextSequence: Long,
        internal val lastResponseSequence: Long,
    )

    data class FaultReady(
        val mode: String,
        val operation: String,
        val requestSha256: String,
        val requestSequence: Long,
        val requestStatus: String,
        val reservedResponseSequence: Long,
        val businessOutcome: String,
        val handlerExecuted: Boolean,
        val scope: String,
        val responseSha256: String?,
        val restartRequired: Boolean?,
        val hubSourceSha256: String,
        val readyEnvelopeSha256: String,
        val rawEventSha256: String,
        val restartReceiptSha256: String?,
    )

    data class FaultVerification(
        val outcome: Outcome,
        val faultReady: FaultReady,
        val recoveryError: String?,
    )

    fun capture(state: JsonObject, expectedOperation: String): Original {
        require(expectedOperation in setOf("link.key_grant", "link.review_policy_grant")) {
            "Recovery must select a dedicated Link consent operation"
        }
        val pending = objectField(state, "pending")
        val fence = objectField(objectField(state, "linkConsentLedger"), "write_fence")
        val pin = objectField(state, "pin")
        val enrollment = objectField(state, "enrollment")
        val operationId = string(pending, "operationId")
        val sequence = number(pending, "sequence", 1)
        val responseSequence = number(pending, "expectedResponseSequence", 1)
        val nextSequence = number(state, "nextSequence", 1)
        val lastResponseSequence = number(state, "lastResponseSequence", 0)
        require(sequence < Long.MAX_VALUE && lastResponseSequence < Long.MAX_VALUE &&
            nextSequence == sequence + 1 && responseSequence == lastResponseSequence + 1) {
            "Original recovery counters are inconsistent"
        }
        val packet = string(pending, "packetJson")
        val packetHash = digest(packet)
        val route = objectField(JsonParser.parseString(packet).asJsonObject, "route")
        require(string(pending, "operation") == expectedOperation &&
            string(route, "operation") == expectedOperation && string(route, "operation_id") == operationId &&
            number(route, "sequence", 1) == sequence &&
            string(route, "hub_id") == string(pin, "hubId") &&
            string(route, "owner_id") == string(enrollment, "ownerId") &&
            string(route, "device_id") == string(enrollment, "deviceId") &&
            number(route, "session_epoch", 1) == number(enrollment, "sessionEpoch", 1)) {
            "Original packet route differs from its enrolled request context"
        }
        require(string(fence, "operation") == expectedOperation &&
            string(fence, "operation_id") == operationId &&
            number(fence, "request_sequence", 1) == sequence &&
            number(fence, "expected_response_sequence", 1) == responseSequence &&
            string(fence, "packet_json") == packet && string(fence, "packet_sha256") == packetHash &&
            string(fence, "signed_proof_sha256") == digest(string(fence, "signed_proof_json"))) {
            "Original consent fence differs from the saved packet or proof bytes"
        }
        val proofHash = string(fence, "signed_proof_sha256")
        val tupleHash = optionalString(fence, "tuple_digest") ?: ""
        require(HEX_64.matches(packetHash) && HEX_64.matches(proofHash) &&
            (tupleHash.isEmpty() || HEX_64.matches(tupleHash))) {
            "Original Link recovery digest is invalid"
        }
        return Original(expectedOperation, operationId, digest(operationId), sequence, responseSequence, packetHash,
            proofHash, tupleHash,
            pending.deepCopy(), fence.deepCopy(), pin.deepCopy(), enrollment.deepCopy(),
            nextSequence, lastResponseSequence)
    }

    /** Captures only a durable, still-pending request after the native submit saw a transport loss. */
    fun captureOriginalConsentFault(state: JsonObject, expectedOperation: String): Original {
        val original = capture(state, expectedOperation)
        require(string(original.fence, "state") == "PENDING" &&
            boolean(state, "sessionCapabilitiesReady") &&
            !optionalBoolean(state, "authFenced") && !optionalBoolean(state, "recoveryBlocked") &&
            !optionalBoolean(state, "uncertainNeedsReconciliation") && optionalObject(state, "retiredPending") == null) {
            "Original Link consent write was not left pending after transport loss"
        }
        require(original.lastResponseSequence + 1 == original.expectedResponseSequence) {
            "Original Link consent response reservation differs from the persisted counter"
        }
        val ledger = objectField(state, "linkConsentLedger")
        val review = objectField(ledger, "review")
        val tuple = objectField(review, "tuple")
        require(HEX_64.matches(original.tupleSha256) && digest(tuple.toString()) == original.tupleSha256) {
            "Original consent tuple digest differs from the saved authority tuple"
        }
        return original
    }

    fun captureReceipt(original: Original, scenario: LinkConsentRecoveryScenario, ownerRole: String): JsonObject {
        scenario.requireSelector(original.operation)
        require(ownerRole in setOf("source", "target")) { "Recovery Owner side is invalid" }
        return JsonObject().apply {
            addProperty("schema", CAPTURE_SCHEMA)
            addProperty("phase", "CAPTURED")
            addProperty("run_id_sha256", digest(scenario.runId))
            addProperty("owner_role", ownerRole)
            addProperty("expected_operation", original.operation)
            addProperty("fault_mode", scenario.faultMode)
            addProperty("operation_id_sha256", original.operationIdSha256)
            addProperty("packet_sha256", original.packetSha256)
            addProperty("proof_sha256", original.proofSha256)
            addProperty("tuple_sha256", original.tupleSha256)
            addProperty("request_sequence", original.requestSequence.toString())
            addProperty("expected_response_sequence", original.expectedResponseSequence.toString())
            addProperty("next_sequence", original.nextSequence.toString())
            addProperty("last_response_sequence", original.lastResponseSequence.toString())
            addProperty("original_pending", true)
            addProperty("original_fence", true)
            addProperty("submit_network_error", "NETWORK_ERROR")
            addProperty("native_confirmed_argument", true)
            addProperty("phone_ui_confirmation_observed", false)
        }
    }

    fun verifyCaptureReceipt(
        original: Original,
        value: JsonObject,
        scenario: LinkConsentRecoveryScenario,
        ownerRole: String,
    ) {
        scenario.requireSelector(original.operation)
        require(ownerRole in setOf("source", "target")) { "Recovery Owner side is invalid" }
        val fields = setOf(
            "schema", "phase", "run_id_sha256", "owner_role", "expected_operation", "fault_mode", "operation_id_sha256",
            "packet_sha256", "proof_sha256", "tuple_sha256", "request_sequence", "expected_response_sequence",
            "next_sequence", "last_response_sequence", "original_pending", "original_fence",
            "submit_network_error", "native_confirmed_argument", "phone_ui_confirmation_observed",
        )
        require(value.keySet() == fields && string(value, "schema") == CAPTURE_SCHEMA &&
            string(value, "phase") == "CAPTURED" && string(value, "run_id_sha256") == digest(scenario.runId) &&
            string(value, "owner_role") == ownerRole &&
            string(value, "expected_operation") == original.operation && string(value, "fault_mode") == scenario.faultMode &&
            string(value, "operation_id_sha256") == original.operationIdSha256 &&
            string(value, "packet_sha256") == original.packetSha256 &&
            string(value, "proof_sha256") == original.proofSha256 && string(value, "tuple_sha256") == original.tupleSha256 &&
            decimalString(value, "request_sequence") == original.requestSequence &&
            decimalString(value, "expected_response_sequence") == original.expectedResponseSequence &&
            decimalString(value, "next_sequence") == original.nextSequence &&
            decimalString(value, "last_response_sequence") == original.lastResponseSequence &&
            boolean(value, "original_pending") && boolean(value, "original_fence") &&
            string(value, "submit_network_error") == "NETWORK_ERROR" &&
            boolean(value, "native_confirmed_argument") && !boolean(value, "phone_ui_confirmation_observed")) {
            "Immutable Link recovery capture receipt differs from the saved original request"
        }
    }

    /** Strictly validates the Core FAULT_READY receipt and exactly one later native recovery. */
    fun verifyOriginalConsentFault(
        original: Original,
        beforeRecovery: JsonObject,
        faultReceipt: JsonObject,
        afterRecovery: JsonObject,
        recoveryReceipt: JsonObject?,
        recoveryError: String?,
        scenario: LinkConsentRecoveryScenario,
        ownerRole: String,
        readyEnvelopeRaw: ByteArray = faultReceipt.toString().toByteArray(StandardCharsets.UTF_8),
    ): FaultVerification {
        scenario.requireSelector(original.operation)
        require(ownerRole in setOf("source", "target")) { "Recovery Owner side is invalid" }
        verifyOriginalBeforeRecovery(original, beforeRecovery)
        val ready = validateFaultReady(original, faultReceipt, scenario, readyEnvelopeRaw)
        val outcome = verify(original, afterRecovery, recoveryReceipt, recoveryError)
        when (scenario.faultMode) {
            "response-loss" -> require(outcome == Outcome.COMPLETED && recoveryError == null) {
                "Response-loss recovery did not complete the authenticated original response"
            }
            "processing" -> require(outcome == Outcome.PENDING && recoveryError == "STILL_PROCESSING" &&
                string(afterRecovery, "sessionError") == "STILL_PROCESSING" &&
                string(objectField(afterRecovery, "linkConsentLedger").getAsJsonObject("write_fence"), "state") == "STILL_PROCESSING") {
                "Processing recovery did not preserve the original packet under STILL_PROCESSING"
            }
            "legacy" -> require(outcome == Outcome.PENDING && recoveryError == "RECOVERY_UNAVAILABLE" &&
                string(afterRecovery, "sessionError") == "RECOVERY_UNAVAILABLE" && boolean(afterRecovery, "recoveryBlocked") &&
                string(objectField(afterRecovery, "linkConsentLedger").getAsJsonObject("write_fence"), "state") == "RECOVERY_UNAVAILABLE") {
                "Legacy recovery did not preserve and block the original packet"
            }
            "uncertain" -> require(outcome == Outcome.UNCERTAIN && recoveryError == null &&
                string(afterRecovery, "sessionError") == "OUTCOME_UNCERTAIN") {
                "Uncertain recovery did not retain the authenticated retired packet and business fence"
            }
        }
        return FaultVerification(outcome, ready, recoveryError)
    }

    /** Validate Root/Core evidence before the selector consumes the one recovery attempt. */
    fun validateReadyForRecovery(
        original: Original,
        envelope: JsonObject,
        scenario: LinkConsentRecoveryScenario,
        envelopeRaw: ByteArray = envelope.toString().toByteArray(StandardCharsets.UTF_8),
    ): FaultReady = validateFaultReady(original, envelope, scenario, envelopeRaw)

    private fun verifyOriginalBeforeRecovery(original: Original, state: JsonObject) {
        require(objectField(state, "pin") == original.pin && objectField(state, "enrollment") == original.enrollment &&
            objectField(state, "pending") == original.pending &&
            objectField(objectField(state, "linkConsentLedger"), "write_fence") == original.fence &&
            number(state, "nextSequence", 1) == original.nextSequence &&
            number(state, "lastResponseSequence", 0) == original.lastResponseSequence &&
            boolean(state, "sessionCapabilitiesReady") && !optionalBoolean(state, "authFenced") &&
            !optionalBoolean(state, "recoveryBlocked") && !optionalBoolean(state, "uncertainNeedsReconciliation")) {
            "Reloaded original pending request or consent fence differs from its immutable capture"
        }
    }

    /** Confirms an unresolved result blocks a later managed write before local state advances. */
    fun verifyBlockedMutation(before: JsonObject, after: JsonObject, errorCode: String?, mode: String): String {
        require(mode in setOf("processing", "uncertain", "legacy")) {
            "Mutation refusal check is only valid for unresolved Link outcomes"
        }
        val expected = if (mode == "uncertain") "LINK_CONSENT_RECOVERY_REQUIRED" else "PENDING_RECOVERY_REQUIRED"
        require(errorCode == expected && before == after) {
            "A new managed write was not refused before consuming or changing local request state"
        }
        return expected
    }

    private fun validateFaultReady(
        original: Original,
        envelope: JsonObject,
        scenario: LinkConsentRecoveryScenario,
        envelopeRaw: ByteArray,
    ): FaultReady {
        require(envelopeRaw.isNotEmpty() && envelopeRaw.size <= 24 * 1024) {
            "Root recovery READY envelope bytes are outside the fixed bound"
        }
        val parsedEnvelope = LinkConsentRecoveryJson.parseStrictObject(envelopeRaw, 24 * 1024)
        require(parsedEnvelope == envelope) { "Root recovery READY object differs from its exact source bytes" }
        val responseLoss = scenario.faultMode == "response-loss"
        require(envelope.keySet() == setOf(
            "schema", "run_id", "hub_source", "fault_ready_raw_base64", "fault_ready_raw_sha256", "restart",
        ) && string(envelope, "schema") == READY_SCHEMA && string(envelope, "run_id") == scenario.runId) {
            "Root recovery READY envelope is invalid"
        }
        val hubSource = objectField(envelope, "hub_source")
        require(hubSource.keySet() == setOf(
            "core_revision", "hub_image_id", "source_fingerprint", "catalog_sha256", "contract_revision", "wire_version",
        ) && string(hubSource, "core_revision") == CORE_REVISION && string(hubSource, "hub_image_id") == HUB_IMAGE_ID &&
            string(hubSource, "source_fingerprint") == SOURCE_FINGERPRINT &&
            string(hubSource, "catalog_sha256") == CATALOG_SHA256 &&
            string(hubSource, "contract_revision") == CONTRACT_REVISION && number(hubSource, "wire_version", 1) == 1L) {
            "Root recovery READY envelope is not pinned to the fixed e2 delivery"
        }
        val restart = objectField(envelope, "restart")
        require(restart.keySet() == setOf("status", "receipt_sha256")) {
            "Root recovery restart receipt fields are invalid"
        }
        val restartStatus = string(restart, "status")
        val restartReceiptSha256 = restart.get("receipt_sha256")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
            ?.asString
        if (scenario.faultMode == "uncertain") {
            require(restartStatus == "VERIFIED" && restartReceiptSha256 != null && HEX_64.matches(restartReceiptSha256)) {
                "Uncertain recovery is missing Root's verified restart receipt"
            }
        } else {
            require(restartStatus == "NOT_REQUIRED" && restart.get("receipt_sha256")?.isJsonNull == true) {
                "Root restart evidence is not valid for this non-uncertain mode"
            }
        }
        val rawBase64 = string(envelope, "fault_ready_raw_base64")
        val rawBytes = try { Base64.getDecoder().decode(rawBase64) }
        catch (_: IllegalArgumentException) { error("Raw Core FAULT_READY is not canonical base64") }
        require(rawBytes.size in 2..4096 && rawBytes.last() == '\n'.code.toByte() &&
            rawBytes.count { it == '\n'.code.toByte() } == 1 && rawBytes.none { it == '\r'.code.toByte() } &&
            Base64.getEncoder().encodeToString(rawBytes) == rawBase64 &&
            string(envelope, "fault_ready_raw_sha256") == digest(rawBytes)) {
            "Root recovery READY raw Core receipt digest does not match"
        }
        val value = LinkConsentRecoveryJson.parseStrictObject(rawBytes, 4096)
        val fields = mutableSetOf(
            "event", "mode", "operation", "request_sha256", "request_sequence",
            "request_status", "reserved_response_sequence", "business_outcome", "handler_executed", "scope",
        )
        if (responseLoss) fields += "response_sha256" else fields += "restart_required"
        require(value.keySet() == fields && string(value, "mode") == scenario.faultMode && string(value, "event") == "FAULT_READY" &&
            string(value, "operation") == original.operation &&
            string(value, "request_sha256") == original.packetSha256 &&
            number(value, "request_sequence", 1) == original.requestSequence &&
            string(value, "business_outcome") == "UNKNOWN") {
            "Core FAULT_READY receipt is not bound to the exact original Link packet"
        }
        val requestStatus = string(value, "request_status")
        val reserved = number(value, "reserved_response_sequence", 0)
        val handlerExecuted = boolean(value, "handler_executed")
        val scope = string(value, "scope")
        val responseSha = if (responseLoss) string(value, "response_sha256") else null
        if (responseSha != null) require(HEX_64.matches(responseSha)) { "Core cached response digest is invalid" }
        val restartRequired = if (responseLoss) null else boolean(value, "restart_required")
        when (scenario.faultMode) {
            "response-loss" -> require(requestStatus == "COMPLETED" &&
                reserved == original.expectedResponseSequence && handlerExecuted &&
                scope == "REAL_HANDLER_COMPLETED_TRANSPORT" && responseSha != null) {
                "Core response-loss receipt did not prove one completed real handler response"
            }
            "processing" -> require(requestStatus == "PROCESSING" && reserved == 0L && !handlerExecuted &&
                scope == "OUTER_RPC_LEDGER_ONLY" && restartRequired == false) {
                "Core processing receipt differs from the isolated outer-ledger fault"
            }
            "uncertain" -> require(requestStatus == "PROCESSING" &&
                reserved == original.expectedResponseSequence && !handlerExecuted &&
                scope == "OUTER_RPC_LEDGER_ONLY" && restartRequired == true) {
                "Core uncertain receipt differs from the externally restarted outer-ledger fault"
            }
            "legacy" -> require(requestStatus == "UNCERTAIN" && reserved == 0L && !handlerExecuted &&
                scope == "OUTER_RPC_LEDGER_ONLY" && restartRequired == false) {
                "Core legacy receipt differs from the unavailable-reservation fault"
            }
        }
        return FaultReady(scenario.faultMode, original.operation, original.packetSha256,
            original.requestSequence, requestStatus, reserved, "UNKNOWN", handlerExecuted, scope,
            responseSha, restartRequired, digest(hubSource.toString()), digest(envelopeRaw),
            string(envelope, "fault_ready_raw_sha256"), restartReceiptSha256)
    }

    fun verify(original: Original, after: JsonObject, receipt: JsonObject?, recoveryError: String?): Outcome {
        require(objectField(after, "pin") == original.pin && objectField(after, "enrollment") == original.enrollment &&
            number(after, "nextSequence", 1) == original.nextSequence) {
            "Recovery changed the enrolled context or created another request"
        }
        if (receipt != null) {
            if (receipt.has("operationId")) require(string(receipt, "operationId") == original.operationId) {
                "Recovery receipt names a different operation"
            }
            if (receipt.has("operation")) require(string(receipt, "operation") == original.operation) {
                "Recovery receipt names a different operation kind"
            }
        }
        val pending = optionalObject(after, "pending")
        val fence = optionalObject(objectField(after, "linkConsentLedger"), "write_fence")
        if (pending != null) {
            require(pending == original.pending && number(after, "lastResponseSequence", 0) == original.lastResponseSequence) {
                "Unresolved recovery changed the original pending packet or response counter"
            }
            requireOriginalFence(original, fence)
            require(recoveryError != null || (receipt != null && boolean(receipt, "reconciliationRequired"))) {
                "Pending recovery was reported as resolved"
            }
            return Outcome.PENDING
        }
        require(number(after, "lastResponseSequence", 0) == original.expectedResponseSequence) {
            "Recovery did not consume the persisted original response sequence"
        }
        if (fence != null) {
            requireOriginalFence(original, fence)
            require(string(fence, "state") == "UNCERTAIN" &&
                objectField(after, "retiredPending") == original.pending &&
                boolean(after, "uncertainNeedsReconciliation") &&
                string(after, "outcomeUncertainOperationId") == original.operationId &&
                recoveryError == null && receipt != null && boolean(receipt, "reconciliationRequired")) {
                "Uncertain recovery did not retain the original packet and business fence"
            }
            return Outcome.UNCERTAIN
        }
        // Native removes the operation ID with the resolved fence. Correlation comes
        // from the original durable packet and exact counter transition, not a new ID.
        require(recoveryError == null && receipt != null && !boolean(receipt, "reconciliationRequired") &&
            !boolean(after, "authFenced") && !boolean(after, "recoveryBlocked") &&
            !boolean(after, "uncertainNeedsReconciliation") && boolean(after, "sessionCapabilitiesReady")) {
            "Recovery is not a resolved authenticated transport outcome"
        }
        return Outcome.COMPLETED
    }

    private fun requireOriginalFence(original: Original, fence: JsonObject?) {
        require(fence != null) { "Unresolved recovery lost its original consent fence" }
        require(string(fence, "state") in setOf(
            "PENDING", "STILL_PROCESSING", "UNCERTAIN", "RECOVERY_UNAVAILABLE", "RECOVERY_REJECTED", "AUTH_REVOKED",
        )) { "Recovery fence state is invalid" }
        val expected = original.fence.deepCopy().apply { remove("state") }
        val actual = fence.deepCopy().apply { remove("state") }
        require(actual == expected) { "Unresolved recovery changed the original consent fence" }
    }

    private fun optionalObject(value: JsonObject, field: String): JsonObject? {
        val element = value.get(field) ?: return null
        require(element.isJsonObject) { "Recovery state object is invalid" }
        return element.asJsonObject
    }

    private fun objectField(value: JsonObject, field: String): JsonObject =
        optionalObject(value, field) ?: error("Recovery state object is missing")

    private fun string(value: JsonObject, field: String): String = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?.takeIf { it.isNotBlank() } ?: error("Recovery string field is invalid")

    private fun optionalString(value: JsonObject, field: String): String? {
        val element = value.get(field) ?: return null
        require(element.isJsonPrimitive && element.asJsonPrimitive.isString) { "Recovery string field is invalid" }
        return element.asString
    }

    private fun number(value: JsonObject, field: String, minimum: Long): Long {
        val token = value.get(field)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
            ?: error("Recovery integer field is invalid")
        require(token.matches(Regex("0|[1-9][0-9]*"))) { "Recovery integer field is invalid" }
        return token.toLongOrNull()?.takeIf { it >= minimum } ?: error("Recovery integer field is out of range")
    }

    private fun decimalString(value: JsonObject, field: String): Long {
        val token = string(value, field)
        require(token.matches(Regex("0|[1-9][0-9]*"))) { "Recovery decimal counter is invalid" }
        return token.toLongOrNull() ?: error("Recovery decimal counter is out of range")
    }

    private fun boolean(value: JsonObject, field: String): Boolean = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
        ?: error("Recovery boolean field is invalid")

    private fun optionalBoolean(value: JsonObject, field: String): Boolean {
        val element = value.get(field) ?: return false
        require(element.isJsonPrimitive && element.asJsonPrimitive.isBoolean) { "Recovery boolean field is invalid" }
        return element.asBoolean
    }

    private fun digest(value: String): String = digest(value.toByteArray(StandardCharsets.UTF_8))

    private fun digest(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 255) }
}

/** Strict test-only JSON reader: rejects duplicate keys, trailing values and lenient syntax. */
internal object LinkConsentRecoveryJson {
    fun parseStrictObject(raw: ByteArray, maximumBytes: Int): JsonObject {
        require(raw.isNotEmpty() && raw.size <= maximumBytes) { "Bounded strict JSON bytes are required" }
        val decoded = try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
        } catch (_: Exception) { error("Strict JSON bytes are not valid UTF-8") }
        val reader = JsonReader(StringReader(decoded)).apply { strictness = Strictness.STRICT }
        val value = try {
            readValue(reader, 0).also {
                require(reader.peek() == JsonToken.END_DOCUMENT) { "Strict JSON has trailing values" }
            }
        } finally {
            reader.close()
        }
        require(value.isJsonObject) { "Strict JSON root must be an object" }
        return value.asJsonObject
    }

    private fun readValue(reader: JsonReader, depth: Int): JsonElement {
        require(depth <= 12) { "Strict JSON nesting exceeds the fixed bound" }
        return when (reader.peek()) {
            JsonToken.BEGIN_OBJECT -> JsonObject().apply {
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    require(!has(name)) { "Strict JSON contains a duplicate field" }
                    add(name, readValue(reader, depth + 1))
                }
                reader.endObject()
            }
            JsonToken.BEGIN_ARRAY -> com.google.gson.JsonArray().apply {
                reader.beginArray()
                while (reader.hasNext()) add(readValue(reader, depth + 1))
                reader.endArray()
            }
            JsonToken.STRING -> JsonPrimitive(reader.nextString())
            JsonToken.NUMBER -> JsonPrimitive(LexicalNumber(reader.nextString()))
            JsonToken.BOOLEAN -> JsonPrimitive(reader.nextBoolean())
            JsonToken.NULL -> JsonNull.INSTANCE.also { reader.nextNull() }
            else -> error("Strict JSON value is malformed")
        }
    }

    private class LexicalNumber(private val token: String) : Number() {
        override fun toByte(): Byte = token.toByte()
        override fun toShort(): Short = token.toShort()
        override fun toInt(): Int = token.toInt()
        override fun toLong(): Long = token.toLong()
        override fun toFloat(): Float = token.toFloat()
        override fun toDouble(): Double = token.toDouble()
        override fun toString(): String = token
    }
}
