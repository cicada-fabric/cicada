package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Test-only persisted-state checks; these do not authenticate a Hub response. */
internal object LinkConsentRecoveryEvidence {
    enum class Outcome { COMPLETED, PENDING, UNCERTAIN }

    class Original internal constructor(
        val operation: String,
        val operationId: String,
        val requestSequence: Long,
        val expectedResponseSequence: Long,
        val packetSha256: String,
        internal val pending: JsonObject,
        internal val fence: JsonObject,
        internal val pin: JsonObject,
        internal val enrollment: JsonObject,
        internal val nextSequence: Long,
        internal val lastResponseSequence: Long,
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
        return Original(expectedOperation, operationId, sequence, responseSequence, packetHash,
            pending.deepCopy(), fence.deepCopy(), pin.deepCopy(), enrollment.deepCopy(),
            nextSequence, lastResponseSequence)
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

    private fun number(value: JsonObject, field: String, minimum: Long): Long {
        val token = value.get(field)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
            ?: error("Recovery integer field is invalid")
        require(token.matches(Regex("0|[1-9][0-9]*"))) { "Recovery integer field is invalid" }
        return token.toLongOrNull()?.takeIf { it >= minimum } ?: error("Recovery integer field is out of range")
    }

    private fun boolean(value: JsonObject, field: String): Boolean = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
        ?: error("Recovery boolean field is invalid")

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
}
