package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Synthetic persisted-state cases only; this never authenticates Hub crypto or proves a grant. */
private data class RecoveryFixture(
    val before: JsonObject,
    val original: LinkConsentRecoveryEvidence.Original,
    val packet: String,
    val proof: String,
)

private const val OPERATION = "link.key_grant"
private const val OPERATION_ID = "synthetic_operation_a"
private const val HUB_ID = "synthetic_hub_a"
private const val OWNER_ID = "synthetic_owner_a"
private const val DEVICE_ID = "synthetic_device_a"
private const val REQUEST_SEQUENCE = 41L
private const val RESPONSE_SEQUENCE = 90L
private const val LAST_RESPONSE_SEQUENCE = RESPONSE_SEQUENCE - 1

private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
    .digest(value.toByteArray(StandardCharsets.UTF_8))
    .joinToString("") { "%02x".format(it.toInt() and 255) }

private fun obj(value: JsonObject, field: String): JsonObject = value.getAsJsonObject(field)

private fun expectRejected(action: () -> Unit) {
    check(runCatching(action).isFailure) { "Malformed or uncorrelated recovery evidence was accepted" }
}

private fun fixture(): RecoveryFixture {
    val proof = "{\"synthetic_public_test_proof\":true}"
    val packet = """{"route":{"operation":"$OPERATION","operation_id":"$OPERATION_ID","sequence":$REQUEST_SEQUENCE,"hub_id":"$HUB_ID","owner_id":"$OWNER_ID","device_id":"$DEVICE_ID","session_epoch":7},"ciphertext":"synthetic"}"""
    val state = JsonObject().apply {
        add("pin", JsonObject().apply { addProperty("hubId", HUB_ID) })
        add("enrollment", JsonObject().apply {
            addProperty("ownerId", OWNER_ID)
            addProperty("deviceId", DEVICE_ID)
            addProperty("sessionEpoch", 7)
        })
        addProperty("nextSequence", REQUEST_SEQUENCE + 1)
        addProperty("lastResponseSequence", LAST_RESPONSE_SEQUENCE)
        add("pending", JsonObject().apply {
            addProperty("operation", OPERATION)
            addProperty("operationId", OPERATION_ID)
            addProperty("sequence", REQUEST_SEQUENCE)
            addProperty("expectedResponseSequence", RESPONSE_SEQUENCE)
            addProperty("packetJson", packet)
        })
        add("linkConsentLedger", JsonObject().apply {
            add("write_fence", JsonObject().apply {
                addProperty("operation", OPERATION)
                addProperty("operation_id", OPERATION_ID)
                addProperty("request_sequence", REQUEST_SEQUENCE)
                addProperty("expected_response_sequence", RESPONSE_SEQUENCE)
                addProperty("packet_json", packet)
                addProperty("packet_sha256", sha256(packet))
                addProperty("signed_proof_json", proof)
                addProperty("signed_proof_sha256", sha256(proof))
                addProperty("state", "PENDING")
            })
        })
    }
    return RecoveryFixture(state, LinkConsentRecoveryEvidence.capture(state, OPERATION), packet, proof)
}

private fun completedState(fixture: RecoveryFixture): JsonObject = fixture.before.deepCopy().apply {
    remove("pending")
    addProperty("lastResponseSequence", RESPONSE_SEQUENCE)
    addProperty("sessionCapabilitiesReady", true)
    addProperty("authFenced", false)
    addProperty("recoveryBlocked", false)
    addProperty("uncertainNeedsReconciliation", false)
    obj(this, "linkConsentLedger").remove("write_fence")
}

private fun receipt(reconciliationRequired: Boolean): JsonObject = JsonObject().apply {
    addProperty("reconciliationRequired", reconciliationRequired)
}

private fun replaceRouteField(state: JsonObject, field: String, value: String) {
    val pending = obj(state, "pending")
    val packetObject = JsonParser.parseString(pending.get("packetJson").asString).asJsonObject
    obj(packetObject, "route").addProperty(field, value)
    val packet = packetObject.toString()
    pending.addProperty("packetJson", packet)
    obj(obj(state, "linkConsentLedger"), "write_fence").apply {
        addProperty("packet_json", packet)
        addProperty("packet_sha256", sha256(packet))
    }
}

private fun replaceRouteSequence(state: JsonObject, sequence: Long) {
    val pending = obj(state, "pending")
    val packetObject = JsonParser.parseString(pending.get("packetJson").asString).asJsonObject
    obj(packetObject, "route").addProperty("sequence", sequence)
    val packet = packetObject.toString()
    pending.addProperty("packetJson", packet)
    obj(obj(state, "linkConsentLedger"), "write_fence").apply {
        addProperty("packet_json", packet)
        addProperty("packet_sha256", sha256(packet))
    }
}

private fun replaceRouteNumber(state: JsonObject, field: String, value: Long) {
    val pending = obj(state, "pending")
    val packetObject = JsonParser.parseString(pending.get("packetJson").asString).asJsonObject
    obj(packetObject, "route").addProperty(field, value)
    val packet = packetObject.toString()
    pending.addProperty("packetJson", packet)
    obj(obj(state, "linkConsentLedger"), "write_fence").apply {
        addProperty("packet_json", packet)
        addProperty("packet_sha256", sha256(packet))
    }
}

private fun captureBindsExactOriginalPacketAndEnrolledRoute() {
    val f = fixture()
    check(f.original.operation == OPERATION)
    check(f.original.operationId == OPERATION_ID)
    check(f.original.requestSequence == REQUEST_SEQUENCE)
    check(f.original.expectedResponseSequence == RESPONSE_SEQUENCE)
    check(f.original.packetSha256 == sha256(f.packet))
    check(f.original.pending.get("packetJson").asString == f.packet)
    check(f.original.fence.get("signed_proof_sha256").asString == sha256(f.proof))

    val invalidCaptures = listOf<(JsonObject) -> Unit>(
        { obj(it, "pending").addProperty("operation", "status.snapshot") },
        { replaceRouteField(it, "operation", "status.snapshot") },
        { replaceRouteField(it, "operation_id", "different_operation") },
        { replaceRouteSequence(it, REQUEST_SEQUENCE + 1) },
        { replaceRouteField(it, "hub_id", "different_hub") },
        { replaceRouteField(it, "owner_id", "different_owner") },
        { replaceRouteField(it, "device_id", "different_device") },
        { replaceRouteNumber(it, "session_epoch", 8) },
        { obj(it, "pin").addProperty("hubId", "different_hub") },
        { obj(it, "enrollment").addProperty("ownerId", "different_owner") },
        { obj(it, "enrollment").addProperty("deviceId", "different_device") },
        { obj(it, "enrollment").addProperty("sessionEpoch", 8) },
        { it.addProperty("nextSequence", REQUEST_SEQUENCE + 2) },
        { it.addProperty("lastResponseSequence", LAST_RESPONSE_SEQUENCE - 1) },
        { obj(it, "pending").addProperty("expectedResponseSequence", RESPONSE_SEQUENCE + 1) },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("packet_sha256", "0".repeat(64)) },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("signed_proof_sha256", "0".repeat(64)) },
    )
    for (mutate in invalidCaptures) {
        val bad = f.before.deepCopy()
        mutate(bad)
        expectRejected { LinkConsentRecoveryEvidence.capture(bad, OPERATION) }
    }
    expectRejected { LinkConsentRecoveryEvidence.capture(f.before, "status.snapshot") }
}

private fun onlyCorrelatedResolvedTransportResultIsCompleted() {
    val f = fixture()
    val after = completedState(f)
    // Resolution removes the pending/fence operation id; the durable original packet
    // and exact response counter provide correlation for this synthetic helper case.
    val noOptionalOperationId = receipt(false)
    check(!noOptionalOperationId.has("operationId"))
    check(LinkConsentRecoveryEvidence.verify(f.original, after, noOptionalOperationId, null) ==
        LinkConsentRecoveryEvidence.Outcome.COMPLETED)

    val wrongReceipts = listOf(
        receipt(false).apply { addProperty("operationId", "different_operation") },
        receipt(false).apply { addProperty("operation", "link.review_policy_grant") },
    )
    for (wrong in wrongReceipts) {
        expectRejected { LinkConsentRecoveryEvidence.verify(f.original, after, wrong, null) }
    }

    val invalidResolvedStates = listOf<(JsonObject) -> Unit>(
        { it.addProperty("lastResponseSequence", RESPONSE_SEQUENCE + 1) },
        { it.addProperty("nextSequence", REQUEST_SEQUENCE + 2) },
        { it.addProperty("authFenced", true) },
        { it.addProperty("recoveryBlocked", true) },
        { it.addProperty("uncertainNeedsReconciliation", true) },
        { it.addProperty("sessionCapabilitiesReady", false) },
        { it.addProperty("sessionCapabilitiesReady", "true") },
    )
    for (mutate in invalidResolvedStates) {
        val bad = after.deepCopy()
        mutate(bad)
        expectRejected { LinkConsentRecoveryEvidence.verify(f.original, bad, receipt(false), null) }
    }
    expectRejected { LinkConsentRecoveryEvidence.verify(f.original, after, receipt(true), null) }
    expectRejected {
        LinkConsentRecoveryEvidence.verify(f.original, after,
            JsonObject().apply { addProperty("reconciliationRequired", "false") }, null)
    }
    expectRejected { LinkConsentRecoveryEvidence.verify(f.original, after, receipt(false), "RECOVERY_REJECTED") }
    val changedEnrolledOwner = after.deepCopy().apply { obj(this, "enrollment").addProperty("ownerId", "different_owner") }
    expectRejected { LinkConsentRecoveryEvidence.verify(f.original, changedEnrolledOwner, receipt(false), null) }
}

private fun processingUnavailableAndUncertainStayFenced() {
    val f = fixture()
    for ((fenceState, error) in listOf(
        "STILL_PROCESSING" to "STILL_PROCESSING",
        "RECOVERY_UNAVAILABLE" to "RECOVERY_UNAVAILABLE",
        "RECOVERY_REJECTED" to "RECOVERY_REJECTED",
        "AUTH_REVOKED" to "RPC_HTTP_403",
    )) {
        val after = f.before.deepCopy().apply {
            obj(obj(this, "linkConsentLedger"), "write_fence").addProperty("state", fenceState)
        }
        check(LinkConsentRecoveryEvidence.verify(f.original, after, null, error) ==
            LinkConsentRecoveryEvidence.Outcome.PENDING)
    }

    val stillPending = f.before.deepCopy()
    obj(obj(stillPending, "linkConsentLedger"), "write_fence").addProperty("state", "STILL_PROCESSING")
    check(LinkConsentRecoveryEvidence.verify(f.original, stillPending, receipt(true), null) ==
        LinkConsentRecoveryEvidence.Outcome.PENDING)

    val uncertain = f.before.deepCopy().apply {
        remove("pending")
        add("retiredPending", f.original.pending.deepCopy())
        addProperty("lastResponseSequence", RESPONSE_SEQUENCE)
        addProperty("uncertainNeedsReconciliation", true)
        addProperty("outcomeUncertainOperationId", OPERATION_ID)
        obj(obj(this, "linkConsentLedger"), "write_fence").addProperty("state", "UNCERTAIN")
    }
    check(LinkConsentRecoveryEvidence.verify(f.original, uncertain, receipt(true), null) ==
        LinkConsentRecoveryEvidence.Outcome.UNCERTAIN)
    expectRejected { LinkConsentRecoveryEvidence.verify(f.original, uncertain, receipt(false), null) }

    val invalidFencedStates = listOf<(JsonObject) -> Unit>(
        { obj(it, "pending").addProperty("packetJson", "different_packet") },
        { obj(it, "pending").addProperty("sequence", REQUEST_SEQUENCE + 1) },
        { obj(it, "pending").addProperty("operationId", "different_operation") },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("packet_json", "different_packet") },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("packet_sha256", "0".repeat(64)) },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("request_sequence", REQUEST_SEQUENCE + 1) },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("expected_response_sequence", RESPONSE_SEQUENCE + 1) },
        { obj(obj(it, "linkConsentLedger"), "write_fence").addProperty("signed_proof_json", "different_proof") },
        { it.addProperty("lastResponseSequence", RESPONSE_SEQUENCE) },
        { it.addProperty("nextSequence", REQUEST_SEQUENCE + 2) },
    )
    for (mutate in invalidFencedStates) {
        val bad = f.before.deepCopy()
        obj(obj(bad, "linkConsentLedger"), "write_fence").addProperty("state", "STILL_PROCESSING")
        mutate(bad)
        expectRejected { LinkConsentRecoveryEvidence.verify(f.original, bad, receipt(true), null) }
    }

    val wrongRetiredPacket = uncertain.deepCopy().apply {
        obj(this, "retiredPending").addProperty("packetJson", "different_packet")
    }
    expectRejected { LinkConsentRecoveryEvidence.verify(f.original, wrongRetiredPacket, receipt(true), null) }
    val wrongUncertainId = uncertain.deepCopy().apply { addProperty("outcomeUncertainOperationId", "different_operation") }
    expectRejected { LinkConsentRecoveryEvidence.verify(f.original, wrongUncertainId, receipt(true), null) }
}

fun main() {
    captureBindsExactOriginalPacketAndEnrolledRoute()
    onlyCorrelatedResolvedTransportResultIsCompleted()
    processingUnavailableAndUncertainStayFenced()
    println("LinkConsentRecoveryEvidenceRegression: PASS (3 groups; synthetic helper cases only)")
}
