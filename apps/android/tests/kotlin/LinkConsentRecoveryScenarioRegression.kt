package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Synthetic selector, Root-envelope, Core-event, and persisted-state cases only. */
private const val RUN_ID = "v164-link-recovery-regression"
private const val OPERATION_ID = "synthetic_original_operation"
private const val HUB_ID = "synthetic_hub"
private const val OWNER_ID = "synthetic_owner"
private const val DEVICE_ID = "synthetic_device"
private const val REQUEST_SEQUENCE = 41L
private const val RESPONSE_SEQUENCE = 90L
private const val LAST_RESPONSE_SEQUENCE = RESPONSE_SEQUENCE - 1

private data class RecoveryCase(
    val operation: String,
    val mode: String,
    val before: JsonObject,
    val original: LinkConsentRecoveryEvidence.Original,
    val scenario: LinkConsentRecoveryScenario,
    val captureReceipt: JsonObject,
)

private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(value).joinToString("") { "%02x".format(it.toInt() and 255) }

private fun sha256(value: String): String = sha256(value.toByteArray(StandardCharsets.UTF_8))

private fun objectAt(value: JsonObject, field: String): JsonObject = value.getAsJsonObject(field)

private fun expectRejected(block: () -> Unit) {
    check(runCatching(block).isFailure) { "Malformed Link recovery evidence was accepted" }
}

private fun scenario(operation: String, mode: String): LinkConsentRecoveryScenario =
    LinkConsentRecoveryScenario.parse(JsonObject().apply {
        addProperty("schema", LinkConsentRecoveryScenario.SCHEMA)
        addProperty("run_id", RUN_ID)
        addProperty("expected_operation", operation)
        addProperty("fault_mode", mode)
    }, RUN_ID)

private fun fixture(operation: String, mode: String, ownerRole: String = "source"): RecoveryCase {
    val operationId = "$OPERATION_ID-${operation.substringAfterLast('.')}-${ownerRole}"
    val tuple = JsonObject().apply {
        addProperty("profile_id", "synthetic_profile")
        addProperty("profile_generation", 3)
        addProperty("hub_id", HUB_ID)
        addProperty("owner_id", OWNER_ID)
        addProperty("device_id", DEVICE_ID)
        addProperty("link_id", "synthetic_link")
        addProperty("link_version", 5)
        addProperty("local_side", if (ownerRole == "source") "SOURCE" else "TARGET")
        addProperty("kind", if (operation == "link.key_grant") "KEY" else "REVIEW_POLICY")
    }
    val tupleHash = sha256(tuple.toString())
    val proof = "{\"synthetic_external_owner_proof\":true}"
    val route = JsonObject().apply {
        addProperty("operation", operation)
        addProperty("operation_id", operationId)
        addProperty("sequence", REQUEST_SEQUENCE)
        addProperty("hub_id", HUB_ID)
        addProperty("owner_id", OWNER_ID)
        addProperty("device_id", DEVICE_ID)
        addProperty("session_epoch", 7)
    }
    val packet = JsonObject().apply {
        add("route", route)
        addProperty("synthetic_ciphertext", "not-a-real-packet")
    }.toString()
    val packetHash = sha256(packet)
    val proofHash = sha256(proof)
    val pending = JsonObject().apply {
        addProperty("operation", operation)
        addProperty("operationId", operationId)
        addProperty("sequence", REQUEST_SEQUENCE)
        addProperty("expectedResponseSequence", RESPONSE_SEQUENCE)
        addProperty("packetJson", packet)
    }
    val fence = JsonObject().apply {
        addProperty("operation", operation)
        addProperty("operation_id", operationId)
        addProperty("request_sequence", REQUEST_SEQUENCE)
        addProperty("expected_response_sequence", RESPONSE_SEQUENCE)
        addProperty("signed_proof_json", proof)
        addProperty("signed_proof_sha256", proofHash)
        addProperty("packet_json", packet)
        addProperty("packet_sha256", packetHash)
        addProperty("review_id", "synthetic_review")
        addProperty("consent_digest", "1".repeat(64))
        addProperty("tuple_digest", tupleHash)
        addProperty("state", "PENDING")
    }
    val before = JsonObject().apply {
        add("pin", JsonObject().apply { addProperty("hubId", HUB_ID) })
        add("enrollment", JsonObject().apply {
            addProperty("ownerId", OWNER_ID)
            addProperty("deviceId", DEVICE_ID)
            addProperty("sessionEpoch", 7)
        })
        addProperty("nextSequence", REQUEST_SEQUENCE + 1)
        addProperty("lastResponseSequence", LAST_RESPONSE_SEQUENCE)
        addProperty("sessionCapabilitiesReady", true)
        addProperty("authFenced", false)
        addProperty("recoveryBlocked", false)
        addProperty("uncertainNeedsReconciliation", false)
        add("pending", pending)
        add("linkConsentLedger", JsonObject().apply {
            add("review", JsonObject().apply { add("tuple", tuple) })
            add("write_fence", fence)
        })
    }
    val selectedScenario = scenario(operation, mode)
    val original = LinkConsentRecoveryEvidence.captureOriginalConsentFault(before, operation)
    return RecoveryCase(operation, mode, before, original, selectedScenario,
        LinkConsentRecoveryEvidence.captureReceipt(original, selectedScenario, ownerRole))
}

private fun rawFaultReady(test: RecoveryCase): JsonObject {
    val loss = test.mode == "response-loss"
    val raw = JsonObject().apply {
        addProperty("event", "FAULT_READY")
        addProperty("mode", test.mode)
        addProperty("operation", test.operation)
        addProperty("request_sha256", test.original.packetSha256)
        addProperty("request_sequence", test.original.requestSequence)
        addProperty("request_status", when (test.mode) {
            "response-loss" -> "COMPLETED"
            "legacy" -> "UNCERTAIN"
            else -> "PROCESSING"
        })
        addProperty("reserved_response_sequence", when (test.mode) {
            "response-loss", "uncertain" -> test.original.expectedResponseSequence
            else -> 0
        })
        addProperty("business_outcome", "UNKNOWN")
        addProperty("handler_executed", loss)
        addProperty("scope", if (loss) "REAL_HANDLER_COMPLETED_TRANSPORT" else "OUTER_RPC_LEDGER_ONLY")
        if (loss) addProperty("response_sha256", "a".repeat(64))
        else addProperty("restart_required", test.mode == "uncertain")
    }.toString() + "\n"
    val rawBytes = raw.toByteArray(StandardCharsets.UTF_8)
    return JsonObject().apply {
        addProperty("schema", LinkConsentRecoveryEvidence.READY_SCHEMA)
        addProperty("run_id", RUN_ID)
        add("hub_source", JsonObject().apply {
            addProperty("core_revision", LinkConsentRecoveryEvidence.CORE_REVISION)
            addProperty("hub_image_id", LinkConsentRecoveryEvidence.HUB_IMAGE_ID)
            addProperty("source_fingerprint", LinkConsentRecoveryEvidence.SOURCE_FINGERPRINT)
            addProperty("catalog_sha256", LinkConsentRecoveryEvidence.CATALOG_SHA256)
            addProperty("contract_revision", LinkConsentRecoveryEvidence.CONTRACT_REVISION)
            addProperty("wire_version", 1)
        })
        addProperty("fault_ready_raw_base64", Base64.getEncoder().encodeToString(rawBytes))
        addProperty("fault_ready_raw_sha256", sha256(rawBytes))
        add("restart", JsonObject().apply {
            if (test.mode == "uncertain") {
                addProperty("status", "VERIFIED")
                addProperty("receipt_sha256", "b".repeat(64))
            } else {
                addProperty("status", "NOT_REQUIRED")
                add("receipt_sha256", com.google.gson.JsonNull.INSTANCE)
            }
        })
    }
}

private fun recoveredState(test: RecoveryCase): Pair<JsonObject, JsonObject?> {
    val after = test.before.deepCopy()
    val ledger = objectAt(after, "linkConsentLedger")
    val recovery = when (test.mode) {
        "response-loss" -> {
            after.remove("pending")
            after.addProperty("lastResponseSequence", test.original.expectedResponseSequence)
            ledger.remove("write_fence")
            JsonObject().apply { addProperty("reconciliationRequired", false) }
        }
        "processing" -> {
            objectAt(ledger, "write_fence").addProperty("state", "STILL_PROCESSING")
            after.addProperty("sessionError", "STILL_PROCESSING")
            null
        }
        "legacy" -> {
            objectAt(ledger, "write_fence").addProperty("state", "RECOVERY_UNAVAILABLE")
            after.addProperty("recoveryBlocked", true)
            after.addProperty("sessionError", "RECOVERY_UNAVAILABLE")
            null
        }
        "uncertain" -> {
            after.remove("pending")
            after.add("retiredPending", test.original.pending.deepCopy())
            after.addProperty("lastResponseSequence", test.original.expectedResponseSequence)
            after.addProperty("uncertainNeedsReconciliation", true)
            after.addProperty("outcomeUncertainOperationId", test.original.operationId)
            after.addProperty("sessionError", "OUTCOME_UNCERTAIN")
            objectAt(ledger, "write_fence").addProperty("state", "UNCERTAIN")
            JsonObject().apply {
                addProperty("operationId", test.original.operationId)
                addProperty("operation", test.operation)
                addProperty("reconciliationRequired", true)
            }
        }
        else -> error("Unknown recovery mode")
    }
    return after to recovery
}

private fun strictScenarioSchemaAndSelectorMatrix() {
    for (operation in LinkConsentRecoveryScenario.OPERATIONS) {
        for (mode in LinkConsentRecoveryScenario.MODES) {
            val valid = JsonObject().apply {
                addProperty("schema", LinkConsentRecoveryScenario.SCHEMA)
                addProperty("run_id", RUN_ID)
                addProperty("expected_operation", operation)
                addProperty("fault_mode", mode)
            }
            val parsed = LinkConsentRecoveryScenario.parse(valid, RUN_ID)
            parsed.requireSelector(operation, mode)
            expectRejected {
                LinkConsentRecoveryScenario.parse(valid.deepCopy().apply { addProperty("extra", true) }, RUN_ID)
            }
            expectRejected { LinkConsentRecoveryScenario.parse(valid, "v164-other-run") }
            expectRejected {
                LinkConsentRecoveryScenario.parse(valid.deepCopy().apply { addProperty("fault_mode", "retry") }, RUN_ID)
            }
            val otherMode = if (mode == "legacy") "uncertain" else "legacy"
            expectRejected { parsed.requireSelector(operation, otherMode) }
            if (operation == "link.key_grant") {
                expectRejected { parsed.requireSelector("link.review_policy_grant", mode) }
            }
        }
    }
}

private fun allEightFaultCasesBindOriginalAndNativeOutcome() {
    for (operation in LinkConsentRecoveryScenario.OPERATIONS) {
        for (mode in LinkConsentRecoveryScenario.MODES) {
            val test = fixture(operation, mode, if (operation == "link.key_grant") "source" else "target")
            LinkConsentRecoveryEvidence.verifyCaptureReceipt(test.original, test.captureReceipt,
                test.scenario, if (operation == "link.key_grant") "source" else "target")
            val (after, recovery) = recoveredState(test)
            val error = when (mode) {
                "processing" -> "STILL_PROCESSING"
                "legacy" -> "RECOVERY_UNAVAILABLE"
                else -> null
            }
            val result = LinkConsentRecoveryEvidence.verifyOriginalConsentFault(
                test.original, test.before, rawFaultReady(test), after, recovery, error,
                test.scenario, if (operation == "link.key_grant") "source" else "target",
            )
            val expected = when (mode) {
                "response-loss" -> LinkConsentRecoveryEvidence.Outcome.COMPLETED
                "uncertain" -> LinkConsentRecoveryEvidence.Outcome.UNCERTAIN
                else -> LinkConsentRecoveryEvidence.Outcome.PENDING
            }
            check(result.outcome == expected && result.faultReady.mode == mode)
            if (mode != "response-loss") {
                val blockedCode = if (mode == "uncertain") "LINK_CONSENT_RECOVERY_REQUIRED" else "PENDING_RECOVERY_REQUIRED"
                check(LinkConsentRecoveryEvidence.verifyBlockedMutation(after, after.deepCopy(), blockedCode, mode) == blockedCode)
                expectRejected { LinkConsentRecoveryEvidence.verifyBlockedMutation(after, after.deepCopy(), null, mode) }
                expectRejected {
                    LinkConsentRecoveryEvidence.verifyBlockedMutation(after, after.deepCopy().apply {
                        addProperty("nextSequence", REQUEST_SEQUENCE + 2)
                    }, blockedCode, mode)
                }
            }
            val serializedCapture = test.captureReceipt.toString()
            check(!serializedCapture.contains(test.original.operationId) &&
                !serializedCapture.contains(test.original.pending.get("packetJson").asString) &&
                !serializedCapture.contains(test.original.fence.get("signed_proof_json").asString))
        }
    }
}

private fun readyEnvelopeAndCoreFieldsFailClosed() {
    val test = fixture("link.key_grant", "response-loss")
    val good = rawFaultReady(test)
    val goodAfter = recoveredState(test).first
    val prettyEnvelopeBytes = ("\n  " + good.toString() + "  \n").toByteArray(StandardCharsets.UTF_8)
    val verifiedReady = LinkConsentRecoveryEvidence.validateReadyForRecovery(
        test.original, good, test.scenario, prettyEnvelopeBytes,
    )
    check(verifiedReady.readyEnvelopeSha256 == sha256(prettyEnvelopeBytes)) {
        "READY envelope receipt must bind exact staged bytes, not a reserialized object"
    }
    expectRejected {
        LinkConsentRecoveryEvidence.validateReadyForRecovery(
            test.original, good, test.scenario, "different bytes".toByteArray(StandardCharsets.UTF_8),
        )
    }
    val duplicateEnvelopeBytes = good.toString().replaceFirst("\"schema\":", "\"schema\":\"duplicate\",\"schema\":")
        .toByteArray(StandardCharsets.UTF_8)
    expectRejected {
        LinkConsentRecoveryEvidence.validateReadyForRecovery(
            test.original, good, test.scenario, duplicateEnvelopeBytes,
        )
    }
    expectRejected {
        LinkConsentRecoveryEvidence.verifyOriginalConsentFault(test.original, test.before,
            good.deepCopy().apply { addProperty("unexpected", true) }, goodAfter,
            JsonObject().apply { addProperty("reconciliationRequired", false) }, null, test.scenario, "source")
    }
    val wrongEnvelopeDigest = good.deepCopy().apply { addProperty("fault_ready_raw_sha256", "0".repeat(64)) }
    expectRejected {
        LinkConsentRecoveryEvidence.verifyOriginalConsentFault(test.original, test.before,
            wrongEnvelopeDigest, goodAfter, JsonObject().apply { addProperty("reconciliationRequired", false) },
            null, test.scenario, "source")
    }
    val wrongHub = good.deepCopy().apply {
        objectAt(this, "hub_source").addProperty("hub_image_id", "sha256:" + "0".repeat(64))
    }
    expectRejected {
        LinkConsentRecoveryEvidence.verifyOriginalConsentFault(test.original, test.before,
            wrongHub, goodAfter, JsonObject().apply { addProperty("reconciliationRequired", false) },
            null, test.scenario, "source")
    }
    val rawBytes = Base64.getDecoder().decode(good.get("fault_ready_raw_base64").asString)
    val normalEvent = String(rawBytes, StandardCharsets.UTF_8).removeSuffix("\n")
    val duplicateCoreEvent = normalEvent.replaceFirst(
        "\"event\":\"FAULT_READY\"", "\"event\":\"OTHER\",\"event\":\"FAULT_READY\"",
    ) + "\n"
    val duplicateCoreBytes = duplicateCoreEvent.toByteArray(StandardCharsets.UTF_8)
    val duplicateCore = good.deepCopy().apply {
        addProperty("fault_ready_raw_base64", Base64.getEncoder().encodeToString(duplicateCoreBytes))
        addProperty("fault_ready_raw_sha256", sha256(duplicateCoreBytes))
    }
    expectRejected {
        LinkConsentRecoveryEvidence.validateReadyForRecovery(test.original, duplicateCore, test.scenario)
    }
    val floatSequenceEvent = normalEvent.replaceFirst("\"request_sequence\":41", "\"request_sequence\":41.0") + "\n"
    val floatSequenceBytes = floatSequenceEvent.toByteArray(StandardCharsets.UTF_8)
    val floatSequence = good.deepCopy().apply {
        addProperty("fault_ready_raw_base64", Base64.getEncoder().encodeToString(floatSequenceBytes))
        addProperty("fault_ready_raw_sha256", sha256(floatSequenceBytes))
    }
    expectRejected {
        LinkConsentRecoveryEvidence.validateReadyForRecovery(test.original, floatSequence, test.scenario)
    }
    val changedRaw = JsonParser.parseString(String(rawBytes, StandardCharsets.UTF_8)).asJsonObject
        .apply { addProperty("request_status", "PROCESSING") }
    val changedBytes = (changedRaw.toString() + "\n").toByteArray(StandardCharsets.UTF_8)
    val wrongStatus = good.deepCopy().apply {
        addProperty("fault_ready_raw_base64", Base64.getEncoder().encodeToString(changedBytes))
        addProperty("fault_ready_raw_sha256", sha256(changedBytes))
    }
    expectRejected {
        LinkConsentRecoveryEvidence.verifyOriginalConsentFault(test.original, test.before,
            wrongStatus, goodAfter, JsonObject().apply { addProperty("reconciliationRequired", false) },
            null, test.scenario, "source")
    }
    val uncertain = fixture("link.review_policy_grant", "uncertain", "target")
    val wrongRestart = rawFaultReady(uncertain).apply {
        objectAt(this, "restart").addProperty("status", "NOT_REQUIRED")
        objectAt(this, "restart").add("receipt_sha256", com.google.gson.JsonNull.INSTANCE)
    }
    val (uncertainAfter, uncertainReceipt) = recoveredState(uncertain)
    expectRejected {
        LinkConsentRecoveryEvidence.verifyOriginalConsentFault(uncertain.original, uncertain.before,
            wrongRestart, uncertainAfter, uncertainReceipt, null, uncertain.scenario, "target")
    }
}

private fun captureReceiptIsImmutableAndOwnerBound() {
    val test = fixture("link.key_grant", "legacy", "source")
    LinkConsentRecoveryEvidence.verifyCaptureReceipt(test.original, test.captureReceipt, test.scenario, "source")
    expectRejected {
        LinkConsentRecoveryEvidence.verifyCaptureReceipt(test.original, test.captureReceipt, test.scenario, "target")
    }
    expectRejected {
        LinkConsentRecoveryEvidence.verifyCaptureReceipt(test.original,
            test.captureReceipt.deepCopy().apply { addProperty("raw_packet", "forbidden") }, test.scenario, "source")
    }
    val alteredState = test.before.deepCopy().apply {
        objectAt(objectAt(this, "linkConsentLedger"), "write_fence").addProperty("tuple_digest", "0".repeat(64))
    }
    expectRejected { LinkConsentRecoveryEvidence.captureOriginalConsentFault(alteredState, test.operation) }
}

fun main() {
    strictScenarioSchemaAndSelectorMatrix()
    allEightFaultCasesBindOriginalAndNativeOutcome()
    readyEnvelopeAndCoreFieldsFailClosed()
    captureReceiptIsImmutableAndOwnerBound()
    println("LinkConsentRecoveryScenarioRegression: PASS (4 synthetic groups; no Hub or key material)")
}
