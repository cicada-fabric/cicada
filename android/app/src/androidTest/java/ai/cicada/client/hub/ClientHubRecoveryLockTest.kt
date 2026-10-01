package ai.cicada.client.hub

import android.content.Context
import android.content.ContextWrapper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Regression tests for durable N4 safety locks using an isolated, synthetic session. */
@RunWith(AndroidJUnit4::class)
class ClientHubRecoveryLockTest {
    private data class Sandbox(
        val context: Context,
        val root: File,
        val stateFile: File,
        val wrappedDeviceKeyFile: File,
    )

    @Test
    fun uncertainPendingRpcSurvivesReconstructionAndBlocksRecoveryResetAndRepin() {
        val sandbox = sandbox()
        try {
            val controlPublic = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            val initial = ClientHubSession(sandbox.context)
            initial.createDeviceIdentity()
            val pendingPacket = "SYNTHETIC_OPAQUE_PENDING_PACKET_MUST_NOT_BE_REPLACED"
            writeState(sandbox.stateFile, pendingState(controlPublic.toJson(), pendingPacket))
            val initialStateBytes = sandbox.stateFile.readBytes()
            val wrappedKeyBytes = sandbox.wrappedDeviceKeyFile.readBytes()

            // A new ClientHubSession instance represents process/session reconstruction.
            val restored = ClientHubSession(sandbox.context)
            val status = restored.getStatus()
            assertEquals("pending-n4-synthetic-operation",
                status.get("pendingOperationId").asString)
            assertEquals(42L, status.get("nextSequence").asLong)
            assertTrue(status.get("recoveryBlocked").asBoolean)
            assertFalse(status.get("remoteEnabled").asBoolean)

            // The pin uses an unreachable loopback endpoint. The precise local guard error
            // proves recovery stopped before parsing keys, opening HTTP, or changing state.
            expectError("RECOVERY_SEQUENCE_UNAVAILABLE") { restored.recoverPending() }
            assertUnchanged(sandbox.stateFile, initialStateBytes)

            expectError("PENDING_RECOVERY_REQUIRED") { restored.startNewDeviceEnrollment() }
            assertUnchanged(sandbox.stateFile, initialStateBytes)
            assertUnchanged(sandbox.wrappedDeviceKeyFile, wrappedKeyBytes)

            val reconstructedAgain = ClientHubSession(sandbox.context)
            val replacementControl = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            expectError("PENDING_RECOVERY_REQUIRED") {
                reconstructedAgain.pinHub(
                    "https://127.0.0.1:1",
                    "hub-n4-replacement-synthetic",
                    replacementControl.toJson(),
                )
            }
            val after = ClientHubSession(sandbox.context).getStatus()
            assertEquals("hub-n4-original-synthetic", after.get("hubId").asString)
            assertEquals("pending-n4-synthetic-operation",
                after.get("pendingOperationId").asString)
            assertEquals(42L, after.get("nextSequence").asLong)
            assertFalse(after.get("remoteEnabled").asBoolean)
            assertUnchanged(sandbox.stateFile, initialStateBytes)
            assertUnchanged(sandbox.wrappedDeviceKeyFile, wrappedKeyBytes)
        } finally {
            sandbox.root.deleteRecursively()
        }
    }

    @Test
    fun ambiguousEnrollmentAttemptSurvivesReconstructionAndBlocksRetryResetAndRepin() {
        val sandbox = sandbox()
        try {
            val controlPublic = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            val initial = ClientHubSession(sandbox.context)
            val deviceKeyId = initial.createDeviceIdentity()
                .getAsJsonObject("devicePublicIdentity").get("id").asString
            writeState(
                sandbox.stateFile,
                enrollmentAttemptState(controlPublic.toJson(), deviceKeyId),
            )
            val initialStateBytes = sandbox.stateFile.readBytes()
            val wrappedKeyBytes = sandbox.wrappedDeviceKeyFile.readBytes()

            val restored = ClientHubSession(sandbox.context)
            val status = restored.getStatus()
            assertTrue(status.get("enrollmentRecoveryRequired").asBoolean)
            assertEquals("owner-n4-synthetic", status.get("pendingEnrollmentOwnerId").asString)
            assertEquals("device-n4-synthetic", status.get("pendingEnrollmentDeviceId").asString)
            assertFalse(status.get("enrolled").asBoolean)
            assertFalse(status.get("remoteEnabled").asBoolean)

            expectError("ENROLLMENT_RECOVERY_REQUIRED") {
                restored.enroll("", "", "{}", "", "not-a-grant")
            }
            expectError("ENROLLMENT_RECOVERY_UNAVAILABLE") { restored.recoverEnrollment() }
            assertUnchanged(sandbox.stateFile, initialStateBytes)

            expectError("ENROLLMENT_RECOVERY_REQUIRED") {
                restored.startNewDeviceEnrollment()
            }
            assertUnchanged(sandbox.stateFile, initialStateBytes)
            assertUnchanged(sandbox.wrappedDeviceKeyFile, wrappedKeyBytes)

            val replacementControl = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            expectError("ENROLLMENT_RECOVERY_REQUIRED") {
                ClientHubSession(sandbox.context).pinHub(
                    "https://127.0.0.1:1",
                    "hub-n4-replacement-synthetic",
                    replacementControl.toJson(),
                )
            }
            val after = ClientHubSession(sandbox.context).getStatus()
            assertTrue(after.get("enrollmentRecoveryRequired").asBoolean)
            assertEquals("hub-n4-original-synthetic", after.get("hubId").asString)
            assertFalse(after.get("enrolled").asBoolean)
            assertUnchanged(sandbox.stateFile, initialStateBytes)
            assertUnchanged(sandbox.wrappedDeviceKeyFile, wrappedKeyBytes)
        } finally {
            sandbox.root.deleteRecursively()
        }
    }

    @Test
    fun authenticatedUncertainOutcomeRequiresSnapshotBeforeAnotherWrite() {
        val sandbox = sandbox()
        try {
            val controlPublic = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            ClientHubSession(sandbox.context).createDeviceIdentity()
            val saved = pendingState(controlPublic.toJson(), "unused").apply {
                remove("pending")
                addProperty("recoveryBlocked", false)
                addProperty("sessionError", "OUTCOME_UNCERTAIN")
                addProperty("outcomeUncertainOperationId", "prior-uncertain-operation")
                addProperty("uncertainNeedsReconciliation", true)
                add("allowedOperations", JsonArray().apply {
                    add("session.capabilities")
                    add("status.snapshot")
                    add("topology.apply")
                })
            }
            writeState(sandbox.stateFile, saved)
            val before = sandbox.stateFile.readBytes()
            val session = ClientHubSession(sandbox.context)
            assertTrue(session.getStatus().get("uncertainNeedsReconciliation").asBoolean)
            expectError("BUSINESS_RECONCILIATION_REQUIRED") {
                session.rpc("topology.apply", JsonObject())
            }
            assertUnchanged(sandbox.stateFile, before)
        } finally {
            sandbox.root.deleteRecursively()
        }
    }

    @Test
    fun monitorPrepareRecoveryRecordSurvivesRestartWithoutTextAndFencesReplacementAndReseal() {
        val sandbox = sandbox()
        val privateDraft = "private-monitor-draft-cjk-雪-emoji-🪶-trailing  "
        try {
            val controlPublic = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            val deviceId = ClientHubSession(sandbox.context).createDeviceIdentity()
                .getAsJsonObject("devicePublicIdentity").get("id").asString
            val saved = baseState(controlPublic.toJson()).apply {
                add("enrollment", JsonObject().apply {
                    addProperty("ownerId", "owner-n4-synthetic")
                    addProperty("deviceId", deviceId)
                    addProperty("sessionEpoch", 7)
                    addProperty("deviceKeyVersion", 2)
                    addProperty("state", "ACTIVE")
                })
                addProperty("nextSequence", 42)
                addProperty("lastResponseSequence", 41)
                addProperty("role", "manager")
                addProperty("sessionCapabilitiesReady", true)
                addProperty("validatedContractRevision", CONTRACT_REVISION)
                addProperty("validatedCatalogSha256", CATALOG_SHA256)
                add("allowedOperations", JsonArray().apply {
                    add("session.capabilities")
                    add("monitor.broadcast_prepare")
                    add("monitor.broadcast_confirm")
                    add("monitor.broadcast_status")
                    add("monitor.broadcast_recover")
                })
                addProperty("authFenced", false)
                addProperty("recoveryBlocked", false)
                addProperty("uncertainNeedsReconciliation", true)
                addProperty("outcomeUncertainOperationId", "prepare-original-n4")
                add("monitorOperations", JsonArray().apply {
                    add(JsonObject().apply {
                        addProperty("operationId", "prepare-original-n4")
                        addProperty("groupId", "group-n4")
                        addProperty("monitorEndpointId", "monitor-n4")
                        addProperty("bodySha256", "a".repeat(64))
                        addProperty("state", "PREPARE_UNCERTAIN")
                        addProperty("confirmAttempted", false)
                    })
                })
            }
            writeState(sandbox.stateFile, saved)
            val before = sandbox.stateFile.readBytes()
            assertFalse(String(before, StandardCharsets.UTF_8).contains(privateDraft))

            val restored = ClientHubSession(sandbox.context)
            val operations = restored.monitorBroadcastOperations().getAsJsonArray("operations")
            assertEquals(1, operations.size())
            assertEquals("prepare-original-n4", operations[0].asJsonObject.get("operationId").asString)
            assertEquals("PREPARE_UNCERTAIN", operations[0].asJsonObject.get("state").asString)
            assertFalse(operations.toString().contains(privateDraft))
            // The global uncertain-outcome latch is checked before Monitor-local
            // admission. First assert that fail-closed guard, then model the saved
            // state after an authenticated status.snapshot reconciles that global
            // outcome; the unresolved Prepare must still fence a replacement.
            expectError("BUSINESS_RECONCILIATION_REQUIRED") {
                restored.monitorBroadcastPrepare("group-n4", "monitor-n4", privateDraft, "prepare-new-n4")
            }
            assertUnchanged(sandbox.stateFile, before)
            val snapshotReconciled = JsonParser.parseString(String(before, StandardCharsets.UTF_8)).asJsonObject.apply {
                addProperty("uncertainNeedsReconciliation", false)
                remove("outcomeUncertainOperationId")
                add("sessionError", com.google.gson.JsonNull.INSTANCE)
            }
            writeState(sandbox.stateFile, snapshotReconciled)
            val monitorFenceBefore = sandbox.stateFile.readBytes()
            val afterSnapshot = ClientHubSession(sandbox.context)
            expectError("MONITOR_PREPARE_RECOVERY_REQUIRED") {
                afterSnapshot.monitorBroadcastPrepare("group-n4", "monitor-n4", privateDraft, "prepare-new-n4")
            }
            expectError("VERIFIED_MONITOR_FLOW_REQUIRED") {
                afterSnapshot.rpc("monitor.broadcast_prepare", JsonObject())
            }
            assertUnchanged(sandbox.stateFile, monitorFenceBefore)

            val confirmUncertain = JsonParser.parseString(String(monitorFenceBefore, StandardCharsets.UTF_8)).asJsonObject
            val operation = confirmUncertain.getAsJsonArray("monitorOperations")[0].asJsonObject
            operation.addProperty("state", "CONFIRM_UNCERTAIN")
            operation.addProperty("previewId", "preview-n4")
            operation.addProperty("confirmAttempted", true)
            operation.addProperty("confirmOperationId", "confirm-original-n4")
            operation.addProperty("confirmStatusReconciled", false)
            // Reconcile the generic business latch to show that the same-preview
            // Monitor status requirement remains independently enforced.
            confirmUncertain.addProperty("uncertainNeedsReconciliation", false)
            confirmUncertain.remove("outcomeUncertainOperationId")
            confirmUncertain.add("sessionError", com.google.gson.JsonNull.INSTANCE)
            writeState(sandbox.stateFile, confirmUncertain)
            val confirmBefore = sandbox.stateFile.readBytes()
            val restoredConfirm = ClientHubSession(sandbox.context)
            expectError("MONITOR_STATUS_REQUIRED") {
                restoredConfirm.monitorBroadcastRecover("prepare-original-n4")
            }
            expectError("MONITOR_PREPARE_RECOVERY_REQUIRED") {
                restoredConfirm.monitorBroadcastPrepare("group-n4", "monitor-n4", privateDraft, "prepare-new-n4")
            }
            assertUnchanged(sandbox.stateFile, confirmBefore)
        } finally {
            sandbox.root.deleteRecursively()
        }
    }

    @Test
    fun monitorStatusAllowsPreDispatchLedgerGapsButRequiresCompleteDispatchRoster() {
        val sandbox = sandbox()
        try {
            val controlPublic = ClientWireCrypto.Identity.generate().use { it.publicIdentity }
            val saved = baseState(controlPublic.toJson()).apply {
                add("monitorOperations", JsonArray().apply {
                    add(JsonObject().apply {
                        addProperty("operationId", "prepare-status-validation")
                        addProperty("groupId", "group-status-validation")
                        addProperty("monitorEndpointId", "monitor-status-validation")
                        addProperty("bodySha256", "a".repeat(64))
                        addProperty("state", "EXPIRED")
                        addProperty("previewId", "preview-status-validation")
                        addProperty("broadcastId", "broadcast-status-validation")
                        addProperty("expiresAt", "2020-01-02T00:00:00Z")
                        addProperty("grantExpiresAt", "2020-01-01T00:00:00Z")
                        add("recipientEndpointIds", JsonArray().apply {
                            add("endpoint-status-a")
                            add("endpoint-status-b")
                        })
                    })
                })
            }
            writeState(sandbox.stateFile, saved)
            val session = ClientHubSession(sandbox.context)
            val readState = ClientHubSession::class.java.getDeclaredMethod("readState").apply { isAccessible = true }
            val state = readState.invoke(session)
            val operationsField = state.javaClass.getDeclaredField("monitorOperations").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val operations = operationsField.get(state) as Map<String, Any>
            val metadata = operations.getValue("prepare-status-validation")
            val validate = ClientHubSession::class.java.declaredMethods
                .single { it.name == "validateMonitorStatusResult" }.apply { isAccessible = true }
            val displayState = ClientHubSession::class.java.declaredMethods
                .single { it.name == "monitorStatusDisplayState" }.apply { isAccessible = true }

            fun status(approval: String, recipients: JsonArray) = JsonObject().apply {
                addProperty("preview_id", "preview-status-validation")
                addProperty("broadcast_id", "broadcast-status-validation")
                addProperty("group_id", "group-status-validation")
                addProperty("approval_status", approval)
                addProperty("expires_at", "2020-01-02T00:00:00Z")
                add("recipients", recipients)
            }
            fun recipient(ordinal: Int, endpoint: String) = JsonObject().apply {
                addProperty("ordinal", ordinal)
                addProperty("endpoint_id", endpoint)
                addProperty("state", "UNKNOWN")
            }
            fun accept(approval: String, recipients: JsonArray) {
                validate.invoke(session, metadata, status(approval, recipients))
            }
            fun reject(approval: String, recipients: JsonArray) {
                try {
                    validate.invoke(session, metadata, status(approval, recipients))
                    fail("Expected INVALID_MONITOR_STATUS for $approval recipient ledger")
                } catch (error: java.lang.reflect.InvocationTargetException) {
                    assertEquals("INVALID_MONITOR_STATUS", (error.targetException as HubSessionException).errorCode)
                }
            }

            accept("PREPARED", JsonArray())
            accept("APPROVED", JsonArray().apply { add(recipient(1, "endpoint-status-b")) })
            reject("PREPARED", JsonArray().apply { add(recipient(1, "endpoint-status-a")) })
            reject("DISPATCH_AUTHORIZED", JsonArray().apply { add(recipient(0, "endpoint-status-a")) })
            accept("DISPATCH_AUTHORIZED", JsonArray().apply {
                add(recipient(0, "endpoint-status-a"))
                add(recipient(1, "endpoint-status-b"))
            })
            val changedExpiry = status("PREPARED", JsonArray()).apply {
                addProperty("expires_at", "2020-01-02T00:00:01Z")
            }
            try {
                validate.invoke(session, metadata, changedExpiry)
                fail("A Monitor status with changed immutable expiry must be rejected")
            } catch (error: java.lang.reflect.InvocationTargetException) {
                assertEquals("INVALID_MONITOR_STATUS", (error.targetException as HubSessionException).errorCode)
            }
            assertEquals("EXPIRED", displayState.invoke(session, metadata, status("PREPARED", JsonArray())))
            assertEquals("APPROVED", displayState.invoke(session, metadata, status("APPROVED", JsonArray())))
            val operationView = session.monitorBroadcastOperations().getAsJsonArray("operations")[0].asJsonObject
            assertEquals("2020-01-01T00:00:00Z", operationView.get("grantExpiresAt").asString)
            assertEquals("2020-01-01T00:00:00Z", operationView.get("validUntil").asString)
        } finally {
            sandbox.root.deleteRecursively()
        }
    }

    @Test
    fun monitorConfirmPreflightRequiresCurrentSourcePermissionAndBinding() {
        val sandbox = sandbox()
        try {
            val session = ClientHubSession(sandbox.context)
            val source = MonitorBroadcastCrypto.ConsentEndpoint(
                endpointId = "endpoint-source-preflight",
                principalId = "principal-source-preflight",
                ownerId = "owner-preflight",
                nodeId = "node-source-preflight",
                membershipRevision = 17,
                groupJoinRevision = 4,
                bindingId = "binding-source-preflight",
                bindingEpoch = 3,
                keyId = "key-source-preflight",
                keyVersion = 2,
                keyFingerprint = "sha256:" + "a".repeat(64),
                keyProofDigest = "b".repeat(64),
            )
            val method = ClientHubSession::class.java.declaredMethods
                .single { it.name == "verifyMonitorTopologySource" }.apply { isAccessible = true }

            fun snapshot(permission: Boolean = true, status: String = "active", bindingEpoch: Long = 3) =
                JsonObject().apply {
                    addProperty("contract_version", 2)
                    addProperty("owner_principal_id", "owner-preflight")
                    addProperty("captured_at", "2026-09-30T12:00:00Z")
                    addProperty("read_consistency", "best_effort")
                    addProperty("networks_truncated", false)
                    addProperty("network_endpoints_truncated", false)
                    add("networks", JsonArray().apply {
                        add(JsonObject().apply {
                            addProperty("network_id", "network-preflight")
                            addProperty("name", "Synthetic preflight Network")
                            addProperty("state", "ACTIVE")
                            addProperty("version", 1)
                            addProperty("can_create_group", true)
                        })
                    })
                    add("groups", JsonArray().apply {
                        add(JsonObject().apply {
                            addProperty("group_id", "group-preflight")
                            addProperty("network_id", "network-preflight")
                            addProperty("name", "Synthetic preflight Group")
                            addProperty("state", "ACTIVE")
                            // These management CAS versions are intentionally distinct from
                            // the signed Group manifest revisions in the source consent card.
                            addProperty("version", 900)
                        })
                    })
                    add("endpoints", JsonArray().apply {
                        add(JsonObject().apply {
                            addProperty("endpoint_id", source.endpointId)
                            addProperty("name", "Synthetic preflight Monitor")
                            addProperty("principal_id", source.principalId)
                            addProperty("node_id", source.nodeId)
                            addProperty("binding_id", source.bindingId)
                            addProperty("binding_epoch", bindingEpoch)
                            addProperty("binding_status", "leased")
                            add("group_ids", JsonArray().apply { add("group-preflight") })
                            add("network_ids", JsonArray().apply { add("network-preflight") })
                            addProperty("presence", "online")
                        })
                    })
                    add("memberships", JsonArray().apply {
                        add(JsonObject().apply {
                            addProperty("group_id", "group-preflight")
                            addProperty("membership_id", "membership-source-preflight")
                            addProperty("principal_id", source.principalId)
                            addProperty("role", "monitor")
                            addProperty("status", status)
                            addProperty("broadcast_permission_enabled", permission)
                            // This is a topology CAS version, not membership_revision.
                            addProperty("version", 730)
                        })
                    })
                    add("links", JsonArray())
                }

            fun accept(value: JsonObject) {
                method.invoke(session, value, "owner-preflight", "group-preflight", source)
            }
            fun reject(value: JsonObject) {
                try {
                    accept(value)
                    fail("An obsolete Monitor authorization was accepted")
                } catch (error: java.lang.reflect.InvocationTargetException) {
                    assertTrue(error.targetException is IllegalArgumentException)
                }
            }

            accept(snapshot())
            reject(snapshot().apply { addProperty("contract_version", 1) })
            reject(snapshot(permission = false))
            reject(snapshot(status = "revoked"))
            reject(snapshot(bindingEpoch = 4))
        } finally {
            sandbox.root.deleteRecursively()
        }
    }

    private fun sandbox(): Sandbox {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(target.cacheDir, "n4-recovery-lock-${UUID.randomUUID()}")
        check(root.mkdirs()) { "Could not create isolated N4 test state" }
        val context = IsolatedContext(target, root)
        val sessionDir = File(root, "client-hub").apply {
            check(mkdirs()) { "Could not create isolated ClientHubSession state" }
        }
        return Sandbox(
            context,
            root,
            File(sessionDir, "session-state.json"),
            File(sessionDir, "device-key.wrap.json"),
        )
    }

    private fun pendingState(controlPublicJson: String, packet: String) =
        baseState(controlPublicJson).apply {
            add("enrollment", JsonObject().apply {
                addProperty("ownerId", "owner-n4-synthetic")
                addProperty("deviceId", "device-n4-synthetic")
                addProperty("sessionEpoch", 7)
                addProperty("deviceKeyVersion", 2)
                addProperty("state", "ACTIVE")
            })
            addProperty("nextSequence", 42)
            addProperty("lastResponseSequence", 23)
            addProperty("role", "manager")
            addProperty("sessionCapabilitiesReady", true)
            addProperty("validatedContractRevision", CONTRACT_REVISION)
            addProperty("validatedCatalogSha256", CATALOG_SHA256)
            add("allowedOperations", JsonArray().apply {
                add("session.capabilities")
                add("status.snapshot")
            })
            addProperty("authFenced", false)
            addProperty("recoveryBlocked", true)
            addProperty("sessionError", "RPC_HTTP_409_UNCERTAIN")
            addProperty("previousDeviceMayRemainOnHub", false)
            add("pending", JsonObject().apply {
                addProperty("operation", "status.snapshot")
                addProperty("operationId", "pending-n4-synthetic-operation")
                addProperty("sequence", 41)
                addProperty("packetJson", packet)
            })
        }

    private fun enrollmentAttemptState(controlPublicJson: String, deviceKeyId: String) =
        baseState(controlPublicJson).apply {
            addProperty("nextSequence", 1)
            addProperty("lastResponseSequence", 0)
            addProperty("role", null as String?)
            addProperty("sessionCapabilitiesReady", false)
            addProperty("validatedContractRevision", null as String?)
            addProperty("validatedCatalogSha256", null as String?)
            add("allowedOperations", JsonArray())
            addProperty("authFenced", false)
            addProperty("recoveryBlocked", false)
            addProperty("sessionError", null as String?)
            addProperty("previousDeviceMayRemainOnHub", false)
            add("enrollmentAttempt", JsonObject().apply {
                addProperty("ownerId", "owner-n4-synthetic")
                addProperty("deviceId", "device-n4-synthetic")
                addProperty("deviceKeyId", deviceKeyId)
                addProperty("grantSha256", "a".repeat(64))
            })
        }

    private fun baseState(controlPublicJson: String) = JsonObject().apply {
        add("pin", JsonObject().apply {
            // A refused loopback port is isolated from any actual Hub process.
            addProperty("baseUrl", "https://127.0.0.1:1")
            addProperty("hubId", "hub-n4-original-synthetic")
            addProperty("controlPublicIdentityJson", controlPublicJson)
            addProperty("controlKeyVersion", 1)
        })
        addProperty("previousDeviceMayRemainOnHub", false)
    }

    private fun writeState(file: File, state: JsonObject) {
        file.writeText(state.toString(), StandardCharsets.UTF_8)
    }

    private fun assertUnchanged(file: File, expected: ByteArray) {
        assertTrue("Expected isolated test file ${file.name}", file.exists())
        assertArrayEquals("${file.name} must remain byte-for-byte unchanged", expected, file.readBytes())
    }

    private fun expectError(expected: String, action: () -> Unit) {
        try {
            action()
            throw AssertionError("Expected HubSessionException $expected")
        } catch (error: HubSessionException) {
            assertEquals(expected, error.errorCode)
        }
    }

    private class IsolatedContext(
        base: Context,
        private val isolatedNoBackupFilesDir: File,
    ) : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this

        override fun getNoBackupFilesDir(): File = isolatedNoBackupFilesDir
    }

    private companion object {
        const val CONTRACT_REVISION = "client-hub-v1.6"
        const val CATALOG_SHA256 = "1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c"
    }
}
