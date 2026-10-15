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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Synthetic local-state tests: no Hub fixture, bearer, Owner secret or device code is used. */
@RunWith(AndroidJUnit4::class)
class HubProfileStoreTest {
    @Test
    fun distinctDeviceKeysAndProfileBoundWrappingRejectKeyFileSwap() = sandbox { context, _ ->
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        val withB = store.createHubProfile("Second Hub", a)
        val bId = otherId(withB, a.profileId)
        assertEquals(a, scope(withB))
        val aIdentity = store.withActiveScope(a) { it.createDeviceIdentity() }
            .getAsJsonObject("devicePublicIdentity")
        val b = scope(store.activateHubProfile(bId, a))
        val bIdentity = store.withActiveScope(b) { it.createDeviceIdentity() }
            .getAsJsonObject("devicePublicIdentity")
        assertNotEquals(aIdentity.get("id").asString, bIdentity.get("id").asString)
        val aWrap = keyFile(context, a.profileId)
        val originalA = aWrap.readBytes()
        val bWrap = keyFile(context, b.profileId).readBytes()
        aWrap.writeBytes(bWrap)
        expectCode("DEVICE_KEY_UNAVAILABLE") { ClientHubSession(context, a.profileId).createDeviceIdentity() }
        assertArrayEquals(bWrap, aWrap.readBytes())
        aWrap.writeBytes(originalA)
        val restored = ClientHubSession(context, a.profileId).createDeviceIdentity()
        assertEquals(aIdentity, restored.getAsJsonObject("devicePublicIdentity"))
        assertEquals(bIdentity, ClientHubSession(context, b.profileId).createDeviceIdentity()
            .getAsJsonObject("devicePublicIdentity"))
    }

    @Test
    fun originalPendingPacketCountersAndMonitorScopeSurviveSwitchAndRestart() = sandbox { context, _ ->
        val initial = HubProfileStore(context)
        val a = scope(initial.listHubProfiles())
        val bId = otherId(initial.createHubProfile("Second Hub", a), a.profileId)
        val identity = initial.withActiveScope(a) { it.createDeviceIdentity() }
            .getAsJsonObject("devicePublicIdentity").toString()
        val aState = syntheticState("hub-a", identity, 42, 23).apply {
            addProperty("activeNetworkId", "network-a")
            add("pending", JsonObject().apply {
                addProperty("operation", "monitor.broadcast_prepare")
                addProperty("operationId", "original-monitor-operation")
                addProperty("sequence", 41)
                addProperty("expectedResponseSequence", 24)
                addProperty("packetJson", "EXACT_SYNTHETIC_SIGNED_CIPHERTEXT_PACKET")
            })
            add("monitorOperations", JsonArray().apply { add(JsonObject().apply {
                addProperty("operationId", "original-monitor-operation")
                addProperty("groupId", "original-group")
                addProperty("monitorEndpointId", "original-endpoint")
                addProperty("bodySha256", "a".repeat(64))
                addProperty("state", "PREPARE_UNCERTAIN")
            }) })
        }
        stateFile(context, a.profileId).writeText(aState.toString())
        val originalBytes = stateFile(context, a.profileId).readBytes()
        val originalWrap = keyFile(context, a.profileId).readBytes()
        val b = scope(initial.activateHubProfile(bId, a))
        val bIdentity = initial.withActiveScope(b) { it.createDeviceIdentity() }
            .getAsJsonObject("devicePublicIdentity").toString()
        stateFile(context, b.profileId).writeText(syntheticState("hub-b", bIdentity, 7, 3).apply {
            addProperty("activeNetworkId", "network-b")
        }.toString())
        val reconstructed = HubProfileStore(context)
        assertEquals(b, scope(reconstructed.listHubProfiles()))
        assertEquals(7L, reconstructed.getStatus(b).get("nextSequence").asLong)
        assertEquals("network-b", reconstructed.getStatus(b).get("activeNetworkId").asString)
        val returnedA = scope(reconstructed.activateHubProfile(a.profileId, b))
        val status = reconstructed.getStatus(returnedA)
        assertEquals("hub-a", status.get("hubId").asString)
        assertEquals("network-a", status.get("activeNetworkId").asString)
        assertEquals(42L, status.get("nextSequence").asLong)
        assertEquals("original-monitor-operation", status.get("pendingOperationId").asString)
        assertTrue(status.get("hasUnresolvedMonitorOperations").asBoolean)
        assertFalse(status.get("remoteEnabled").asBoolean)
        assertArrayEquals(originalBytes, stateFile(context, a.profileId).readBytes())
        assertArrayEquals(originalWrap, keyFile(context, a.profileId).readBytes())
        expectCode("PENDING_RECOVERY_REQUIRED") {
            reconstructed.withActiveScope(returnedA) { it.rpc("status.snapshot", JsonObject()) }
        }
        assertArrayEquals(originalBytes, stateFile(context, a.profileId).readBytes())
    }

    @Test
    fun enrollmentRequestIsPreservedAndRemovalRefusesItsUnknownOutcome() = sandbox { context, _ ->
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        val bId = otherId(store.createHubProfile("Second Hub", a), a.profileId)
        stateFile(context, a.profileId).writeText(JsonObject().apply {
            add("enrollmentAttempt", JsonObject().apply {
                addProperty("ownerId", "synthetic-owner")
                addProperty("deviceId", "synthetic-device")
                addProperty("deviceKeyId", "synthetic-key")
                addProperty("grantSha256", "b".repeat(64))
                addProperty("requestJson", "EXACT_SYNTHETIC_OWNER_DEVICE_GRANT_REQUEST")
            })
        }.toString())
        val bytes = stateFile(context, a.profileId).readBytes()
        val b = scope(store.activateHubProfile(bId, a))
        expectCode("PROFILE_RECOVERY_REQUIRED") { store.removeHubProfile(a.profileId, b) }
        val returned = scope(HubProfileStore(context).activateHubProfile(a.profileId, b))
        assertTrue(store.getStatus(returned).get("enrollmentRecoveryRequired").asBoolean)
        assertArrayEquals(bytes, stateFile(context, a.profileId).readBytes())
    }

    @Test
    fun oldScopeAndAbaScopeRejectBeforeTheActionCanRun() = sandbox { context, _ ->
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        val bId = otherId(store.createHubProfile("Second Hub", a), a.profileId)
        val b = scope(store.activateHubProfile(bId, a))
        var executed = false
        expectCode("PROFILE_SELECTION_CHANGED") {
            store.withActiveScope(a) { executed = true; it.createDeviceIdentity() }
        }
        assertFalse(executed)
        assertFalse(keyFile(context, a.profileId).exists())
        val returnedA = scope(store.activateHubProfile(a.profileId, b))
        assertEquals(a.profileId, returnedA.profileId)
        assertTrue(returnedA.selectionGeneration > a.selectionGeneration)
        expectCode("PROFILE_SELECTION_CHANGED") {
            store.withActiveScope(a) { executed = true; it.rpc("intent.submit", JsonObject()) }
        }
        expectCode("PROFILE_SELECTION_CHANGED") { store.removeHubProfile(b.profileId, a) }
        expectCode("PROFILE_SELECTION_CHANGED") { store.createHubProfile("Stale dialog", a) }
        expectCode("PROFILE_SELECTION_CHANGED") { store.setActiveNetwork("stale-network", a) }
        assertFalse(executed)
        assertEquals(2, store.listHubProfiles().getAsJsonArray("profiles").size())
    }

    @Test
    fun removalRefusesActivePendingAndMonitorProfilesAndPreservesOtherDeviceKey() = sandbox { context, _ ->
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        val bId = otherId(store.createHubProfile("Second Hub", a), a.profileId)
        store.withActiveScope(a) { it.createDeviceIdentity() }
        val keyBytes = keyFile(context, a.profileId).readBytes()
        expectCode("PROFILE_IS_ACTIVE") { store.removeHubProfile(a.profileId, a) }
        val b = scope(store.activateHubProfile(bId, a))
        store.withActiveScope(b) { it.createDeviceIdentity() }
        stateFile(context, a.profileId).writeText(JsonObject().apply {
            addProperty("uncertainNeedsReconciliation", true)
        }.toString())
        expectCode("PROFILE_RECOVERY_REQUIRED") { store.removeHubProfile(a.profileId, b) }
        stateFile(context, a.profileId).writeText(JsonObject().apply {
            add("monitorOperations", JsonArray().apply { add(JsonObject().apply {
                addProperty("operationId", "original-monitor-confirm")
                addProperty("groupId", "original-group")
                addProperty("monitorEndpointId", "original-endpoint")
                addProperty("bodySha256", "c".repeat(64))
                addProperty("state", "APPROVED")
                addProperty("confirmAttempted", true)
                addProperty("confirmStatusReconciled", false)
            }) })
        }.toString())
        expectCode("PROFILE_RECOVERY_REQUIRED") { store.removeHubProfile(a.profileId, b) }
        stateFile(context, a.profileId).writeText("{}")
        val returnedA = scope(store.activateHubProfile(a.profileId, b))
        val removed = store.removeHubProfile(b.profileId, returnedA)
        assertEquals(1, removed.getAsJsonArray("profiles").size())
        assertFalse(ClientHubSession.profileDirectory(context, b.profileId).exists())
        assertArrayEquals(keyBytes, keyFile(context, a.profileId).readBytes())
        assertEquals(returnedA, scope(removed))
    }

    @Test
    fun legacyAdoptionPreservesExactPendingStateAndDoesNotCreateOrRotateAKey() = sandbox { context, _ ->
        val legacyDirectory = ClientHubSession.profileDirectory(context, "legacy").apply { check(mkdirs()) }
        val legacyFile = File(legacyDirectory, "session-state.json")
        val original = JsonObject().apply {
            addProperty("nextSequence", 13)
            addProperty("lastResponseSequence", 8)
            add("pending", JsonObject().apply {
                addProperty("operation", "intent.submit")
                addProperty("operationId", "legacy-original-operation")
                addProperty("sequence", 12)
                addProperty("expectedResponseSequence", 9)
                addProperty("packetJson", "EXACT_LEGACY_SYNTHETIC_PACKET")
            })
        }.toString().toByteArray()
        legacyFile.writeBytes(original)
        val store = HubProfileStore(context)
        val first = store.listHubProfiles()
        val a = scope(first)
        assertEquals("legacy", a.profileId)
        assertEquals(1L, a.selectionGeneration)
        assertEquals("legacy-original-operation", store.getStatus(a).get("pendingOperationId").asString)
        assertArrayEquals(original, legacyFile.readBytes())
        assertFalse(File(legacyDirectory, "device-key.wrap.json").exists())
        val bId = otherId(store.createHubProfile("New independent Hub", a), "legacy")
        val b = scope(store.activateHubProfile(bId, a))
        val restored = scope(HubProfileStore(context).activateHubProfile("legacy", b))
        assertEquals("legacy", restored.profileId)
        assertArrayEquals(original, legacyFile.readBytes())
        expectCode("PROFILE_SELECTION_CHANGED") { store.withActiveScope(a) { it.createDeviceIdentity() } }
        assertFalse(File(legacyDirectory, "device-key.wrap.json").exists())
    }

    @Test
    fun corruptRegistryAndUnsafeProfileIdsFailClosedWithoutResettingSelection() = sandbox { context, root ->
        val store = HubProfileStore(context)
        val initial = store.listHubProfiles()
        val a = scope(initial)
        expectCode("INVALID_PROFILE_ID") { ClientHubSession(context, "../../outside") }
        expectCode("INVALID_PROFILE_ID") { store.activateHubProfile("../../outside", a) }
        assertEquals(a, scope(store.listHubProfiles()))
        val registry = File(root, "client-hub-profiles/profiles.json")
        val original = registry.readBytes()
        registry.writeText("{invalid")
        expectCode("PROFILE_REGISTRY_INVALID") { HubProfileStore(context).listHubProfiles() }
        assertEquals("{invalid", registry.readText())
        registry.writeBytes(original)
        assertEquals(a, scope(HubProfileStore(context).listHubProfiles()))
    }

    @Test
    fun legacyAtomicBackupIsAdoptedAndRecoveredWithoutDiscardingPending() = sandbox { context, _ ->
        val legacy = ClientHubSession.profileDirectory(context, "legacy").apply { check(mkdirs()) }
        File(legacy, "session-state.json.bak").writeText(JsonObject().apply {
            add("pending", JsonObject().apply {
                addProperty("operation", "intent.submit")
                addProperty("operationId", "atomic-backup-original-operation")
                addProperty("sequence", 5)
                addProperty("expectedResponseSequence", 3)
                addProperty("packetJson", "EXACT_BACKUP_SYNTHETIC_PACKET")
            })
            addProperty("nextSequence", 6)
            addProperty("lastResponseSequence", 2)
        }.toString())
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        assertEquals("legacy", a.profileId)
        assertEquals("atomic-backup-original-operation", store.getStatus(a).get("pendingOperationId").asString)
        val restored = JsonParser.parseString(File(legacy, "session-state.json").readText()).asJsonObject
        assertEquals("EXACT_BACKUP_SYNTHETIC_PACKET", restored.getAsJsonObject("pending").get("packetJson").asString)
        assertEquals(6L, restored.get("nextSequence").asLong)
    }

    @Test
    fun networkSelectionDoesNotTrustCachedSelectionWithoutAnEncryptedSession() = sandbox { context, _ ->
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        stateFile(context, a.profileId).writeText("{\"activeNetworkId\":\"old-network\"}")
        val original = stateFile(context, a.profileId).readBytes()
        expectCode("HUB_NOT_PINNED") { store.setActiveNetwork("new-network", a) }
        assertEquals(a, scope(store.listHubProfiles()))
        assertArrayEquals(original, stateFile(context, a.profileId).readBytes())
        assertEquals("old-network", store.getStatus(a).get("activeNetworkId").asString)
    }

    @Test
    fun aDifferentHubRequiresANewProfileAndCannotReuseTheOriginalDeviceKey() = sandbox { context, _ ->
        val store = HubProfileStore(context)
        val a = scope(store.listHubProfiles())
        val aIdentity = store.withActiveScope(a) { it.createDeviceIdentity() }
            .getAsJsonObject("devicePublicIdentity")
        store.withActiveScope(a) { it.pinHub("https://127.0.0.1:1", "synthetic-hub-a", aIdentity.toString()) }
        val originalState = stateFile(context, a.profileId).readBytes()
        val originalKey = keyFile(context, a.profileId).readBytes()
        expectCode("PROFILE_HUB_ID_MISMATCH") {
            store.withActiveScope(a) { it.pinHub("https://127.0.0.1:2", "synthetic-hub-b", aIdentity.toString()) }
        }
        assertArrayEquals(originalState, stateFile(context, a.profileId).readBytes())
        assertArrayEquals(originalKey, keyFile(context, a.profileId).readBytes())
        assertEquals("synthetic-hub-a", store.getStatus(a).get("hubId").asString)
        val bId = otherId(store.createHubProfile("Independent second Hub", a), a.profileId)
        val b = scope(store.activateHubProfile(bId, a))
        val bIdentity = store.withActiveScope(b) { it.createDeviceIdentity() }
            .getAsJsonObject("devicePublicIdentity")
        assertNotEquals(aIdentity.get("id").asString, bIdentity.get("id").asString)
        store.withActiveScope(b) { it.pinHub("https://127.0.0.1:2", "synthetic-hub-b", bIdentity.toString()) }
        assertEquals("synthetic-hub-b", store.getStatus(b).get("hubId").asString)
        assertArrayEquals(originalState, stateFile(context, a.profileId).readBytes())
        assertArrayEquals(originalKey, keyFile(context, a.profileId).readBytes())
    }

    private fun syntheticState(hubId: String, publicIdentity: String, next: Long, last: Long) = JsonObject().apply {
        add("pin", JsonObject().apply {
            addProperty("baseUrl", "https://127.0.0.1:1")
            addProperty("hubId", hubId)
            addProperty("controlPublicIdentityJson", publicIdentity)
        })
        add("enrollment", JsonObject().apply {
            addProperty("ownerId", "synthetic-$hubId-owner")
            addProperty("deviceId", "synthetic-$hubId-device")
            addProperty("sessionEpoch", 1)
            addProperty("deviceKeyVersion", 1)
            addProperty("state", "ACTIVE")
        })
        addProperty("nextSequence", next)
        addProperty("lastResponseSequence", last)
    }

    private fun scope(result: JsonObject): HubProfileStore.Scope = result.getAsJsonObject("activeScope").let {
        HubProfileStore.Scope(it.get("profileId").asString, it.get("selectionGeneration").asLong)
    }

    private fun otherId(result: JsonObject, existing: String): String = result.getAsJsonArray("profiles")
        .map { it.asJsonObject.get("profileId").asString }.single { it != existing }

    private fun stateFile(context: Context, id: String): File = File(ClientHubSession.profileDirectory(context, id), "session-state.json")
    private fun keyFile(context: Context, id: String): File = File(ClientHubSession.profileDirectory(context, id), "device-key.wrap.json")

    private fun sandbox(action: (Context, File) -> Unit) {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(target.cacheDir, "hub-profiles-${UUID.randomUUID()}").apply { check(mkdirs()) }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getNoBackupFilesDir(): File = root
        }
        try { action(context, root) }
        finally {
            // Only UUID profile keys created by this test are removed; the shared legacy alias is untouched.
            File(root, "client-hub-profiles").listFiles()?.filter { it.isDirectory }?.forEach { profile ->
                File(profile, "session-state.json").writeText("{}")
                ClientHubSession(context, profile.name).deleteProfileState()
            }
            root.deleteRecursively()
        }
    }

    private fun expectCode(expected: String, action: () -> Unit) {
        try { action(); fail("Expected $expected") }
        catch (error: HubSessionException) { assertEquals(expected, error.errorCode) }
    }
}
