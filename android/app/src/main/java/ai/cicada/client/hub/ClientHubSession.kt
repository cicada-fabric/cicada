package ai.cicada.client.hub

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import com.cicadaclient.BuildConfig
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.StringReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.withLock
import kotlin.math.floor

/**
 * Android's local Client-to-Hub session. All durable state is kept under
 * noBackupFilesDir. Device private key bytes are separately wrapped by a
 * non-exportable Android Keystore AES-GCM key.
 *
 * Public methods are synchronous so instrumentation tests can exercise the
 * exact same code as the React Native bridge. Call them off the UI thread.
 */
class ClientHubSession(context: Context, internal val profileId: String = "legacy") {
    private val appContext = context.applicationContext
    private val directory = profileDirectory(appContext, profileId).apply {
        if (!exists() && !mkdirs()) throw HubSessionException("STORAGE_UNAVAILABLE", "Cannot create private Hub state directory")
    }
    private val stateFile = AtomicFile(File(directory, "session-state.json"))
    private val privateKeyFile = AtomicFile(File(directory, "device-key.wrap.json"))
    private val gson = com.google.gson.Gson()
    private val wrappingKeyAlias = if (profileId == "legacy") KEY_ALIAS else "$KEY_ALIAS.$profileId"
    private val wrappingKeyAad = if (profileId == "legacy") KEY_AAD else
        ("cicada/android/client-device-key/wrap/profile/v1\u0000" + profileId).toByteArray(StandardCharsets.UTF_8)

    companion object {
        private const val KEY_ALIAS = "ai.cicada.client.hub.device-wrap.v1"
        private val KEY_AAD = "cicada/android/client-device-key/wrap/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        private const val CONTRACT_REVISION = "client-hub-v1.6.4"
        private const val CATALOG_SHA256 = "953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d"
        /** Release-gate state for the v1.6.4 Link consent candidate. */
        internal const val LINK_CONSENT_READY = true
        private const val MAX_BODY_BYTES = 64 * 1024
        private const val MAX_MONITOR_BODY_BYTES = 16 * 1024
        private const val MAX_PACKET_BYTES = 256 * 1024
        private const val MAX_RESPONSE_BYTES = 256 * 1024
        private const val MAX_METADATA_BYTES = 256 * 1024
        private const val MAX_SESSION_STATE_BYTES = 1_048_576
        private const val LINK_STATUS_LIST_LIMIT = 100
        private const val MAX_LINK_STATUS_LIST_PAGES = 64
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000
        internal val PROCESS_LOCK = ReentrantLock()
        private val regroupReviews = linkedMapOf<String, RegroupReview>()
        private val regroupLifecycleGeneration = AtomicLong(1)

        // Lifecycle callbacks must not wait on an RPC's network lock on the UI thread.
        internal fun clearRegroupReviews() { regroupLifecycleGeneration.incrementAndGet() }

        internal fun validateProfileId(profileId: String) {
            if (profileId != "legacy" && !profileId.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) {
                throw HubSessionException("INVALID_PROFILE_ID", "Hub profile identifier is invalid")
            }
        }

        internal fun profileDirectory(context: Context, profileId: String): File {
            validateProfileId(profileId)
            return File(context.noBackupFilesDir, if (profileId == "legacy") "client-hub" else "client-hub-profiles/$profileId")
        }
        private val RPC_OPERATIONS = setOf(
            "session.capabilities", "status.snapshot", "status.changes", "goal.lifecycle",
            "topology.snapshot", "topology.apply", "devices.list", "devices.revoke",
            "nodes.preview", "nodes.confirm", "nodes.list", "nodes.revoke",
            "approvals.list", "approvals.decide", "goal.result", "intent.get", "intent.status",
            "intent.list", "intent.submit", "link.list", "link.review_policy_status", "link.invite_create", "link.invite_preview",
            "link.invite_accept", "group.key_manifest", "group.key_grant", "group.key_status",
            "network.key_manifest", "network.key_grant", "network.key_status",
            "network.directory", "topology.endpoint_admission_preview",
            "topology.regroup_proposal", "topology.delegation_issue", "topology.delegation_revoke",
            "link.key_manifest", "link.key_grants", "link.key_grant",
            "link.review_policy_preview", "link.review_policy_grant",
            "monitor.broadcast_prepare", "monitor.broadcast_confirm", "monitor.broadcast_status",
            "monitor.broadcast_recover",
        )
        private val LINK_CONSENT_OPERATIONS = setOf(
            "link.key_manifest", "link.key_grants", "link.key_grant",
            "link.review_policy_status", "link.review_policy_preview", "link.review_policy_grant",
        )
        private val OWNER_PUBLIC_IDENTITY_FIELDS = setOf("id", "kem_public", "signing_public")
        // These v1.5/v1.6 operations have no complete local owner-proof/current-authority path.
        // Hub advertisement cannot authorize the generic bridge to substitute for those flows.
        private val UNIMPLEMENTED_CONSENT_OPERATIONS = setOf(
            "space.foreign_member_admit", "space.foreign_member_revoke",
            "space.foreign_endpoint_join", "space.key_manifest_v2", "space.key_consent_v2",
            "space.key_admission_v2", "space.key_status_v2",
            "space.foreign_endpoint_preview", "network.collaboration_key_manifest",
            "network.collaboration_key_grant", "network.collaboration_key_status",
            "link.key_manifest", "link.key_grants", "link.key_grant",
            "link.review_policy_preview", "link.review_policy_grant",
        )
        private val MUTATING_RPC_OPERATIONS = setOf(
            "goal.lifecycle", "topology.apply", "devices.revoke", "nodes.confirm",
            "nodes.revoke", "approvals.decide", "intent.submit", "link.invite_create",
            "link.invite_accept", "group.key_grant", "network.key_grant", "monitor.broadcast_prepare",
            "monitor.broadcast_confirm", "link.key_grant", "link.review_policy_grant",
            "topology.delegation_issue", "topology.delegation_revoke",
        )
        private val MONITOR_OPERATION_STATES = setOf(
            "PREPARE_PENDING", "PREPARE_UNCERTAIN", "PREPARED", "APPROVED",
            "DISPATCH_AUTHORIZED", "REJECTED", "CONFIRM_PENDING", "CONFIRM_UNCERTAIN",
            "CONFIRM_REJECTED", "RECOVERY_UNCERTAIN", "EXPIRED",
        )

        /** HTTP is limited to the historical emulator route or a local ADB reverse port. */
        internal fun isDebugHttpHubAllowed(host: String, port: Int,
                                           debugBuild: Boolean, emulator: Boolean): Boolean =
            debugBuild && (
                host == "10.0.2.2" && port in setOf(8787, 8788, 8789, 8790, 8792, 8794, 8795) ||
                    emulator && host == "127.0.0.1" && port in 1024..65535
                )
    }

    private data class Pin(
        val baseUrl: String,
        val hubId: String,
        val controlPublicIdentityJson: String,
        val controlKeyVersion: Long = 1,
    )

    private data class Enrollment(
        val ownerId: String,
        val deviceId: String,
        val sessionEpoch: Long,
        val deviceKeyVersion: Long,
        val state: String,
    )

    private data class Pending(
        val operation: String,
        val operationId: String,
        val sequence: Long,
        /** Reserved expected Hub sequence, calculated before transmission. */
        val expectedResponseSequence: Long?,
        /** Exact serialized signed and encrypted packet; retries must send these same bytes. */
        val packetJson: String,
        /** Original Monitor operation associated with a read-only follow-up route. */
        val monitorOperationId: String? = null,
    )

    private data class EnrollmentAttempt(
        val ownerId: String,
        val deviceId: String,
        val deviceKeyId: String,
        val grantSha256: String,
        /** Exact enrollment POST body, retained across a lost HTTP 201 response. */
        val requestJson: String?,
    )

    /** Persisted selector for an in-flight candidate status read; never a trust result. */
    private data class LinkConsentStatusReadContext(
        val linkId: String,
        val linkVersion: Long,
        val mySide: String,
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val sessionEpoch: Long,
        val operationId: String,
        val sequence: Long,
        val profileGeneration: Long,
    )

    private data class LinkConsentPreparation(
        val review: LinkConsentLedger.Review,
        val authority: VerifiedCurrentLinkAuthority,
        val ownerGrantStatusRead: FreshLinkOwnerGrantStatusRead,
        val ownerGrantStatuses: JsonArray,
        val sourceCurrentKey: LinkKeyManifestVerifier.CurrentOwnerKeyAuthority?,
        val targetCurrentKey: LinkKeyManifestVerifier.CurrentOwnerKeyAuthority?,
        val policyStatusRead: LinkConsentLedger.ReadCorrelation?,
        val policyStatus: JsonObject?,
        val policyPreview: LinkReviewPolicyV164Preview?,
        val reviewPolicyStatusBytes: ByteArray?,
        val reviewPolicyPreviewBytes: ByteArray?,
        val localPolicyLifecycle: LinkReviewPolicyV164OwnerLifecycle?,
        val localPolicyPin: LinkReviewPolicyV164OwnerPin?,
        val policyStatusDisplay: JsonObject?,
    )

    private data class DirectLinkRead(
        val result: JsonElement,
        val correlation: LinkConsentLedger.ReadCorrelation,
    )

    /** Durable identifiers and digests only; Monitor message text is never saved here. */
    private data class MonitorOperation(
        val operationId: String,
        val groupId: String,
        val monitorEndpointId: String,
        val bodySha256: String,
        var state: String,
        var previewId: String? = null,
        var broadcastId: String? = null,
        var snapshotDigest: String? = null,
        var consentDigest: String? = null,
        var expiresAt: String? = null,
        var grantExpiresAt: String? = null,
        var recipientEndpointIds: List<String> = emptyList(),
        var confirmAttempted: Boolean = false,
        var confirmStatusReconciled: Boolean = false,
        var confirmOperationId: String? = null,
        var confirmSequence: Long? = null,
        var sealedPayload: String? = null,
    )

    private data class State(
        var activeNetworkId: String? = null,
        var pin: Pin? = null,
        var enrollment: Enrollment? = null,
        var ownerApprovalPublicIdentityJson: String? = null,
        var nextSequence: Long = 1,
        var lastResponseSequence: Long = 0,
        var role: String? = null,
        var sessionCapabilitiesReady: Boolean = false,
        var validatedContractRevision: String? = null,
        var validatedCatalogSha256: String? = null,
        var allowedOperations: List<String> = emptyList(),
        var authFenced: Boolean = false,
        var recoveryBlocked: Boolean = false,
        var sessionError: String? = null,
        var previousDeviceMayRemainOnHub: Boolean = false,
        var retiredPending: Pending? = null,
        /** First uncertain Network grant; generic read reconciliation must never retire this fence. */
        var networkGrantUncertainPending: Pending? = null,
        /** Original uncertain delegation ciphertext; a generic snapshot cannot retire this fence. */
        var regroupUncertainPending: Pending? = null,
        var regroupWriteContext: JsonObject? = null,
        var pending: Pending? = null,
        var linkReviewStatusReadContext: LinkReviewStatusReadContext? = null,
        var linkConsentStatusReadContext: LinkConsentStatusReadContext? = null,
        var linkConsentLedger: LinkConsentLedger = LinkConsentLedger.empty(),
        var enrollmentAttempt: EnrollmentAttempt? = null,
        var monitorOperations: MutableMap<String, MonitorOperation> = linkedMapOf(),
        var retiredMonitorOperationIds: MutableSet<String> = linkedSetOf(),
        var outcomeUncertainOperationId: String? = null,
        var uncertainNeedsReconciliation: Boolean = false,
    )

    private data class V16OwnerNetworkProjection(
        val network: JsonObject,
        val group: JsonObject? = null,
        val endpoint: JsonObject? = null,
    )

    private data class RegroupReview(
        val id: String,
        val selectionGeneration: Long,
        val lifecycleGeneration: Long,
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val sessionEpoch: Long,
        val networkId: String,
        val expiresAt: Instant,
        val proposal: JsonObject,
    )

    /** Public metadata needed to validate the exact original status response, including recovery. */
    private data class LinkReviewStatusReadContext(
        val linkId: String,
        val linkVersion: Long,
        val mySide: String,
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val sessionEpoch: Long,
        val operationId: String,
        val sequence: Long,
    )

    /** Fetches public metadata only. This method never establishes or changes trust. */
    fun fetchHubMetadata(baseUrl: String): JsonObject = PROCESS_LOCK.withLock {
        val base = validateBaseUrl(baseUrl)
        val capabilities = httpJson(base, "/v2/client/capabilities", "GET", null, MAX_METADATA_BYTES)
        if (optionalString(capabilities, "contract_revision") != CONTRACT_REVISION ||
            optionalString(capabilities, "catalog_sha256") != CATALOG_SHA256) {
            throw HubSessionException("CONTRACT_MISMATCH", "Hub public contract revision or catalog digest differs from this Client build")
        }
        val identity = httpJson(base, "/v2/client/identity", "GET", null, MAX_METADATA_BYTES)
        // Reject malformed candidate key material, while keeping it explicitly untrusted.
        val parsedPin = ClientWireCrypto.HubPin.parse(identity.toString())
        if (parsedPin.hubId.isBlank()) throw HubSessionException("INVALID_HUB_IDENTITY", "Hub identity is incomplete")
        JsonObject().apply {
            addProperty("trusted", false)
            add("capabilities", capabilities)
            add("identity", identity)
        }
    }

    /**
     * Pins values that the user supplied through an independent trusted channel.
     * No network response is consulted or promoted to a pin here.
     */
    fun pinHub(baseUrl: String, hubId: String, controlPublicIdentityJson: String): JsonObject = PROCESS_LOCK.withLock {
        val base = validateBaseUrl(baseUrl)
        val normalizedHubId = hubId.trim()
        if (normalizedHubId.isEmpty() || normalizedHubId.length > 256) {
            throw HubSessionException("INVALID_HUB_ID", "Enter a valid Hub ID from the independent trust channel")
        }
        val controlJson = parseObject(controlPublicIdentityJson, "Invalid Control public identity")
        val control = try {
            ClientWireCrypto.PublicIdentity.parse(controlJson)
        } catch (_: Exception) {
            throw HubSessionException("INVALID_HUB_IDENTITY", "Control public identity is invalid")
        }
        // Constructing a HubPin enforces the currently supported key version.
        try {
            ClientWireCrypto.HubPin(normalizedHubId, control, 1L)
        } catch (_: Exception) {
            throw HubSessionException("INVALID_HUB_IDENTITY", "Hub ID or Control public identity is invalid")
        }
        val state = readState()
        val old = state.pin
        val canonicalIdentity = control.toJson()
        if (old != null && (old.baseUrl != base || old.hubId != normalizedHubId ||
                old.controlPublicIdentityJson != canonicalIdentity)) {
            requireNetworkGrantReconciled(state)
        }
        if (old != null && (old.baseUrl != base || old.hubId != normalizedHubId ||
                old.controlPublicIdentityJson != canonicalIdentity) &&
            (state.pending != null || state.enrollmentAttempt != null || hasUnresolvedMonitorOperation(state))) {
            if (state.enrollmentAttempt != null) {
                throw HubSessionException("ENROLLMENT_RECOVERY_REQUIRED", "Keep the original Hub address and trust pin while device registration is unresolved")
            }
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Keep the original Hub address and trust pin while enrollment or an encrypted RPC is unresolved")
        }
        if (old != null && (old.baseUrl != base || old.hubId != normalizedHubId ||
                old.controlPublicIdentityJson != canonicalIdentity) && state.linkConsentLedger.writeFence != null) {
            throw HubSessionException("LINK_CONSENT_RECOVERY_REQUIRED", "Resolve the original Link consent packet before changing this Hub pin")
        }
        if (old != null && old.hubId != normalizedHubId) {
            throw HubSessionException("PROFILE_HUB_ID_MISMATCH", "Create an independent profile with its own device identity before trusting a different Hub")
        }
        if (old != null && (old.hubId != normalizedHubId || old.controlPublicIdentityJson != canonicalIdentity)) {
            // A changed trust anchor invalidates the prior enrolled authority and replay state.
            state.previousDeviceMayRemainOnHub = state.enrollment != null || state.previousDeviceMayRemainOnHub
            if (state.pending != null) state.retiredPending = state.pending
            state.enrollment = null
            state.activeNetworkId = null
            state.ownerApprovalPublicIdentityJson = null
            state.nextSequence = 1
            state.lastResponseSequence = 0
            state.role = null
            state.sessionCapabilitiesReady = false
            state.validatedContractRevision = null
            state.validatedCatalogSha256 = null
            state.allowedOperations = emptyList()
            state.authFenced = false
            state.recoveryBlocked = false
            state.sessionError = null
            state.outcomeUncertainOperationId = null
            state.uncertainNeedsReconciliation = false
            state.pending = null
            state.monitorOperations.clear()
            state.retiredMonitorOperationIds.clear()
            state.linkConsentLedger = state.linkConsentLedger.copy(review = null)
        }
        state.pin = Pin(base, normalizedHubId, canonicalIdentity)
        writeState(state)
        JsonObject().apply {
            addProperty("pinned", true)
            addProperty("hubId", normalizedHubId)
            addProperty("baseUrl", base)
            addProperty("controlKeyId", control.id)
        }
    }

    /** Generates a device key once, wrapping its private bytes before any disk write. */
    fun createDeviceIdentity(): JsonObject = PROCESS_LOCK.withLock {
        val alreadyExists = hasAtomicFile(privateKeyFile)
        if (!alreadyExists) {
            val state = readState()
            requireNetworkGrantReconciled(state)
            requireLinkConsentReconciled(state)
        }
        val identity = if (alreadyExists) {
            loadDeviceIdentity()
        } else {
            ClientWireCrypto.Identity.generate()
        }
        try {
            if (!alreadyExists) writeWrappedPrivateJson(identity.privateJson())
            JsonObject().apply {
                add("devicePublicIdentity", JsonParser.parseString(identity.publicIdentity.toJson()).asJsonObject)
            }
        } finally {
            identity.close()
        }
    }

    /**
     * Explicitly abandons the local enrollment and starts a new device identity.
     * This does not revoke the old Hub record; an owner-authorized device must
     * revoke that record separately when the old key may still be usable.
     */
    fun startNewDeviceEnrollment(): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireNetworkGrantReconciled(state)
        requireLinkConsentReconciled(state)
        if (state.pin == null) throw HubSessionException("HUB_NOT_PINNED", "Pin a Hub before creating an enrolled device identity")
        if (state.enrollmentAttempt != null) {
            throw HubSessionException("ENROLLMENT_RECOVERY_REQUIRED", "Enrollment outcome is unknown; do not replace its device identity before Hub reconciliation")
        }
        if (state.pending != null) {
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Do not replace the device key while an encrypted request is unresolved")
        }
        if (hasUnresolvedMonitorOperation(state)) {
            throw HubSessionException("MONITOR_RECOVERY_REQUIRED", "Resolve the original Monitor operation before replacing this device identity")
        }
        state.previousDeviceMayRemainOnHub = state.enrollment != null || state.previousDeviceMayRemainOnHub
        if (state.pending != null) state.retiredPending = state.pending
        state.enrollment = null
        state.activeNetworkId = null
        state.ownerApprovalPublicIdentityJson = null
        state.nextSequence = 1
        state.lastResponseSequence = 0
        state.role = null
        state.sessionCapabilitiesReady = false
        state.validatedContractRevision = null
        state.validatedCatalogSha256 = null
        state.allowedOperations = emptyList()
        state.authFenced = false
        state.recoveryBlocked = false
        state.sessionError = null
        state.outcomeUncertainOperationId = null
        state.uncertainNeedsReconciliation = false
        state.pending = null
        state.monitorOperations.clear()
        state.retiredMonitorOperationIds.clear()
        writeState(state)
        deleteDeviceWrappingKey()
        val identity = ClientWireCrypto.Identity.generate()
        try {
            writeWrappedPrivateJson(identity.privateJson())
            JsonObject().apply {
                add("devicePublicIdentity", JsonParser.parseString(identity.publicIdentity.toJson()).asJsonObject)
                addProperty("previousDeviceMayRemainOnHub", state.previousDeviceMayRemainOnHub)
            }
        } finally {
            identity.close()
        }
    }

    /** Locally verifies the independently owner-signed grant before sending enrollment. */
    fun enroll(
        ownerId: String,
        ownerKeyId: String,
        ownerPublicIdentityJson: String,
        deviceId: String,
        ownerDeviceGrantBase64: String,
    ): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireNetworkGrantReconciled(state)
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Pin the Hub through an independent trusted channel first")
        if (state.enrollment != null) throw HubSessionException("ALREADY_ENROLLED", "This local device already has an enrollment")
        if (state.enrollmentAttempt != null) {
            throw HubSessionException("ENROLLMENT_RECOVERY_REQUIRED", "Enrollment outcome is unknown; do not repeat the device registration")
        }
        val checkedOwner = ownerId.trim()
        val checkedKeyId = ownerKeyId.trim()
        val checkedDeviceId = deviceId.trim()
        if (checkedOwner.isEmpty() || checkedKeyId.isEmpty() || checkedDeviceId.isEmpty()) {
            throw HubSessionException("INVALID_ENROLLMENT", "Owner, owner key, and device IDs are required")
        }
        val deviceIdentity = loadDeviceIdentity()
        try {
            verifyLivePinnedIdentity(pin)
            val ownerPublicJson = parseObject(ownerPublicIdentityJson, "Invalid owner approval public identity")
            val ownerPublic = try {
                ClientWireCrypto.PublicIdentity.parse(ownerPublicJson)
            } catch (_: Exception) {
                throw HubSessionException("INVALID_OWNER_IDENTITY", "Owner approval public identity is invalid")
            }
            if (ownerPublic.id != checkedKeyId) {
                throw HubSessionException("OWNER_KEY_ID_MISMATCH", "Owner key ID does not match its public identity")
            }
            val grantBytes = decodeCanonicalBase64(ownerDeviceGrantBase64)
            val grantText = String(grantBytes, StandardCharsets.UTF_8)
            try {
                ClientWireCrypto.verifyOwnerGrant(
                    grantText,
                    ownerPublic,
                    checkedOwner,
                    checkedDeviceId,
                    deviceIdentity.publicIdentity,
                    pin.hubId,
                )
            } catch (_: Exception) {
                throw HubSessionException("INVALID_OWNER_GRANT", "Owner grant signature or device binding is invalid")
            }
            val input = JsonObject().apply {
                addProperty("owner_id", checkedOwner)
                addProperty("owner_key_id", checkedKeyId)
                addProperty("device_id", checkedDeviceId)
                add("device_public_identity", JsonParser.parseString(deviceIdentity.publicIdentity.toJson()).asJsonObject)
                addProperty("owner_device_grant", Base64.encodeToString(grantBytes, Base64.NO_WRAP))
            }
            val grantDigest = MessageDigest.getInstance("SHA-256").digest(grantBytes)
                .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            val requestJson = input.toString()
            state.enrollmentAttempt = EnrollmentAttempt(
                checkedOwner, checkedDeviceId, deviceIdentity.publicIdentity.id, grantDigest, requestJson,
            )
            state.ownerApprovalPublicIdentityJson = ownerPublic.toJson()
            writeState(state) // An ambiguous POST must not be recreated with a new nonce or device key.
            val response = httpJson(pin.baseUrl, "/v2/client/devices/enroll", "POST", requestJson, 48 * 1024, expectedStatus = 201)
            finishEnrollment(state, response, state.enrollmentAttempt!!)
        } finally {
            deviceIdentity.close()
        }
    }

    /** Resends the exact persisted enrollment bytes, even when the original Grant has expired. */
    fun recoverEnrollment(): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireNetworkGrantReconciled(state)
        if (state.enrollment != null) throw HubSessionException("ALREADY_ENROLLED", "Device enrollment already completed")
        val attempt = state.enrollmentAttempt
            ?: throw HubSessionException("NO_PENDING_ENROLLMENT", "There is no device enrollment to recover")
        val exactRequest = attempt.requestJson
            ?: throw HubSessionException("ENROLLMENT_RECOVERY_UNAVAILABLE", "Older enrollment attempt has no preserved request bytes")
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val device = loadDeviceIdentity()
        try {
            if (device.publicIdentity.id != attempt.deviceKeyId) {
                throw HubSessionException("DEVICE_KEY_MISMATCH", "Persisted enrollment uses a different device identity")
            }
            verifyLivePinnedIdentity(pin)
            val original = parseObject(exactRequest, "Persisted enrollment is invalid")
            val originalGrant = decodeCanonicalBase64(requiredString(original, "owner_device_grant"))
            val digest = MessageDigest.getInstance("SHA-256").digest(originalGrant)
                .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            if (digest != attempt.grantSha256 ||
                requiredString(original, "owner_id") != attempt.ownerId ||
                requiredString(original, "device_id") != attempt.deviceId ||
                requiredString(original.getAsJsonObject("device_public_identity"), "id") != attempt.deviceKeyId) {
                throw HubSessionException("ENROLLMENT_RECOVERY_INVALID", "Persisted enrollment identity or Grant changed")
            }
            val response = httpJson(pin.baseUrl, "/v2/client/devices/enroll", "POST", exactRequest, 48 * 1024, expectedStatus = 201)
            finishEnrollment(state, response, attempt)
        } finally {
            device.close()
        }
    }

    private fun finishEnrollment(state: State, response: JsonObject, attempt: EnrollmentAttempt): JsonObject {
        val owner = requiredString(response, "owner_id")
        val device = requiredString(response, "device_id")
        val epoch = longValue(response, "session_epoch")
        val keyVersion = longValue(response, "device_key_version")
        val deviceState = requiredString(response, "state")
        if (owner != attempt.ownerId || device != attempt.deviceId || epoch < 1 || keyVersion < 1 || deviceState != "ACTIVE") {
            throw HubSessionException("INVALID_ENROLLMENT_RESPONSE", "Hub returned an enrollment that does not match this request")
        }
        state.enrollment = Enrollment(owner, device, epoch, keyVersion, deviceState)
        state.activeNetworkId = null
        state.monitorOperations.clear()
        state.retiredMonitorOperationIds.clear()
        state.nextSequence = 1
        state.lastResponseSequence = 0
        state.role = null
        state.sessionCapabilitiesReady = false
        state.validatedContractRevision = null
        state.validatedCatalogSha256 = null
        state.allowedOperations = emptyList()
        state.authFenced = false
        state.recoveryBlocked = false
        state.sessionError = null
        state.pending = null
        state.enrollmentAttempt = null
        writeState(state)
        return JsonObject().apply {
            addProperty("ownerId", owner)
            addProperty("deviceId", device)
            addProperty("sessionEpoch", epoch)
            addProperty("deviceKeyVersion", keyVersion)
            addProperty("state", deviceState)
        }
    }

    /** Starts one encrypted RPC after persisting sequence and exact request bytes. */
    fun rpc(operation: String, body: JsonObject, operationId: String? = null): JsonObject = PROCESS_LOCK.withLock {
        if (operation in LINK_CONSENT_OPERATIONS && operation != "link.review_policy_status") {
            throw HubSessionException("VERIFIED_LINK_CONSENT_FLOW_REQUIRED", "Use the dedicated native Owner-pinned Link consent flow")
        }
        GroupDirectoryPermissionValidation.guardGenericRpc(operation, body)
        if (operation == "link.review_policy_status") {
            throw HubSessionException("VERIFIED_LINK_REVIEW_STATUS_FLOW_REQUIRED", "Use the fresh owner-scoped Link policy status read flow")
        }
        if (operation in setOf("topology.regroup_proposal", "topology.delegation_issue", "topology.delegation_revoke")) {
            throw HubSessionException("VERIFIED_REGROUP_FLOW_REQUIRED", "Use the scope-bound Owner delegation review flow")
        }
        if (operation.startsWith("group.key_")) {
            throw HubSessionException("VERIFIED_GROUP_FLOW_REQUIRED", "Use the verified Group key consent flow")
        }
        if (operation.startsWith("monitor.broadcast_")) {
            throw HubSessionException("VERIFIED_MONITOR_FLOW_REQUIRED", "Use the dedicated Monitor broadcast flow")
        }
        if (operation.startsWith("network.key_")) {
            throw HubSessionException("VERIFIED_NETWORK_FLOW_REQUIRED", "Use the verified Network Endpoint key consent flow")
        }
        requireImplementedOperation(operation)
        val state = readState()
        requireReadyForRpc(state)
        if (state.pending != null) {
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact pending encrypted request before starting another RPC")
        }
        validateOperation(state, operation)
        if (operation == "network.directory") {
            return@withLock networkDirectoryRead(state, body, operationId)
        }
        if (operation == "topology.endpoint_admission_preview") {
            return@withLock topologyEndpointAdmissionPreview(state, body, operationId)
        }
        createAndSend(state, operation, body, operationId)
    }

    /** Reads one exact proposal and binds a short-lived local review to this selection. */
    fun previewRegroupDelegation(proposalId: String, selectionGeneration: Long): JsonObject = PROCESS_LOCK.withLock {
        require(selectionGeneration > 0)
        val selector = requestToken(JsonObject().apply { addProperty("proposal_id", proposalId) }, "proposal_id")
        regroupReviews.remove(directory.absolutePath)
        val lifecycle = regroupLifecycleGeneration.get()
        val state = readState()
        val (proposal, _) = readRegroupProjection(state, selector)
        if (lifecycle != regroupLifecycleGeneration.get()) {
            throw HubSessionException("REGROUP_REVIEW_STALE", "App left the foreground during this review")
        }
        val now = Instant.now()
        regroupReviews.entries.removeAll { it.value.expiresAt <= now }
        if (regroupReviews.size >= 128) throw HubSessionException("REGROUP_REVIEW_CAPACITY", "Too many unresolved local reviews")
        val review = RegroupReview(UUID.randomUUID().toString(), selectionGeneration, lifecycle, state.pin!!.hubId,
            state.enrollment!!.ownerId, state.enrollment!!.deviceId, state.enrollment!!.sessionEpoch,
            state.activeNetworkId!!, now.plusSeconds(120), proposal)
        regroupReviews[directory.absolutePath] = review
        JsonObject().apply { addProperty("reviewId", review.id); add("proposal", proposal.deepCopy()) }
    }

    /** Grants only the exact reviewed action once; the server still guards versions and execution. */
    fun issueRegroupDelegation(reviewId: String, expiresAt: String, confirmed: Boolean,
                              selectionGeneration: Long): JsonObject = PROCESS_LOCK.withLock {
        if (!confirmed) throw HubSessionException("EXPLICIT_CONFIRMATION_REQUIRED", "Confirm the exact one-use delegation")
        val state = readState()
        requireRegroupReconciled(state)
        val review = consumeRegroupReview(state, reviewId, selectionGeneration)
        val (proposal, topology) = readRegroupProjection(state, requiredString(review.proposal, "proposal_id"),
            "topology.delegation_issue")
        try {
            require(proposal == review.proposal)
            RegroupDelegationValidation.currentIssue(proposal, topology, Instant.now())
            RegroupDelegationValidation.issueExpiry(proposal, expiresAt, Instant.now())
        } catch (_: Exception) {
            throw HubSessionException("REGROUP_REVIEW_STALE", "Proposal, Group versions, binding or expiry changed; review again")
        }
        val body = JsonObject().apply {
            addProperty("proposal_id", requiredString(proposal, "proposal_id"))
            addProperty("expires_at", expiresAt)
            addProperty("max_uses", 1)
        }
        sendRegroupMutation(state, "topology.delegation_issue", body, proposal, review)
    }

    /** Revokes only the exact current delegation ID/version shown in this device's review. */
    fun revokeRegroupDelegation(reviewId: String, delegationId: String, expectedVersion: Long,
                               confirmed: Boolean, selectionGeneration: Long): JsonObject = PROCESS_LOCK.withLock {
        if (!confirmed) throw HubSessionException("EXPLICIT_CONFIRMATION_REQUIRED", "Confirm the exact delegation revocation")
        if (expectedVersion < 1 || expectedVersion >= 9_007_199_254_740_991L) {
            throw HubSessionException("INVALID_REGROUP_VERSION", "Delegation CAS version is invalid")
        }
        val state = readState()
        requireRegroupReconciled(state)
        val review = consumeRegroupReview(state, reviewId, selectionGeneration)
        val (proposal, _) = readRegroupProjection(state, requiredString(review.proposal, "proposal_id"),
            "topology.delegation_revoke")
        val delegation = proposal.get("delegation")?.takeIf { it.isJsonObject }?.asJsonObject
        if (proposal != review.proposal || delegation == null ||
            optionalString(delegation, "delegation_id") != delegationId ||
            optionalString(delegation, "state") != "ACTIVE" || longValue(delegation, "version") != expectedVersion) {
            throw HubSessionException("REGROUP_REVIEW_STALE", "The exact delegation changed; read and confirm its current version")
        }
        val body = JsonObject().apply {
            addProperty("delegation_id", delegationId)
            addProperty("expected_version", expectedVersion)
        }
        sendRegroupMutation(state, "topology.delegation_revoke", body, proposal, review)
    }

    private fun consumeRegroupReview(state: State, reviewId: String, selectionGeneration: Long): RegroupReview {
        val review = regroupReviews.remove(directory.absolutePath)
        val enrollment = state.enrollment
        if (review == null || review.id != reviewId || review.selectionGeneration != selectionGeneration ||
            review.lifecycleGeneration != regroupLifecycleGeneration.get() ||
            review.expiresAt <= Instant.now() || review.hubId != state.pin?.hubId ||
            enrollment == null || review.ownerId != enrollment.ownerId || review.deviceId != enrollment.deviceId ||
            review.sessionEpoch != enrollment.sessionEpoch || review.networkId != state.activeNetworkId) {
            throw HubSessionException("REGROUP_REVIEW_STALE", "Local review expired or its Hub, device or selection changed")
        }
        return review
    }

    private fun readRegroupProjection(state: State, proposalId: String,
                                      writeOperation: String? = null): Pair<JsonObject, JsonObject> {
        requireReadyForRpc(state)
        if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original ciphertext first")
        val networkId = state.activeNetworkId ?: throw HubSessionException("NETWORK_SELECTION_REQUIRED", "Select a Network explicitly")
        val operations = setOf("topology.snapshot", "topology.regroup_proposal") + listOfNotNull(writeOperation)
        requireNetworkAvailability(state, operations)
        val response = createAndSend(state, "topology.regroup_proposal", JsonObject().apply {
            addProperty("proposal_id", proposalId)
        })
        if (response.get("ok")?.asBoolean != true) {
            throw HubSessionException("REGROUP_PROPOSAL_UNAVAILABLE", "Hub did not authorize the exact proposal read")
        }
        val topologyResponse = createAndSend(state, "topology.snapshot", JsonObject())
        try {
            require(topologyResponse.get("ok")?.asBoolean == true)
            val topology = topologyResponse.getAsJsonObject("result")
            val proposal = RegroupDelegationValidation.proposal(response.getAsJsonObject("result"), topology,
                state.pin!!.hubId, state.enrollment!!.ownerId, networkId, proposalId)
            return proposal to topology
        } catch (_: Exception) {
            throw HubSessionException("REGROUP_PROJECTION_INVALID", "Hub proposal does not match the selected Owner topology")
        }
    }

    private fun sendRegroupMutation(state: State, operation: String, body: JsonObject,
                                    proposal: JsonObject, review: RegroupReview): JsonObject {
        val context = JsonObject().apply {
            addProperty("operation", operation)
            for (key in listOf("proposal_id", "hub_id", "owner_id")) add(key, proposal.get(key).deepCopy())
            add("input", proposal.getAsJsonObject("input").deepCopy())
            add("request", body.deepCopy())
        }
        return createAndSend(state, operation, body, beforePersist = { _, _, _ ->
            if (review.lifecycleGeneration != regroupLifecycleGeneration.get() || review.expiresAt <= Instant.now()) {
                throw HubSessionException("REGROUP_REVIEW_STALE", "Foreground review expired before dispatch")
            }
            state.regroupUncertainPending = state.pending
            state.regroupWriteContext = context
        })
    }

    /** Runs for both ordinary responses and original-packet recovery before clearing pending. */
    private fun applyRegroupRpcResult(state: State, pending: Pending, body: JsonObject,
                                      ok: Boolean, uncertain: Boolean) {
        if (pending.operation !in setOf("topology.delegation_issue", "topology.delegation_revoke")) return
        val original = state.regroupUncertainPending
        val context = state.regroupWriteContext
        if (original == null || original.operationId != pending.operationId ||
            original.packetJson != pending.packetJson || context == null ||
            optionalString(context, "operation") != pending.operation) {
            throw HubSessionException("REGROUP_RECOVERY_CONTEXT_INVALID", "The original delegation recovery context is missing")
        }
        if (uncertain) return
        if (ok) {
            try {
                val result = RegroupDelegationValidation.delegation(body.getAsJsonObject("result"), context)
                val request = context.getAsJsonObject("request")
                if (pending.operation == "topology.delegation_issue") {
                    require(requiredString(result, "state") == "ACTIVE" && longValue(result, "version") == 1L &&
                        Instant.parse(requiredString(result, "expires_at")) == Instant.parse(requiredString(request, "expires_at")))
                } else {
                    require(requiredString(result, "delegation_id") == requiredString(request, "delegation_id") &&
                        requiredString(result, "state") == "REVOKED" &&
                        longValue(result, "version") == longValue(request, "expected_version") + 1)
                }
            } catch (_: Exception) {
                throw HubSessionException("REGROUP_DELEGATION_INVALID", "Authenticated result differs from the original confirmed delegation; keep pending")
            }
        }
        state.regroupUncertainPending = null
        state.regroupWriteContext = null
    }

    private fun requireRegroupReconciled(state: State) {
        if (state.regroupUncertainPending != null) {
            throw HubSessionException("REGROUP_RECONCILIATION_REQUIRED", "Keep the original uncertain delegation ciphertext; a snapshot or proposal projection cannot prove this operation's outcome")
        }
    }

    /** Safe Monitor operation index, suitable for restoring UI recovery after process death. */
    fun monitorBroadcastOperations(): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        JsonObject().apply {
            add("operations", JsonArray().apply {
                state.monitorOperations.values.forEach { operation ->
                    add(monitorOperationSummary(operation))
                }
            })
        }
    }

    /** Locally compares an in-memory draft with one stored body digest; no RPC or disk write occurs. */
    fun monitorBroadcastBodyMatches(previewId: String, body: String): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        val preview = previewId.trim().takeIf { it.isNotEmpty() }
            ?: throw HubSessionException("INVALID_PREVIEW_ID", "Body comparison requires a preview ID")
        val metadata = state.monitorOperations.values.firstOrNull { it.previewId == preview }
            ?: throw HubSessionException("UNKNOWN_MONITOR_PREVIEW", "Preview ID is not in this device's verified Monitor records")
        val digest = monitorBodyDigest(body)
        JsonObject().apply {
            addProperty("matches", digest == metadata.bodySha256)
            addProperty("bodySha256", digest)
        }
    }

    /** Starts a Monitor preview using only selectors and the exact UTF-8 digest. */
    fun monitorBroadcastPrepare(
        groupId: String,
        monitorEndpointId: String,
        body: String,
        operationId: String? = null,
    ): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireReadyForRpc(state)
        if (state.pending != null) {
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact pending encrypted request before starting Monitor prepare")
        }
        validateOperation(state, "monitor.broadcast_prepare")
        val group = validateMonitorSelector(groupId, "Group ID")
        val monitor = validateMonitorSelector(monitorEndpointId, "Monitor Endpoint ID")
        val digest = monitorBodyDigest(body)
        val logicalId = operationId?.trim()?.takeIf { it.isNotEmpty() } ?: UUID.randomUUID().toString()
        if (logicalId.length > 256) throw HubSessionException("INVALID_OPERATION_ID", "Monitor Prepare operation ID is too long")
        if (logicalId in state.monitorOperations || logicalId in state.retiredMonitorOperationIds) {
            throw HubSessionException("MONITOR_PREPARE_RECOVERY_REQUIRED", "This Monitor Prepare operation already exists; recover its original operation ID")
        }
        pruneMonitorOperations(state)
        val unresolved = state.monitorOperations.values.firstOrNull {
            it.state in setOf("PREPARE_PENDING", "PREPARE_UNCERTAIN", "RECOVERY_UNCERTAIN", "CONFIRM_PENDING", "CONFIRM_UNCERTAIN") ||
                it.confirmAttempted && !it.confirmStatusReconciled
        }
        if (unresolved != null) {
            throw HubSessionException("MONITOR_PREPARE_RECOVERY_REQUIRED", "Recover Monitor Prepare operation ${unresolved.operationId} before starting another")
        }
        if (state.monitorOperations.size >= 128) {
            throw HubSessionException("MONITOR_STATE_CAPACITY", "Temporary Monitor history capacity reached; retry after older previews expire")
        }
        val metadata = MonitorOperation(
            operationId = logicalId,
            groupId = group,
            monitorEndpointId = monitor,
            bodySha256 = digest,
            state = "PREPARE_PENDING",
        )
        state.monitorOperations[logicalId] = metadata
        writeState(state) // Preserve the original Prepare operation ID before any network I/O.

        val response = try {
            createAndSend(state, "monitor.broadcast_prepare", JsonObject().apply {
                addProperty("group_id", group)
                addProperty("monitor_endpoint_id", monitor)
                addProperty("body_sha256", digest)
            }, logicalId, monitorOperationId = logicalId)
        } catch (error: Exception) {
            // Pending packet and operation metadata remain durable for exact recovery.
            throw error
        }
        if (!response.get("ok").asBoolean) {
            if (optionalString(response, "errorCode") == "OUTCOME_UNCERTAIN") {
                metadata.state = "PREPARE_UNCERTAIN"
                writeState(state)
                return@withLock JsonObject().apply {
                    addProperty("operationId", logicalId)
                    addProperty("outcomeUncertain", true)
                    addProperty("recoveryRequired", true)
                    addProperty("errorCode", "OUTCOME_UNCERTAIN")
                }
            }
            metadata.state = "REJECTED"
            writeState(state)
            return@withLock response.deepCopy().apply { addProperty("monitorOperationId", logicalId) }
        }
        val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("INVALID_MONITOR_PREPARE", "Hub returned no Monitor preview")
        val verified = verifyMonitorPrepareAllowExpired(state, metadata, result)
        updateMonitorPreview(metadata, result, verified)
        metadata.state = monitorResultState(result)
        markMonitorAuthorizationExpired(metadata, verified)
        writeState(state)
        monitorPrepareView(metadata, verified, result, response)
    }

    /** Reconciles only the durable original Prepare operation ID. */
    fun monitorBroadcastRecover(operationId: String): JsonObject = PROCESS_LOCK.withLock {
        var state = readState()
        requireReadyForRpc(state)
        val logicalId = operationId.trim().takeIf { it.isNotEmpty() }
            ?: throw HubSessionException("INVALID_OPERATION_ID", "Monitor recovery requires the original Prepare operation ID")
        var metadata = state.monitorOperations[logicalId]
            ?: throw HubSessionException("UNKNOWN_MONITOR_OPERATION", "Monitor operation ID is not in this device's recovery record")
        if (metadata.confirmAttempted && !metadata.confirmStatusReconciled) {
            throw HubSessionException("MONITOR_STATUS_REQUIRED", "An uncertain confirmation must be reconciled through status for the same preview")
        }
        if (metadata.state == "EXPIRED" && metadata.previewId != null) {
            return@withLock JsonObject().apply {
                addProperty("operationId", logicalId)
                addProperty("previewId", metadata.previewId)
                addProperty("broadcastId", metadata.broadcastId)
                addProperty("status", "PREPARED")
                addProperty("expiresAt", metadata.expiresAt)
                metadata.grantExpiresAt?.let { addProperty("grantExpiresAt", it) }
                monitorValidUntil(metadata)?.let { addProperty("validUntil", it.toString()) }
                addProperty("recoveryResolved", true)
                addProperty("canConfirm", false)
                addProperty("statusAvailable", true)
            }
        }
        if (metadata.state == "REJECTED") {
            return@withLock JsonObject().apply {
                addProperty("operationId", logicalId)
                addProperty("state", "REJECTED")
                addProperty("recoveryResolved", true)
                addProperty("canConfirm", false)
            }
        }
        if (state.pending != null) {
            val pending = state.pending!!
            if (pending.operation != "monitor.broadcast_prepare" || pending.operationId != logicalId) {
                throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact pending encrypted request before Monitor lookup")
            }
            val exact = recoverPending()
            // recoverPending reads and commits its own State instance. Reload it before
            // touching Monitor metadata so stale sequence/pending fields cannot be restored.
            state = readState()
            metadata = state.monitorOperations[logicalId]
                ?: throw HubSessionException("UNKNOWN_MONITOR_OPERATION", "Monitor recovery metadata disappeared")
            if (exact.get("ok")?.takeIf { it.isJsonPrimitive }?.asBoolean == true) {
                val result = exact.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                    ?: throw HubSessionException("INVALID_MONITOR_PREPARE", "Recovered Prepare omitted its preview")
                return@withLock acceptMonitorPreview(state, metadata, result, exact)
            }
            if (optionalString(exact, "errorCode") != "OUTCOME_UNCERTAIN") {
                metadata.state = "REJECTED"
                writeState(state)
                return@withLock exact.deepCopy().apply { addProperty("monitorOperationId", logicalId) }
            }
            metadata.state = "PREPARE_UNCERTAIN"
            writeState(state)
        }
        validateOperation(state, "monitor.broadcast_recover")
        val lookup = createAndSend(state, "monitor.broadcast_recover", JsonObject().apply {
            addProperty("operation_id", logicalId)
        }, monitorOperationId = logicalId)
        if (lookup.get("ok")?.takeIf { it.isJsonPrimitive }?.asBoolean != true) {
            // An absent/unknown lookup is not permission to issue Prepare again.
            if (optionalString(lookup, "errorCode") == "OUTCOME_UNCERTAIN") {
                metadata.state = "RECOVERY_UNCERTAIN"
                writeState(state)
            }
            return@withLock lookup.deepCopy().apply {
                addProperty("monitorOperationId", logicalId)
                addProperty("recoveryUnresolved", true)
            }
        }
        val result = lookup.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("INVALID_MONITOR_RECOVERY", "Hub returned no recovered Monitor preview")
        acceptMonitorPreview(state, metadata, result, lookup)
    }

    /** Confirms a reviewed preview exactly once; the sealed and outer RPC bytes are persisted together. */
    fun monitorBroadcastConfirm(previewId: String, body: String, consentDigest: String): JsonObject =
        PROCESS_LOCK.withLock {
            val state = readState()
            requireReadyForRpc(state)
            if (state.pending != null) {
                throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact pending encrypted request before Monitor confirmation")
            }
            val preview = previewId.trim().takeIf { it.isNotEmpty() }
                ?: throw HubSessionException("INVALID_PREVIEW_ID", "Monitor confirmation requires a preview ID")
            val metadata = state.monitorOperations.values.firstOrNull { it.previewId == preview }
                ?: throw HubSessionException("UNKNOWN_MONITOR_PREVIEW", "Preview ID is not in this device's verified Monitor records")
            if (metadata.confirmAttempted) {
                throw HubSessionException("MONITOR_CONFIRM_RECOVERY_REQUIRED", "This preview already has a durable confirmation attempt; check its status")
            }
            if (metadata.state != "PREPARED") {
                throw HubSessionException("MONITOR_PREVIEW_NOT_CONFIRMABLE", "Only an unexpired PREPARED preview can be confirmed")
            }
            if (monitorValidUntil(metadata)?.isAfter(Instant.now()) == false) {
                metadata.state = "EXPIRED"
                writeState(state)
                throw HubSessionException("MONITOR_PREVIEW_NOT_CONFIRMABLE", "Monitor preview or Group authorization has expired")
            }
            val digest = monitorBodyDigest(body)
            if (digest != metadata.bodySha256) {
                throw HubSessionException("MONITOR_BODY_CHANGED", "Message text differs from the reviewed Monitor preview")
            }
            if (!constantTimeHexEquals(consentDigest, metadata.consentDigest)) {
                throw HubSessionException("MONITOR_CONSENT_CHANGED", "Consent review differs from the verified Monitor preview")
            }
            validateOperation(state, "monitor.broadcast_confirm")
            val refreshed = recoverMonitorPreviewForConfirm(state, metadata)
            preflightMonitorAuthorization(state, metadata, refreshed)
            if (!refreshed.canConfirm) {
                metadata.state = "EXPIRED"
                writeState(state)
                throw HubSessionException("MONITOR_PREVIEW_NOT_CONFIRMABLE", "Monitor preview or its Owner grant expired before confirmation")
            }
            val logicalId = UUID.randomUUID().toString()
            var exactSealedPayload: String? = null
            createAndSend(
                state,
                "monitor.broadcast_confirm",
                JsonObject(),
                logicalId,
                monitorOperationId = metadata.operationId,
                bodyBuilder = { device, currentEnrollment, sequence ->
                    val sealed = try {
                        MonitorBroadcastCrypto.sealBody(
                            device,
                            refreshed,
                            currentEnrollment.deviceId,
                            currentEnrollment.sessionEpoch,
                            currentEnrollment.deviceKeyVersion,
                            sequence,
                            body,
                        )
                    } catch (_: Exception) {
                        throw HubSessionException("MONITOR_SEAL_FAILED", "Could not seal the reviewed Monitor message")
                    }
                    exactSealedPayload = sealed
                    JsonObject().apply {
                        addProperty("preview_id", metadata.previewId)
                        addProperty("snapshot_digest", metadata.snapshotDigest)
                        addProperty("body_sha256", metadata.bodySha256)
                        addProperty("sealed_payload", sealed)
                    }
                },
                beforePersist = { operation, sequence, requestBody ->
                    metadata.confirmAttempted = true
                    metadata.confirmOperationId = operation
                    metadata.confirmSequence = sequence
                    metadata.state = "CONFIRM_PENDING"
                    metadata.sealedPayload = exactSealedPayload
                    if (metadata.sealedPayload.isNullOrEmpty() ||
                        requestBody.get("sealed_payload")?.asString != metadata.sealedPayload) {
                        throw HubSessionException("MONITOR_SEAL_FAILED", "Sealed Monitor payload was not available for durable recovery")
                    }
                },
            ).let { response ->
                if (response.get("ok")?.takeIf { it.isJsonPrimitive }?.asBoolean == true) {
                    val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                        ?: throw HubSessionException("INVALID_MONITOR_CONFIRM", "Hub returned no Monitor confirmation result")
                    validateMonitorConfirmResult(metadata, result)
                    metadata.state = monitorResultState(result)
                    metadata.confirmStatusReconciled = true
                    writeState(state)
                    return@withLock response.deepCopy().apply {
                        addProperty("previewId", metadata.previewId)
                        addProperty("confirmed", true)
                    }
                }
                if (optionalString(response, "errorCode") == "OUTCOME_UNCERTAIN") {
                    metadata.state = "CONFIRM_UNCERTAIN"
                    writeState(state)
                    return@withLock JsonObject().apply {
                        addProperty("operationId", metadata.confirmOperationId)
                        addProperty("previewId", metadata.previewId)
                        addProperty("outcomeUncertain", true)
                        addProperty("statusRequired", true)
                        addProperty("errorCode", "OUTCOME_UNCERTAIN")
                    }
                }
                metadata.state = "CONFIRM_REJECTED"
                writeState(state)
                response.deepCopy().apply { addProperty("previewId", metadata.previewId) }
            }
        }

    /** Reads recipient outcomes for one locally verified preview only. */
    fun monitorBroadcastStatus(previewId: String): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireReadyForRpc(state)
        if (state.pending != null) {
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact pending encrypted request before Monitor status")
        }
        val preview = previewId.trim().takeIf { it.isNotEmpty() }
            ?: throw HubSessionException("INVALID_PREVIEW_ID", "Monitor status requires a preview ID")
        val metadata = state.monitorOperations.values.firstOrNull { it.previewId == preview }
            ?: throw HubSessionException("UNKNOWN_MONITOR_PREVIEW", "Preview ID is not in this device's verified Monitor records")
        validateOperation(state, "monitor.broadcast_status")
        val response = createAndSend(state, "monitor.broadcast_status", JsonObject().apply {
            addProperty("preview_id", preview)
        }, monitorOperationId = metadata.operationId)
        if (response.get("ok")?.takeIf { it.isJsonPrimitive }?.asBoolean != true) return@withLock response
        val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("INVALID_MONITOR_STATUS", "Hub returned no Monitor status")
        validateMonitorStatusResult(metadata, result)
        metadata.state = monitorStatusDisplayState(metadata, result)
        metadata.confirmStatusReconciled = true
        if (metadata.confirmAttempted && state.uncertainNeedsReconciliation &&
            state.outcomeUncertainOperationId == metadata.confirmOperationId) {
            clearMonitorUncertainLatch(state, metadata)
        } else {
            writeState(state)
        }
        response
    }

    /** Returns a manifest only after independent proof and digest validation. */
    fun previewGroupKey(groupId: String, endpointId: String, ownerKeyId: String): JsonObject =
        PROCESS_LOCK.withLock {
            val state = readState()
            requireReadyForRpc(state)
            if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original request first")
            validateOperation(state, "group.key_manifest")
            val trustedOwner = state.ownerApprovalPublicIdentityJson
                ?: throw HubSessionException("OWNER_PUBLIC_KEY_REQUIRED", "A pinned owner approval key is required")
            val trustedKeyId = try { ClientWireCrypto.PublicIdentity.parse(
                parseObject(trustedOwner, "Invalid owner key")).id }
                catch (_: Exception) { throw HubSessionException("OWNER_PUBLIC_KEY_INVALID", "Saved owner approval key is invalid") }
            if (trustedKeyId != ownerKeyId) {
                throw HubSessionException("OWNER_KEY_ID_MISMATCH", "Selected owner key differs from the enrollment trust key")
            }
            val issued = Instant.now().truncatedTo(ChronoUnit.SECONDS)
            val response = createAndSend(state, "group.key_manifest", groupManifestRequest(
                groupId, endpointId, ownerKeyId, issued.toString(), issued.plusSeconds(900).toString()), null)
            verifiedGroupManifest(response, state, groupId, endpointId, ownerKeyId)
        }

    /**
     * Reads and verifies the exact manifest named by an externally signed
     * Owner proof. This is used to show the object being approved before the
     * separate grant call re-reads it under the same digest guard.
     */
    fun previewGroupKeyGrant(groupId: String, endpointId: String, ownerKeyId: String,
                             expectedDigest: String, signedProofBase64: String): JsonObject =
        PROCESS_LOCK.withLock {
            val state = readState()
            requireReadyForRpc(state)
            if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original request first")
            verifiedGroupManifestForOwnerProof(state, groupId, endpointId, ownerKeyId,
                expectedDigest, signedProofBase64)
        }

    /** Requires a separate owner signature and a fresh, identical Hub manifest. */
    fun grantGroupKey(groupId: String, endpointId: String, ownerKeyId: String,
                      expectedDigest: String, signedProofBase64: String): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireReadyForRpc(state)
        if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original request first")
        validateOperation(state, "group.key_grant")
        val verified = verifiedGroupManifestForOwnerProof(state, groupId, endpointId,
            ownerKeyId, expectedDigest, signedProofBase64)
        createAndSend(state, "group.key_grant", JsonObject().apply {
            addProperty("group_id", groupId)
            addProperty("endpoint_id", endpointId)
            addProperty("owner_key_id", ownerKeyId)
            addProperty("signed_proof", signedProofBase64)
        }, null)
    }

    /** Reads the current owner-scoped Group key grant through encrypted RPC. */
    fun groupKeyStatus(groupId: String, endpointId: String): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireReadyForRpc(state)
        if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original request first")
        validateOperation(state, "group.key_status")
        createAndSend(state, "group.key_status", JsonObject().apply {
            addProperty("group_id", groupId)
            addProperty("endpoint_id", endpointId)
        }, null)
    }

    /** A verified Owner preview for the explicitly selected Network; it grants no peer permission. */
    fun previewNetworkKey(networkId: String, endpointId: String, ownerKeyId: String): JsonObject =
        PROCESS_LOCK.withLock {
            val state = readState()
            val owner = requireNetworkOwner(state, networkId, ownerKeyId)
            requireNetworkAvailability(state, setOf("topology.snapshot", "network.key_manifest"))
            verifiedNetworkManifest(state, networkId, endpointId, owner)
        }

    /** Verifies an external Owner proof against a newly read, identical complete manifest. */
    fun previewNetworkKeyGrant(networkId: String, endpointId: String, ownerKeyId: String,
                               expectedDigest: String, signedProofBase64: String): JsonObject =
        PROCESS_LOCK.withLock {
            val state = readState()
            val owner = requireNetworkOwner(state, networkId, ownerKeyId)
            val proof = decodeNetworkOwnerProof(expectedDigest, signedProofBase64)
            requireNetworkAvailability(state, setOf("topology.snapshot", "network.key_manifest"))
            verifiedNetworkManifestForOwnerProof(state, networkId, endpointId, owner,
                expectedDigest, proof)
        }

    /** Keeps Owner private material external and verifies scope and expiry again before sealing. */
    fun grantNetworkKey(networkId: String, endpointId: String, ownerKeyId: String,
                        expectedDigest: String, signedProofBase64: String): JsonObject =
        PROCESS_LOCK.withLock {
            val state = readState()
            requireNetworkGrantReconciled(state)
            val owner = requireNetworkOwner(state, networkId, ownerKeyId)
            val proof = decodeNetworkOwnerProof(expectedDigest, signedProofBase64)
            requireNetworkAvailability(state, setOf("topology.snapshot", "network.key_manifest", "network.key_grant"))
            val verified = verifiedNetworkManifestForOwnerProof(state, networkId, endpointId,
                owner, expectedDigest, proof).getAsJsonObject("result")
            val response = createAndSend(state, "network.key_grant", JsonObject(), bodyBuilder = { _, _, _ ->
                // No cached preview or caller-supplied digest can replace the just-verified manifest.
                verifyNetworkOwnerProof(proof, verified, owner)
                JsonObject().apply {
                    addProperty("network_id", networkId)
                    addProperty("endpoint_id", endpointId)
                    addProperty("signed_proof", signedProofBase64)
                }
            })
            verifyNetworkGrantResult(response, state, networkId, endpointId, owner,
                expectedDigest, proof)
            response
        }

    /** Status may remain stale after revocation; it is not evidence of current peer permission. */
    fun networkKeyStatus(networkId: String, endpointId: String): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        val owner = requireNetworkOwner(state, networkId, null)
        requireNetworkAvailability(state, setOf("network.key_status"))
        val response = createAndSend(state, "network.key_status", JsonObject().apply {
            addProperty("network_id", networkId)
            addProperty("endpoint_id", endpointId)
        })
        verifyNetworkGrantResult(response, state, networkId, endpointId, owner)
        response
    }

    private fun requireNetworkOwner(state: State, networkId: String,
                                    ownerKeyId: String?): ClientWireCrypto.PublicIdentity {
        requireReadyForRpc(state)
        if (state.pending != null) {
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original encrypted request before Network key consent")
        }
        if (state.activeNetworkId == null || state.activeNetworkId != networkId) {
            throw HubSessionException("NETWORK_SELECTION_REQUIRED", "Select this Network explicitly in the active Hub profile")
        }
        if (!state.sessionCapabilitiesReady || state.role !in setOf("manager", "external")) {
            throw HubSessionException("SESSION_CAPABILITIES_REQUIRED", "Read current encrypted Owner session capabilities first")
        }
        val publicJson = state.ownerApprovalPublicIdentityJson
            ?: throw HubSessionException("OWNER_PUBLIC_KEY_REQUIRED", "Re-enroll with an independently trusted Owner approval key")
        val owner = try { ClientWireCrypto.PublicIdentity.parse(parseObject(publicJson, "Invalid owner key")) }
            catch (_: Exception) { throw HubSessionException("OWNER_PUBLIC_KEY_INVALID", "Saved Owner approval key is invalid") }
        if (ownerKeyId != null && owner.id != ownerKeyId) {
            throw HubSessionException("OWNER_KEY_ID_MISMATCH", "Selected Owner key differs from the independent enrollment trust key")
        }
        return owner
    }

    private fun requireNetworkGrantReconciled(state: State) {
        requireRegroupReconciled(state)
        if (state.networkGrantUncertainPending != null) {
            throw HubSessionException("NETWORK_GRANT_RECONCILIATION_REQUIRED", "The original Network key grant outcome is unresolved; Client has not completed dedicated authoritative reconciliation for that grant. Keep its original ciphertext; a general snapshot cannot authorize another grant or reset this profile")
        }
    }

    private fun requireLinkConsentReconciled(state: State) {
        if (state.linkConsentLedger.writeFence != null) {
            throw HubSessionException("LINK_CONSENT_RECOVERY_REQUIRED", "Resolve the original Link consent packet before changing this profile or device key")
        }
    }

    private fun validateNetworkGrantFence(pending: Pending): Pending {
        if (pending.operation != "network.key_grant" || pending.operationId.isBlank() ||
            pending.sequence < 1 || pending.packetJson.isBlank() ||
            pending.expectedResponseSequence?.let { it < 1 } == true) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Network grant reconciliation fence is invalid")
        }
        return pending
    }

    /** Public availability is an additional restriction; only encrypted capabilities authorize. */
    private fun requireNetworkAvailability(state: State, operations: Set<String>) {
        // Obvious local denials must not consume a sequence or create any pending request.
        operations.forEach { validateOperation(state, it) }
        validateOperation(state, "session.capabilities")
        val current = createAndSend(state, "session.capabilities", JsonObject())
        if (current.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true ||
            !state.sessionCapabilitiesReady || state.role !in setOf("manager", "external")) {
            throw HubSessionException("SESSION_CAPABILITIES_REQUIRED", "Hub did not confirm current encrypted Owner session capabilities")
        }
        // finishResponse checked exact Owner, contract and catalog; authorization may have narrowed.
        operations.forEach { validateOperation(state, it) }
        val capabilities = fetchHubMetadata(state.pin!!.baseUrl).getAsJsonObject("capabilities")
        val listName = if (state.role == "external") "external_rpc_operations" else "available_rpc_operations"
        val advertised = capabilities.get(listName)?.takeIf { it.isJsonArray }?.asJsonArray
            ?.mapNotNull { item -> item.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString }
            ?.toSet() ?: emptySet()
        val e2ee = capabilities.get("client_control_pq_e2ee")
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true
        val authenticated = capabilities.get("authenticated_client_session")
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true
        if (!e2ee || !authenticated || !advertised.containsAll(operations)) {
            throw HubSessionException("NETWORK_OPERATION_UNAVAILABLE", "This Owner role's current public operation catalog does not advertise the requested Network flow")
        }
    }

    /** Explicitly pins a full Owner public identity from a separate trusted channel. */
    fun confirmLinkOwnerPin(
        ownerId: String,
        publicIdentityJson: String,
        expectedFingerprint: String,
        confirmed: Boolean,
        profileGeneration: Long,
    ): JsonObject = PROCESS_LOCK.withLock {
        requireLinkConsentGate()
        if (profileGeneration < 1) throw HubSessionException("INVALID_PROFILE_SCOPE", "Hub profile selection generation is invalid")
        if (!confirmed) throw HubSessionException("OWNER_PIN_CONFIRMATION_REQUIRED", "Confirm the displayed Owner fingerprint before saving this key")
        val ownerIdentity = try {
            parseIndependentOwnerIdentity(publicIdentityJson)
        } catch (_: Exception) {
            throw HubSessionException("OWNER_PIN_INVALID", "Owner public identity is invalid")
        }
        val rawFingerprint = expectedFingerprint.removePrefix("sha256:")
        if (!rawFingerprint.matches(Regex("^[0-9a-f]{64}$")) || rawFingerprint != ownerIdentity.fingerprint()) {
            throw HubSessionException("OWNER_PIN_FINGERPRINT_MISMATCH", "Owner fingerprint differs from the independently supplied public identity")
        }
        val state = readState()
        val next = try {
            state.linkConsentLedger.invalidateReviewForProfileGeneration(profileGeneration)
                .pinOwner(ownerIdentity, ownerId, rawFingerprint, true, Instant.now()).first
        } catch (_: Exception) {
            throw HubSessionException("OWNER_PIN_REJECTED", "Owner public key could not be pinned for this profile")
        }
        state.linkConsentLedger = next
        writeState(state)
        val pin = next.ownerPin(ownerId, ownerIdentity.id)
            ?: throw HubSessionException("OWNER_PIN_STORAGE_FAILED", "Saved Owner public key pin could not be read")
        JsonObject().apply {
            addProperty("ownerId", pin.ownerId)
            addProperty("ownerKeyId", pin.keyId)
            addProperty("ownerKeyFingerprint", "sha256:${pin.fingerprint}")
            addProperty("pinRevision", pin.pinRevision.toString())
            addProperty("confirmed", true)
        }
    }

    /** Captures a fresh candidate review from authenticated manifest, grant and policy reads. */
    fun prepareLinkConsent(
        linkId: String,
        expectedLinkVersion: Long,
        kind: String,
        policyJson: JsonObject?,
        profileGeneration: Long,
    ): JsonObject = PROCESS_LOCK.withLock {
        requireLinkConsentGate()
        if (profileGeneration < 1) throw HubSessionException("INVALID_PROFILE_SCOPE", "Hub profile selection generation is invalid")
        val normalizedPolicy = if (kind == "REVIEW_POLICY") parseLinkConsentPolicy(policyJson) else {
            if (policyJson != null) throw HubSessionException("INVALID_LINK_CONSENT_POLICY", "Key grant review does not accept a policy")
            null
        }
        val state = readState()
        requireLinkConsentSession(state, profileGeneration,
            if (kind == "KEY") setOf("link.key_manifest", "link.key_grants")
            else setOf("link.key_manifest", "link.key_grants", "link.review_policy_status", "link.review_policy_preview"),
            allowFenceRead = false)
        val oldLedger = state.linkConsentLedger
        state.linkConsentLedger = oldLedger.invalidateReviewForProfileGeneration(profileGeneration)
        if (state.linkConsentLedger != oldLedger) writeState(state)
        val prepared = prepareLinkConsentInternal(state, linkId, expectedLinkVersion, kind, normalizedPolicy, profileGeneration)
        state.linkConsentLedger = try { state.linkConsentLedger.prepare(prepared.review) } catch (_: Exception) {
            throw HubSessionException("LINK_CONSENT_REVIEW_INVALID", "Fresh Link authority did not match the independently pinned Owner keys")
        }
        writeState(state)
        linkConsentReviewJson(prepared.review, prepared.policyStatusDisplay)
    }

    /** Rechecks current authority, verifies the external proof, then durably stages its exact ciphertext. */
    fun submitLinkConsent(
        reviewId: String,
        consentDigest: String,
        signedProofBase64: String,
        confirmed: Boolean,
        profileGeneration: Long,
    ): JsonObject = PROCESS_LOCK.withLock {
        requireLinkConsentGate()
        if (!confirmed) throw HubSessionException("LINK_CONSENT_CONFIRMATION_REQUIRED", "Confirm the exact Link consent scope before submitting the Owner proof")
        val state = readState()
        requireLinkConsentSession(state, profileGeneration,
            setOf("link.key_manifest", "link.key_grants", "link.key_grant", "link.review_policy_status", "link.review_policy_preview", "link.review_policy_grant"),
            allowFenceRead = false)
        if (state.uncertainNeedsReconciliation) {
            throw HubSessionException("BUSINESS_RECONCILIATION_REQUIRED", "Reconcile the previous authenticated Hub outcome before submitting Link consent")
        }
        val saved = state.linkConsentLedger.review
            ?: throw HubSessionException("LINK_CONSENT_REVIEW_EXPIRED", "Prepare a fresh Link consent review before submitting")
        if (saved.reviewId != reviewId || saved.consentDigest != consentDigest ||
            saved.tuple.profileGeneration != profileGeneration ||
            state.linkConsentLedger.writeFence != null) {
            throw HubSessionException("LINK_CONSENT_REVIEW_STALE", "Link consent review is stale or another original packet is unresolved")
        }
        val proofBytes = try {
            if (signedProofBase64.length !in 4..21_848) throw IllegalArgumentException()
            val decoded = java.util.Base64.getDecoder().decode(signedProofBase64)
            if (decoded.isEmpty() || decoded.size > LinkConsentLedger.MAX_PROOF_BYTES ||
                java.util.Base64.getEncoder().encodeToString(decoded) != signedProofBase64) throw IllegalArgumentException()
            decoded
        } catch (_: Exception) {
            throw HubSessionException("INVALID_LINK_OWNER_PROOF", "Owner-signed proof must be bounded canonical base64")
        }
        val policy = saved.policyJson?.let { parseLinkConsentPolicy(JsonParser.parseString(it).asJsonObject) }
        val fresh = prepareLinkConsentInternal(state, saved.tuple.linkId, saved.tuple.linkVersion,
            saved.tuple.kind, policy, profileGeneration)
        if (fresh.review.consentDigest != saved.consentDigest || fresh.review.tuple != saved.tuple) {
            proofBytes.fill(0)
            throw HubSessionException("LINK_CONSENT_REVIEW_STALE", "Link, Owner key, policy head or reviewer authority changed; review the new scope")
        }
        val originalRequest = parseObject(saved.signingRequestJson, "Saved Owner signing request is invalid")
        val selectedExpiry = optionalString(originalRequest, "expires_at")?.let { try { Instant.parse(it) } catch (_: Exception) { null } }
            ?: throw HubSessionException("LINK_CONSENT_REVIEW_INVALID", "Saved Owner signing request expiry is invalid")
        if (!Instant.now().isBefore(selectedExpiry)) {
            proofBytes.fill(0)
            throw HubSessionException("LINK_CONSENT_REVIEW_EXPIRED", "Owner proof signing window expired; prepare a new review")
        }
        val localSide = saved.tuple.localSide
        val localScope = if (localSide == "SOURCE") saved.tuple.source else saved.tuple.target
        val signedBody = try {
            if (saved.tuple.kind == "KEY") {
                val verifiedProof = fresh.authority.verifyOwnerGrant(localSide, proofBytes, Instant.now())
                if (verifiedProof.ownerId != saved.tuple.ownerId || verifiedProof.ownerKeyId != localScope.ownerKeyId ||
                    verifiedProof.linkId != saved.tuple.linkId || verifiedProof.linkVersion != saved.tuple.linkVersion ||
                    verifiedProof.manifestDigest != saved.tuple.manifestDigest || verifiedProof.expiresAt > selectedExpiry) {
                    throw IllegalArgumentException()
                }
                JsonObject().apply {
                    addProperty("link_id", saved.tuple.linkId)
                    addProperty("side", localSide)
                    addProperty("owner_key_id", localScope.ownerKeyId)
                    addProperty("signed_proof", java.util.Base64.getEncoder().encodeToString(proofBytes))
                }
            } else {
                val preview = fresh.policyPreview ?: throw IllegalArgumentException()
                val currentLink = fresh.authority.asPolicyCurrentLink()
                val trustedPin = fresh.localPolicyPin ?: throw IllegalArgumentException()
                val lifecycle = fresh.localPolicyLifecycle ?: throw IllegalArgumentException()
                val statusBytes = fresh.policyStatus?.toString()?.toByteArray(StandardCharsets.UTF_8)
                    ?: throw IllegalArgumentException()
                val previewBytes = fresh.reviewPolicyPreviewBytes
                    ?: throw IllegalArgumentException()
                val request = LinkReviewPolicyEvidenceV164.buildGrantRequest(
                    cachedPreview = preview,
                    freshRawPreview = previewBytes,
                    freshRawStatus = statusBytes,
                    currentLink = currentLink,
                    trustedLocalOwnerPin = trustedPin,
                    trustedLocalOwnerLifecycle = lifecycle,
                    proofJson = proofBytes,
                    now = Instant.now(),
                )
                JsonParser.parseString(request.toJson()).asJsonObject
            }
        } catch (_: Exception) {
            proofBytes.fill(0)
            throw HubSessionException("LINK_OWNER_PROOF_INVALID", "Owner signature does not match the fresh Link consent scope")
        }
        val refreshedReview = saved.copy(
            tuple = fresh.review.tuple,
            consentDigest = fresh.review.consentDigest,
            manifestRead = fresh.review.manifestRead,
            statusRead = fresh.review.statusRead,
            previewRead = fresh.review.previewRead,
            policyJson = fresh.review.policyJson,
        )
        state.linkConsentLedger = try { state.linkConsentLedger.prepare(refreshedReview) } catch (_: Exception) {
            proofBytes.fill(0)
            throw HubSessionException("LINK_CONSENT_REVIEW_STALE", "Saved independent Owner pins no longer match the fresh Link authority")
        }
        val operation = if (saved.tuple.kind == "KEY") "link.key_grant" else "link.review_policy_grant"
        val response = try {
            createAndSend(state, operation, signedBody, beforePersist = { operationId, sequence, _ ->
                val pending = state.pending
                    ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original Link packet was not constructed")
                val fence = LinkConsentLedger.WriteFence(
                    operation = operation,
                    operationId = operationId,
                    requestSequence = sequence,
                    expectedResponseSequence = pending.expectedResponseSequence
                        ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original response sequence was not reserved"),
                    signedProofJson = String(proofBytes, StandardCharsets.UTF_8),
                    signedProofSha256 = LinkConsentLedger.digest(proofBytes),
                    packetJson = pending.packetJson,
                    packetSha256 = LinkConsentLedger.digest(pending.packetJson.toByteArray(StandardCharsets.UTF_8)),
                    reviewId = refreshedReview.reviewId,
                    consentDigest = refreshedReview.consentDigest,
                    tupleDigest = LinkConsentLedger.digestTuple(refreshedReview.tuple),
                    state = LinkConsentLedger.FenceState.PENDING,
                )
                state.linkConsentLedger = state.linkConsentLedger.stage(fence)
            })
        } finally {
            proofBytes.fill(0)
        }
        JsonObject().apply {
            addProperty("operationId", optionalString(response, "operationId") ?: "")
            val ok = response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true
            addProperty("ok", ok)
            if (ok && saved.tuple.kind == "REVIEW_POLICY") {
                // finishResponse validates the exact terminal candidate against the
                // saved tuple and original proof at authenticated verified_at.
                response.get("policyStatus")?.takeIf { it.isJsonObject }?.let {
                    add("policyStatus", it.deepCopy())
                } ?: throw HubSessionException("LINK_REVIEW_POLICY_RESULT_INVALID", "Verified terminal policy status is missing")
            }
            optionalString(response, "errorCode")?.let { addProperty("errorCode", it) }
            response.get("originalOperationCompleted")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
                ?.let { addProperty("originalOperationCompleted", it) }
            response.get("reconciliationRequired")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
                ?.let { addProperty("reconciliationRequired", it) }
        }
    }

    /** Returns native-verified bilateral key proof metadata; never exposes retained proofs. */
    fun readLinkKeyGrants(linkId: String, expectedLinkVersion: Long, profileGeneration: Long): JsonObject = PROCESS_LOCK.withLock {
        requireLinkConsentGate()
        val state = readState()
        requireLinkConsentSession(state, profileGeneration, setOf("link.key_manifest", "link.key_grants"), allowFenceRead = true)
        val prepared = prepareLinkConsentInternal(state, linkId, expectedLinkVersion, "KEY", null, profileGeneration)
        val statuses = strictLinkKeyStatusRows(prepared.ownerGrantStatuses, prepared.authority)
        val sourceVerified = prepared.sourceCurrentKey != null
        val targetVerified = prepared.targetCurrentKey != null
        val bilateral = if (sourceVerified && targetVerified) {
            try {
                prepared.authority.verifyOwnerGrants(prepared.ownerGrantStatusRead, prepared.ownerGrantStatuses, Instant.now())
                true
            } catch (_: Exception) {
                throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Current bilateral Owner proof evidence failed native verification")
            }
        } else false
        if (bilateral) resolveKeyGrantFenceIfExact(state, prepared)
        JsonObject().apply {
            addProperty("linkId", prepared.authority.currentLink.linkId)
            addProperty("linkVersion", prepared.authority.currentLink.linkVersion.toString())
            add("sourceStatus", statuses.first)
            add("targetStatus", statuses.second)
            addProperty("bilateralVerified", bilateral)
            state.linkConsentLedger.writeFence?.let { addProperty("reconciliationRequired", true) }
        }
    }

    /** Recovery either replays only the existing exact pending packet or reads fresh proof status. */
    fun recoverLinkConsent(profileGeneration: Long): JsonObject = PROCESS_LOCK.withLock {
        requireLinkConsentGate()
        if (profileGeneration < 1) throw HubSessionException("INVALID_PROFILE_SCOPE", "Hub profile selection generation is invalid")
        val state = readState()
        val fence = state.linkConsentLedger.writeFence
            ?: return@withLock JsonObject().apply { addProperty("reconciliationRequired", false) }
        if (state.pending != null) {
            if (state.pending!!.operationId != fence.operationId || state.pending!!.sequence != fence.requestSequence ||
                state.pending!!.packetJson != fence.packetJson) {
                throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Saved pending request differs from the original Link consent packet")
            }
            recoverPending()
        } else if (state.authFenced) {
            return@withLock linkConsentFenceReceipt(readState())
        } else if (fence.operation == "link.key_grant") {
            val tuple = state.linkConsentLedger.review?.tuple
                ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original Link consent authority tuple is missing")
            readLinkKeyGrants(tuple.linkId, tuple.linkVersion, profileGeneration)
        } else {
            val review = state.linkConsentLedger.review
                ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original Link policy authority tuple is missing")
            val current = readState()
            requireLinkConsentSession(current, profileGeneration,
                setOf("link.key_manifest", "link.key_grants", "link.review_policy_status"),
                allowFenceRead = true)
            // A partial policy candidate is intentionally not discoverable from the
            // active-head endpoint. Reconcile only from a fresh manifest/key read and
            // the active policy head; never re-preview or infer from cached recovery.
            val fresh = prepareLinkConsentInternal(current, review.tuple.linkId, review.tuple.linkVersion,
                "KEY", null, profileGeneration)
            val selection = LinkReviewPolicySelection(
                linkId = review.tuple.linkId,
                linkVersion = fresh.authority.currentLink.linkVersion,
                mySide = fresh.authority.provenance.localSide,
            )
            val statusRead = directLinkRead(
                current, "link.review_policy_status", review.tuple.linkId, profileGeneration,
                selection = selection,
            )
            val status = statusRead.result.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw HubSessionException("LINK_REVIEW_POLICY_STATUS_INVALID", "Fresh Link policy status is missing")
            val parsed = try {
                LinkReviewPolicyEvidenceV164.validateActiveStatus(
                    status.toString().toByteArray(StandardCharsets.UTF_8), fresh.authority.asPolicyCurrentLink(), Instant.now())
            } catch (_: Exception) {
                throw HubSessionException("LINK_REVIEW_POLICY_STATUS_INVALID", "Fresh Link policy status failed native verification")
            }
            val sourceLifecycle = fresh.sourceCurrentKey
            val targetLifecycle = fresh.targetCurrentKey
            val currentTuple = fresh.review.tuple.copy(
                kind = review.tuple.kind,
                source = fresh.review.tuple.source.copy(
                    ownerKeyState = sourceLifecycle?.state,
                    ownerKeyVersion = sourceLifecycle?.version,
                ),
                target = fresh.review.tuple.target.copy(
                    ownerKeyState = targetLifecycle?.state,
                    ownerKeyVersion = targetLifecycle?.version,
                ),
                expectedPolicyVersion = review.tuple.expectedPolicyVersion,
                policyVersion = review.tuple.policyVersion,
                policyDigest = review.tuple.policyDigest,
                maximumProofExpiresAt = review.tuple.maximumProofExpiresAt,
                reviewers = review.tuple.reviewers,
            )
            val savedPolicy = review.policyJson?.let {
                try { parseLinkConsentPolicy(JsonParser.parseString(it).asJsonObject) } catch (_: Exception) { null }
            }
            val sameReviewedPolicy = if (savedPolicy == null) false else try {
                LinkReviewPolicyConsentValidation.canonicalPolicyJson(savedPolicy) ==
                    LinkReviewPolicyConsentValidation.canonicalPolicyJson(parsed.policy)
            } catch (_: Exception) { false }
            if (parsed.current && parsed.policyVersion == review.tuple.policyVersion &&
                parsed.policyDigest == review.tuple.policyDigest &&
                parsed.linkId == review.tuple.linkId && parsed.linkVersion == review.tuple.linkVersion &&
                parsed.contractDigest == review.tuple.contractDigest &&
                fresh.authority.manifest.digest == review.tuple.manifestDigest &&
                review.tuple.profileGeneration == profileGeneration && currentTuple == review.tuple &&
                sameReviewedPolicy &&
                statusRead.correlation.responseSequence > fence.expectedResponseSequence) {
                val hashes = parsed.ownerApprovals.mapNotNull { it.proofBytesCopy()?.let(LinkConsentLedger::digest) }.toSet()
                if (fence.signedProofSha256 in hashes) {
                    val pair = LinkConsentLedger.VerifiedActivatedPair(
                        linkId = parsed.linkId, linkVersion = parsed.linkVersion,
                        contractDigest = parsed.contractDigest, manifestDigest = fresh.authority.manifest.digest,
                        policyDigest = parsed.policyDigest, policyVersion = parsed.policyVersion,
                        tupleDigest = fence.tupleDigest, includedSignedProofSha256 = hashes,
                        freshResponseSequence = statusRead.correlation.responseSequence,
                    )
                    current.linkConsentLedger = current.linkConsentLedger.resolveActivatedPair(pair)
                    clearLinkUncertainLatch(current, fence.operationId)
                    writeState(current)
                }
            }
        }
        linkConsentFenceReceipt(readState())
    }

    private fun requireLinkConsentGate() {
        if (!LINK_CONSENT_READY || !LinkConsentAuthorityFactory.CANDIDATE_READY) {
            throw HubSessionException("VERIFIED_LINK_CONSENT_FLOW_NOT_READY", "The verified Link consent candidate is not enabled in this Client build")
        }
    }

    /**
     * Checks both public Hub metadata and the already authenticated encrypted
     * session before any Link read or proof processing. These operations stay
     * outside the generic RPC dispatcher, which always rejects them.
     */
    private fun requireLinkConsentSession(
        state: State,
        profileGeneration: Long,
        operations: Set<String>,
        allowFenceRead: Boolean,
    ) {
        if (profileGeneration < 1) throw HubSessionException("INVALID_PROFILE_SCOPE", "Hub profile selection generation is invalid")
        requireReadyForRpc(state)
        if (state.pending != null || state.recoveryBlocked || state.linkReviewStatusReadContext != null ||
            state.linkConsentStatusReadContext != null) {
            throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact encrypted request before reading Link consent authority")
        }
        if (state.linkConsentLedger.writeFence != null && !allowFenceRead) {
            throw HubSessionException("LINK_CONSENT_RECOVERY_REQUIRED", "Resolve the original Link consent packet before preparing another review")
        }
        if (state.uncertainNeedsReconciliation && !allowFenceRead) {
            throw HubSessionException("BUSINESS_RECONCILIATION_REQUIRED", "Reconcile the previous authenticated Hub outcome before preparing Link consent")
        }
        if (!state.sessionCapabilitiesReady || state.role !in setOf("manager", "external") ||
            "session.capabilities" !in state.allowedOperations) {
            throw HubSessionException("SESSION_CAPABILITIES_REQUIRED", "Read the current encrypted Owner session capabilities before Link consent")
        }
        val current = try { createAndSend(state, "session.capabilities", JsonObject()) }
            catch (error: HubSessionException) { throw error }
            catch (_: Exception) { throw HubSessionException("SESSION_CAPABILITIES_REQUIRED", "Could not refresh encrypted Owner session capabilities") }
        if (current.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true ||
            !state.sessionCapabilitiesReady || state.role !in setOf("manager", "external")) {
            throw HubSessionException("SESSION_CAPABILITIES_REQUIRED", "The Hub did not confirm current encrypted Owner session capabilities")
        }
        val required = (operations + "link.list" + "session.capabilities").toSet()
        if (required.any { it !in RPC_OPERATIONS } || !state.allowedOperations.containsAll(required)) {
            throw HubSessionException("RPC_OPERATION_NOT_AUTHORIZED", "The authenticated Owner session does not authorize the complete Link consent flow")
        }
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val metadata = try { fetchHubMetadata(pin.baseUrl).getAsJsonObject("capabilities") }
            catch (_: Exception) { throw HubSessionException("NETWORK_OPERATION_UNAVAILABLE", "The pinned Hub metadata could not confirm the Link consent contract") }
        val publicOperations = metadata.get(if (state.role == "external") "external_rpc_operations" else "available_rpc_operations")
            ?.takeIf { it.isJsonArray }?.asJsonArray?.mapNotNull { item ->
                item.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            }?.toSet() ?: emptySet()
        val e2ee = metadata.get("client_control_pq_e2ee")
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true
        val authenticated = metadata.get("authenticated_client_session")
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true
        if (!e2ee || !authenticated || !publicOperations.containsAll(required)) {
            throw HubSessionException("NETWORK_OPERATION_UNAVAILABLE", "The pinned Hub public catalog does not advertise the complete Link consent flow")
        }
    }

    /** Runs one dedicated RPC and creates correlation only after finishResponse authenticated it. */
    private fun directLinkRead(
        state: State,
        operation: String,
        linkId: String,
        profileGeneration: Long,
        body: JsonObject = JsonObject().apply { addProperty("link_id", linkId) },
        selection: LinkReviewPolicySelection? = null,
    ): DirectLinkRead {
        if (operation !in LINK_CONSENT_OPERATIONS || operation in setOf("link.key_grant", "link.review_policy_grant")) {
            throw HubSessionException("VERIFIED_LINK_CONSENT_FLOW_REQUIRED", "Only a dedicated Link consent read can create current authority")
        }
        if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the exact encrypted request before reading Link consent authority")
        if (operation == "link.review_policy_preview") {
            requireExactBodyFields(body, setOf("link_id", "policy"), setOf("link_id", "policy"))
        } else {
            requireExactBodyFields(body, setOf("link_id"), setOf("link_id"))
        }
        if (optionalString(body, "link_id") != linkId) {
            throw HubSessionException("INVALID_CLIENT_READ_REQUEST", "Link read selector differs from its selected authority")
        }
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val enrollment = state.enrollment ?: throw HubSessionException("DEVICE_NOT_ENROLLED", "Device enrollment is missing")
        val operationId = UUID.randomUUID().toString()
        val capturedSequence = state.nextSequence
        var expectedResponseSequence = 0L
        val response = try {
            createAndSend(state, operation, body, operationId = operationId, beforePersist = { savedId, sequence, requestBody ->
                val pending = state.pending
                    ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original Link read was not persisted")
                if (savedId != operationId || sequence != capturedSequence || pending.operation != operation ||
                    pending.operationId != operationId || pending.sequence != sequence) {
                    throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Link read request correlation changed before transmission")
                }
                expectedResponseSequence = pending.expectedResponseSequence
                    ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Link read response sequence was not reserved")
                if (operation == "link.review_policy_status") {
                    val selected = selection
                        ?: throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Candidate policy status requires an authenticated Link selection")
                    if (state.linkReviewStatusReadContext != null || state.linkConsentStatusReadContext != null ||
                        selected.linkId != linkId || selected.linkVersion < 1 || selected.mySide !in setOf("SOURCE", "TARGET")) {
                        throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Candidate Link policy status selection is stale")
                    }
                    requireExactBodyFields(requestBody, setOf("link_id"), setOf("link_id"))
                    state.linkConsentStatusReadContext = LinkConsentStatusReadContext(
                        linkId = linkId,
                        linkVersion = selected.linkVersion,
                        mySide = selected.mySide,
                        hubId = pin.hubId,
                        ownerId = enrollment.ownerId,
                        deviceId = enrollment.deviceId,
                        sessionEpoch = enrollment.sessionEpoch,
                        operationId = operationId,
                        sequence = sequence,
                        profileGeneration = profileGeneration,
                    )
                }
            })
        } catch (error: HubSessionException) {
            throw error
        } catch (_: Exception) {
            throw HubSessionException("LINK_READ_UNAVAILABLE", "The encrypted Link authority read did not complete")
        }
        if (optionalString(response, "operationId") != operationId ||
            response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true ||
            expectedResponseSequence < 1 || state.lastResponseSequence != expectedResponseSequence) {
            throw HubSessionException("LINK_READ_UNAVAILABLE", "The authenticated Link authority read did not return a complete result")
        }
        val result = response.get("result")
            ?: throw HubSessionException("LINK_READ_INVALID", "The authenticated Link authority read omitted its result")
        val correlation = LinkConsentLedger.ReadCorrelation(
            operation = operation,
            operationId = operationId,
            requestSequence = capturedSequence,
            responseSequence = state.lastResponseSequence,
            origin = "DIRECT",
        )
        return DirectLinkRead(result.deepCopy(), correlation)
    }

    private fun prepareLinkConsentInternal(
        state: State,
        linkId: String,
        expectedLinkVersion: Long,
        kind: String,
        policy: LinkReviewPolicyConsentPolicy?,
        profileGeneration: Long,
    ): LinkConsentPreparation {
        if (kind !in setOf("KEY", "REVIEW_POLICY") || (kind == "KEY") != (policy == null)) {
            throw HubSessionException("INVALID_LINK_CONSENT_KIND", "Link consent kind or policy is invalid")
        }
        val operations = if (kind == "KEY") setOf("link.key_manifest", "link.key_grants") else
            setOf("link.key_manifest", "link.key_grants", "link.review_policy_status", "link.review_policy_preview")
        if (!state.allowedOperations.containsAll(operations + "link.list")) {
            throw HubSessionException("RPC_OPERATION_NOT_AUTHORIZED", "The current Owner session does not authorize this Link consent read")
        }
        val selection = try { freshOwnerLinkSelection(state, requestToken(JsonObject().apply { addProperty("link_id", linkId) }, "link_id")) }
            catch (error: HubSessionException) { throw error }
            catch (_: Exception) { throw HubSessionException("LINK_REVIEW_LIST_INVALID", "Could not authenticate the selected Owner Link") }
        if (selection.linkVersion != expectedLinkVersion) {
            throw HubSessionException("LINK_CONSENT_REVIEW_STALE", "The selected Link version changed; refresh before reviewing consent")
        }
        val manifestRead = directLinkRead(state, "link.key_manifest", linkId, profileGeneration, selection = selection)
        val manifestJson = manifestRead.result.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("LINK_MANIFEST_INVALID", "The authenticated Link manifest result is not an object")
        val ownerIds = try { linkManifestOwnerIds(manifestJson) }
            catch (_: Exception) { throw HubSessionException("LINK_MANIFEST_INVALID", "The authenticated Link manifest owner scope is invalid") }
        val ledger = state.linkConsentLedger
        val sourcePinRecord = uniqueOwnerPin(ledger, ownerIds.first)
        val targetPinRecord = uniqueOwnerPin(ledger, ownerIds.second)
        val sourcePin = ownerAuthorityPin(sourcePinRecord)
        val targetPin = ownerAuthorityPin(targetPinRecord)
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val enrollment = state.enrollment ?: throw HubSessionException("DEVICE_NOT_ENROLLED", "Device enrollment is missing")
        val provenance = FreshLinkManifestRead(
            profileId = profileId,
            profileGeneration = profileGeneration,
            hubId = pin.hubId,
            ownerId = enrollment.ownerId,
            deviceId = enrollment.deviceId,
            sessionEpoch = enrollment.sessionEpoch,
            operation = manifestRead.correlation.operation,
            operationId = manifestRead.correlation.operationId,
            requestSequence = manifestRead.correlation.requestSequence,
            responseSequence = manifestRead.correlation.responseSequence,
            authenticatedResultSha256 = LinkConsentAuthorityFactory.manifestResultSha256(manifestJson),
            selectedLinkId = linkId,
            selectedLinkVersion = expectedLinkVersion,
            localSide = selection.mySide,
        )
        val authority = try {
            LinkConsentAuthorityFactory.verifyFreshManifest(provenance, manifestJson, sourcePin, targetPin, Instant.now())
        } catch (_: Exception) {
            throw HubSessionException("LINK_MANIFEST_INVALID", "The Link manifest, Endpoint attestations or independent Owner pins did not verify")
        }
        val statusRead = directLinkRead(state, "link.key_grants", linkId, profileGeneration, selection = selection)
        val statusArray = statusRead.result.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw HubSessionException("LINK_KEY_GRANTS_INVALID", "The authenticated Link key status result is not an array")
        val statusProvenance = FreshLinkOwnerGrantStatusRead(
            profileId = profileId,
            profileGeneration = profileGeneration,
            hubId = pin.hubId,
            ownerId = enrollment.ownerId,
            deviceId = enrollment.deviceId,
            sessionEpoch = enrollment.sessionEpoch,
            operation = statusRead.correlation.operation,
            operationId = statusRead.correlation.operationId,
            requestSequence = statusRead.correlation.requestSequence,
            responseSequence = statusRead.correlation.responseSequence,
            authenticatedResultSha256 = LinkConsentAuthorityFactory.ownerGrantStatusResultSha256(statusArray),
            selectedLinkId = linkId,
            selectedLinkVersion = expectedLinkVersion,
            localSide = selection.mySide,
            manifestDigest = authority.manifest.digest,
        )
        val sourceCurrentKey = try {
            authority.verifyOwnerGrantStatusForSide(statusProvenance, statusArray, "SOURCE", Instant.now())?.currentOwnerKey
        } catch (_: Exception) {
            throw HubSessionException("LINK_KEY_GRANTS_INVALID", "The current source Owner grant proof failed native verification")
        }
        val targetCurrentKey = try {
            authority.verifyOwnerGrantStatusForSide(statusProvenance, statusArray, "TARGET", Instant.now())?.currentOwnerKey
        } catch (_: Exception) {
            throw HubSessionException("LINK_KEY_GRANTS_INVALID", "The current target Owner grant proof failed native verification")
        }

        var policyStatusRead: LinkConsentLedger.ReadCorrelation? = null
        var policyStatus: JsonObject? = null
        var preview: LinkReviewPolicyV164Preview? = null
        var policyPreviewRead: LinkConsentLedger.ReadCorrelation? = null
        var policyStatusBytes: ByteArray? = null
        var previewBytes: ByteArray? = null
        var localPolicyLifecycle: LinkReviewPolicyV164OwnerLifecycle? = null
        var localPolicyPin: LinkReviewPolicyV164OwnerPin? = null
        var policyStatusDisplay: JsonObject? = null
        val reviewers: List<LinkConsentLedger.ReviewerQualification>
        val expectedPolicyVersion: Long?
        val policyVersion: Long?
        val policyDigest: String?
        val maximumProofExpiresAt: String?
        if (kind == "REVIEW_POLICY") {
            val requested = policy ?: throw HubSessionException("INVALID_LINK_CONSENT_POLICY", "Review policy is missing")
            val statusReadResult = directLinkRead(state, "link.review_policy_status", linkId, profileGeneration, selection = selection)
            policyStatusRead = statusReadResult.correlation
            policyStatus = statusReadResult.result.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw HubSessionException("LINK_REVIEW_POLICY_STATUS_INVALID", "The authenticated Link policy status is not an object")
            policyStatusBytes = policyStatus!!.toString().toByteArray(StandardCharsets.UTF_8)
            val currentPolicyStatus = try {
                LinkReviewPolicyEvidenceV164.validateActiveStatus(
                    policyStatusBytes!!, authority.asPolicyCurrentLink(), Instant.now())
            } catch (_: Exception) {
                throw HubSessionException("LINK_REVIEW_POLICY_STATUS_INVALID", "The current Link policy status did not verify against both pinned Owners")
            }
            policyStatusDisplay = linkPolicyStatusDisplay(currentPolicyStatus)
            val previewRead = directLinkRead(
                state, "link.review_policy_preview", linkId, profileGeneration,
                body = JsonObject().apply {
                    addProperty("link_id", linkId)
                    add("policy", JsonParser.parseString(LinkReviewPolicyConsentValidation.canonicalPolicyJson(requested)))
                },
                selection = selection,
            )
            policyPreviewRead = previewRead.correlation
            previewBytes = previewRead.result.toString().toByteArray(StandardCharsets.UTF_8)
            val parsedPreview = try {
                LinkReviewPolicyEvidenceV164.validatePreview(
                    rawPreview = previewBytes!!,
                    reviewedPolicy = requested,
                    rawCurrentStatus = policyStatusBytes!!,
                    currentLink = authority.asPolicyCurrentLink(),
                    now = Instant.now(),
                )
            } catch (_: Exception) {
                throw HubSessionException("LINK_REVIEW_POLICY_PREVIEW_INVALID", "The current Link policy head, preview or reviewer qualifications did not verify")
            }
            preview = parsedPreview
            val localKey = if (selection.mySide == "SOURCE") sourceCurrentKey else targetCurrentKey
                ?: throw HubSessionException("LINK_OWNER_KEY_NOT_CURRENT", "A fresh accepted local Owner key proof is required before policy consent")
            if (localKey == null) throw HubSessionException("LINK_OWNER_KEY_NOT_CURRENT", "A fresh accepted local Owner key proof is required before policy consent")
            localPolicyPin = if (selection.mySide == "SOURCE") authority.asPolicyCurrentLink().sourceOwnerPin
                else authority.asPolicyCurrentLink().targetOwnerPin
            localPolicyLifecycle = LinkReviewPolicyV164OwnerLifecycle(
                ownerId = localKey.ownerId,
                keyId = localKey.keyId,
                state = localKey.state,
                version = localKey.version,
            )
            reviewers = parsedPreview.reviewerQualifications.map { qualification ->
                LinkConsentLedger.ReviewerQualification(
                    endpointId = qualification.endpointId,
                    groupId = qualification.groupId,
                    membershipRevision = qualification.membershipRevision,
                    joinRevision = qualification.joinRevision,
                    groupVersion = qualification.groupVersion,
                    bindingId = qualification.bindingId,
                    bindingEpoch = qualification.bindingEpoch,
                    action = qualification.action,
                    leaseExpiresAt = GroupKeyManifestVerifier.formatCanonicalUtc(qualification.leaseExpiresAt),
                )
            }
            expectedPolicyVersion = parsedPreview.expectedPolicyVersion
            policyVersion = parsedPreview.policyVersion
            policyDigest = parsedPreview.policyDigest
            maximumProofExpiresAt = GroupKeyManifestVerifier.formatCanonicalUtc(parsedPreview.maximumProofExpiresAt)
        } else {
            reviewers = emptyList()
            expectedPolicyVersion = null
            policyVersion = null
            policyDigest = null
            maximumProofExpiresAt = null
        }
        val includeOwnerLifecycle = kind == "REVIEW_POLICY"
        val source = buildLinkSideScope(authority, manifestJson, "SOURCE", sourcePinRecord,
            if (includeOwnerLifecycle) sourceCurrentKey else null)
        val target = buildLinkSideScope(authority, manifestJson, "TARGET", targetPinRecord,
            if (includeOwnerLifecycle) targetCurrentKey else null)
        val now = Instant.now()
        val linkExpiry = authority.manifest.linkExpiresAt
        val signerMaxExpiry = if (kind == "KEY") minOf(linkExpiry, now.plus(5, ChronoUnit.MINUTES))
            else minOf(preview!!.maximumProofExpiresAt, now.plus(5, ChronoUnit.MINUTES))
        if (!signerMaxExpiry.isAfter(now)) throw HubSessionException("LINK_CONSENT_REVIEW_EXPIRED", "Link proof expiry is not in the future")
        val tuple = LinkConsentLedger.AuthorityTuple(
            profileId = profileId,
            profileGeneration = profileGeneration,
            hubId = pin.hubId,
            ownerId = enrollment.ownerId,
            deviceId = enrollment.deviceId,
            sessionEpoch = enrollment.sessionEpoch,
            linkId = linkId,
            linkVersion = expectedLinkVersion,
            contractDigest = authority.manifest.contractDigest,
            manifestDigest = authority.manifest.digest,
            localSide = selection.mySide,
            kind = kind,
            direction = authority.currentLink.direction,
            actions = authority.currentLink.actions,
            dataScopes = authority.currentLink.dataScopes,
            expiresAt = authority.currentLink.expiresAt,
            source = source,
            target = target,
            expectedPolicyVersion = expectedPolicyVersion,
            policyVersion = policyVersion,
            policyDigest = policyDigest,
            maximumProofExpiresAt = maximumProofExpiresAt,
            reviewers = reviewers,
        )
        val localPinRecord = if (selection.mySide == "SOURCE") sourcePinRecord else targetPinRecord
        val peerPinRecord = if (selection.mySide == "SOURCE") targetPinRecord else sourcePinRecord
        val signingRequest = linkConsentSigningRequest(
            kind = kind,
            ownerId = enrollment.ownerId,
            ownerKeyId = localPinRecord.keyId,
            ownerFingerprint = localPinRecord.fingerprint,
            linkId = linkId,
            linkVersion = expectedLinkVersion,
            contractDigest = authority.manifest.contractDigest,
            side = selection.mySide,
            maximumExpiry = signerMaxExpiry,
            policyExpectedVersion = expectedPolicyVersion,
            policyVersion = policyVersion,
            digest = policyDigest ?: authority.manifest.digest,
        )
        val review = LinkConsentLedger.Review(
            reviewId = UUID.randomUUID().toString(),
            consentDigest = LinkConsentLedger.digestTuple(tuple),
            tuple = tuple,
            manifestRead = manifestRead.correlation,
            statusRead = statusRead.correlation,
            previewRead = policyPreviewRead,
            policyJson = if (kind == "REVIEW_POLICY") LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy!!) else null,
            signingRequestJson = signingRequest,
            createdAt = GroupKeyManifestVerifier.formatCanonicalUtc(now),
        )
        return LinkConsentPreparation(
            review = review,
            authority = authority,
            ownerGrantStatusRead = statusProvenance,
            ownerGrantStatuses = statusArray.deepCopy(),
            sourceCurrentKey = sourceCurrentKey,
            targetCurrentKey = targetCurrentKey,
            policyStatusRead = policyStatusRead,
            policyStatus = policyStatus?.deepCopy(),
            policyPreview = preview,
            reviewPolicyStatusBytes = policyStatusBytes?.clone(),
            reviewPolicyPreviewBytes = previewBytes?.clone(),
            localPolicyLifecycle = localPolicyLifecycle,
            localPolicyPin = localPolicyPin,
            policyStatusDisplay = policyStatusDisplay,
        )
    }

    private fun linkManifestOwnerIds(manifest: JsonObject): Pair<String, String> {
        val encoded = optionalString(manifest, "contract_canonical") ?: throw IllegalArgumentException()
        val bytes = java.util.Base64.getDecoder().decode(encoded)
        if (bytes.isEmpty() || bytes.size > 64 * 1024 || java.util.Base64.getEncoder().encodeToString(bytes) != encoded) {
            throw IllegalArgumentException()
        }
        val text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        val contract = parseObject(text, "Link contract is invalid")
        val source = optionalString(contract, "source_owner_id") ?: throw IllegalArgumentException()
        val target = optionalString(contract, "target_owner_id") ?: throw IllegalArgumentException()
        return source to target
    }

    private fun uniqueOwnerPin(ledger: LinkConsentLedger, ownerId: String): LinkConsentLedger.OwnerPin {
        val matches = ledger.ownerPins.filter { it.ownerId == ownerId }
        if (matches.size != 1) throw HubSessionException("OWNER_PIN_REQUIRED", "Confirm exactly one independent full public key pin for each Link Owner")
        return matches.single()
    }

    /** Strictly accepts only three public identity fields, with bounded input and no duplicates. */
    private fun parseIndependentOwnerIdentity(raw: String): ClientWireCrypto.PublicIdentity {
        val bytes = raw.toByteArray(StandardCharsets.UTF_8)
        if (bytes.isEmpty() || bytes.size > LinkConsentLedger.MAX_PUBLIC_IDENTITY_BYTES) {
            throw IllegalArgumentException("Owner public identity size is invalid")
        }
        val decoded = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        val fields = linkedMapOf<String, String>()
        JsonReader(StringReader(decoded)).apply { strictness = Strictness.STRICT }.use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                val name = reader.nextName()
                if (name !in OWNER_PUBLIC_IDENTITY_FIELDS || fields.containsKey(name) ||
                    reader.peek() != JsonToken.STRING) {
                    throw IllegalArgumentException("Owner public identity fields are invalid")
                }
                fields[name] = reader.nextString()
            }
            reader.endObject()
            if (reader.peek() != JsonToken.END_DOCUMENT || fields.keys != OWNER_PUBLIC_IDENTITY_FIELDS) {
                throw IllegalArgumentException("Owner public identity fields are invalid")
            }
        }
        val value = JsonObject().apply {
            addProperty("id", fields.getValue("id"))
            addProperty("kem_public", fields.getValue("kem_public"))
            addProperty("signing_public", fields.getValue("signing_public"))
        }
        return ClientWireCrypto.PublicIdentity.parse(value)
    }

    private fun ownerAuthorityPin(record: LinkConsentLedger.OwnerPin): LinkKeyManifestVerifier.OwnerPublicKeyPin {
        val identity = try { ClientWireCrypto.PublicIdentity.parse(parseObject(record.publicIdentityJson, "Owner public key pin is invalid")) }
            catch (_: Exception) { throw HubSessionException("OWNER_PIN_INVALID", "Saved independent Owner public key pin is invalid") }
        if (identity.id != record.keyId || identity.fingerprint() != record.fingerprint) {
            throw HubSessionException("OWNER_PIN_INVALID", "Saved independent Owner public key pin does not match its fingerprint")
        }
        return LinkKeyManifestVerifier.OwnerPublicKeyPin(record.ownerId, record.keyId, identity)
    }

    private fun buildLinkSideScope(
        authority: VerifiedCurrentLinkAuthority,
        manifest: JsonObject,
        side: String,
        ownerPin: LinkConsentLedger.OwnerPin,
        currentOwnerKey: LinkKeyManifestVerifier.CurrentOwnerKeyAuthority?,
    ): LinkConsentLedger.SideScope {
        val current = if (side == "SOURCE") authority.currentLink.source else authority.currentLink.target
        val verifiedCandidate = if (side == "SOURCE") authority.manifest.source else authority.manifest.target
        val candidate = manifest.get(side.lowercase())?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("LINK_MANIFEST_INVALID", "Verified Link manifest omitted an Endpoint candidate")
        val bindingId = optionalString(candidate, "binding_id") ?: throw HubSessionException("LINK_MANIFEST_INVALID", "Verified Endpoint binding is invalid")
        val bindingEpoch = strictLong(candidate, "binding_epoch", 1L, Long.MAX_VALUE)
        val candidateVersion = strictLong(candidate, "candidate_version", 1L, Long.MAX_VALUE)
        val keyId = optionalString(candidate, "key_id") ?: throw HubSessionException("LINK_MANIFEST_INVALID", "Verified Endpoint key ID is invalid")
        val fingerprint = optionalString(candidate, "key_fingerprint") ?: throw HubSessionException("LINK_MANIFEST_INVALID", "Verified Endpoint fingerprint is invalid")
        val proofDigest = optionalString(candidate, "proof_digest") ?: throw HubSessionException("LINK_MANIFEST_INVALID", "Verified Endpoint proof digest is invalid")
        if (current.endpointId != verifiedCandidate.endpointId || current.groupId != verifiedCandidate.groupId ||
            current.ownerId != verifiedCandidate.ownerId || current.bindingId != bindingId ||
            current.bindingEpoch != bindingEpoch || current.candidateVersion != candidateVersion ||
            verifiedCandidate.publicIdentity.id != keyId || verifiedCandidate.keyFingerprint != fingerprint ||
            ownerPin.ownerId != current.ownerId ||
            currentOwnerKey?.let { it.ownerId != ownerPin.ownerId || it.keyId != ownerPin.keyId ||
                it.publicIdentity.fingerprint() != ownerPin.fingerprint || it.state != "ACTIVE" || it.version <= 0 } == true) {
            throw HubSessionException("LINK_MANIFEST_INVALID", "Verified Endpoint or Owner key scope changed")
        }
        return LinkConsentLedger.SideScope(
            endpointId = current.endpointId,
            groupId = current.groupId,
            principalId = current.principalId,
            ownerId = current.ownerId,
            nodeId = current.nodeId,
            bindingId = bindingId,
            bindingEpoch = bindingEpoch,
            candidateVersion = candidateVersion,
            keyId = keyId,
            keyFingerprint = fingerprint,
            proofDigest = proofDigest,
            membershipRevision = current.membershipRevision,
            joinRevision = current.joinRevision,
            groupVersion = current.groupVersion,
            ownerKeyId = ownerPin.keyId,
            ownerFingerprint = ownerPin.fingerprint,
            ownerKeyState = currentOwnerKey?.state,
            ownerKeyVersion = currentOwnerKey?.version,
            ownerPinRevision = ownerPin.pinRevision,
        )
    }

    private fun linkConsentSigningRequest(
        kind: String,
        ownerId: String,
        ownerKeyId: String,
        ownerFingerprint: String,
        linkId: String,
        linkVersion: Long,
        contractDigest: String,
        side: String,
        maximumExpiry: Instant,
        policyExpectedVersion: Long?,
        policyVersion: Long?,
        digest: String,
    ): String = JsonObject().apply {
        addProperty("schema", "cicada.client.link-consent-signing-request.v1")
        addProperty("kind", kind)
        addProperty("owner_id", ownerId)
        addProperty("owner_key_id", ownerKeyId)
        addProperty("owner_key_fingerprint", ownerFingerprint)
        addProperty("link_id", linkId)
        addProperty("link_version", linkVersion)
        addProperty("contract_digest", contractDigest)
        addProperty("side", side)
        val canonicalExpiry = GroupKeyManifestVerifier.formatCanonicalUtc(maximumExpiry)
        addProperty("max_expiry", canonicalExpiry)
        addProperty("expires_at", canonicalExpiry)
        if (kind == "KEY") addProperty("manifest_digest", digest) else {
            addProperty("policy_digest", digest)
            addProperty("expected_policy_version", policyExpectedVersion
                ?: throw HubSessionException("LINK_CONSENT_REVIEW_INVALID", "Expected review policy head is missing"))
            addProperty("policy_version", policyVersion
                ?: throw HubSessionException("LINK_CONSENT_REVIEW_INVALID", "Candidate review policy version is missing"))
        }
    }.toString()

    private fun parseLinkConsentPolicy(policy: JsonObject?): LinkReviewPolicyConsentPolicy {
        if (policy == null) throw HubSessionException("INVALID_LINK_CONSENT_POLICY", "Review policy is required")
        return try {
            requireExactBodyFields(policy,
                setOf("mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds"),
                setOf("mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds"))
            val mode = optionalString(policy, "mode") ?: throw IllegalArgumentException()
            val reviewers = policy.get("reviewers")?.takeIf { it.isJsonArray }?.asJsonArray?.map { item ->
                val row = item.takeIf { it.isJsonObject }?.asJsonObject ?: throw IllegalArgumentException()
                requireExactBodyFields(row, setOf("endpoint_id", "group_id"), setOf("endpoint_id", "group_id"))
                LinkReviewPolicyConsentReviewer(
                    requestToken(row, "endpoint_id"), requestToken(row, "group_id"),
                )
            } ?: throw IllegalArgumentException()
            val candidate = LinkReviewPolicyConsentPolicy(
                mode = mode,
                reviewers = reviewers,
                maxFailovers = strictInt(policy, "max_failovers", 0, Int.MAX_VALUE),
                reviewerLeaseSeconds = strictInt(policy, "reviewer_lease_seconds", 0, Int.MAX_VALUE),
                maxReviewAgeSeconds = strictInt(policy, "max_review_age_seconds", 0, Int.MAX_VALUE),
            )
            LinkReviewPolicyConsentValidation.canonicalPolicyJson(candidate)
            candidate
        } catch (_: Exception) {
            throw HubSessionException("INVALID_LINK_CONSENT_POLICY", "Review policy is malformed or outside the supported bound")
        }
    }

    private fun strictLinkKeyStatusRows(
        array: JsonArray,
        authority: VerifiedCurrentLinkAuthority,
    ): Pair<JsonObject, JsonObject> {
        // The authority verifier already checked the exact array hash, tuple, and
        // proof contents. This pass creates only the tiny UI metadata projection.
        if (array.size() != 2) throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Both current Link status rows are required")
        val rows = array.map { it.takeIf { element -> element.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Link status row is malformed") }
        fun project(side: String): JsonObject {
            val row = rows.singleOrNull { optionalString(it, "side") == side }
                ?: throw HubSessionException("LINK_KEY_GRANTS_INVALID", "A current Link status side is missing")
            val currentStatus = optionalString(row, "current_status")
                ?: throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Current Link status is malformed")
            val accepted = row.get("accepted")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
                ?: throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Current Link acceptance state is malformed")
            if (currentStatus !in setOf("MISSING", "ACCEPTED", "KEY_BINDING_STALE", "OWNER_KEY_REVOKED", "PROOF_EXPIRED", "INVALID", "LEGACY_KEY_UNBOUND") ||
                (currentStatus == "ACCEPTED" && !accepted)) {
                throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Current Link status is outside the supported state set")
            }
            return JsonObject().apply {
                addProperty("side", side)
                addProperty("currentStatus", currentStatus)
                addProperty("accepted", accepted)
            }
        }
        // Keep the factory argument used as a deliberate provenance boundary.
        if (authority.currentLink.linkId.isBlank()) throw HubSessionException("LINK_KEY_GRANTS_INVALID", "Verified Link authority is unavailable")
        return project("SOURCE") to project("TARGET")
    }

    private fun resolveKeyGrantFenceIfExact(state: State, prepared: LinkConsentPreparation) {
        val fence = state.linkConsentLedger.writeFence ?: return
        if (fence.operation != "link.key_grant" || prepared.review.tuple.kind != "KEY") return
        val existing = state.linkConsentLedger.review ?: return
        if (prepared.review.tuple != existing.tuple || fence.tupleDigest != LinkConsentLedger.digestTuple(existing.tuple) ||
            prepared.ownerGrantStatusRead.responseSequence <= fence.expectedResponseSequence) return
        val hashes = try {
            prepared.ownerGrantStatuses.map { row ->
                val evidence = row.takeIf { it.isJsonObject }?.asJsonObject?.get("evidence")
                    ?.takeIf { it.isJsonObject }?.asJsonObject
                    ?: return
                val encoded = optionalString(evidence, "signed_proof")
                    ?: return
                val raw = java.util.Base64.getDecoder().decode(encoded)
                if (java.util.Base64.getEncoder().encodeToString(raw) != encoded || raw.isEmpty() || raw.size > LinkConsentLedger.MAX_PROOF_BYTES) return
                LinkConsentLedger.digest(raw)
            }.toSet()
        } catch (_: Exception) { return }
        if (fence.signedProofSha256 !in hashes) return
        val sourceKey = prepared.sourceCurrentKey ?: return
        val targetKey = prepared.targetCurrentKey ?: return
        if (sourceKey.state != "ACTIVE" || targetKey.state != "ACTIVE") return
        try {
            state.linkConsentLedger = state.linkConsentLedger.resolveActivatedPair(
                LinkConsentLedger.VerifiedActivatedPair(
                    linkId = prepared.authority.currentLink.linkId,
                    linkVersion = prepared.authority.currentLink.linkVersion,
                    contractDigest = prepared.authority.manifest.contractDigest,
                    manifestDigest = prepared.authority.manifest.digest,
                    policyDigest = null,
                    policyVersion = null,
                    tupleDigest = fence.tupleDigest,
                    includedSignedProofSha256 = hashes,
                    freshResponseSequence = prepared.ownerGrantStatusRead.responseSequence,
                ),
            )
            clearLinkUncertainLatch(state, fence.operationId)
            writeState(state)
        } catch (_: Exception) {
            // A mismatch keeps the original fence and exact packet intact.
        }
    }

    private fun linkConsentReviewJson(review: LinkConsentLedger.Review, policyStatus: JsonObject?): JsonObject {
        val tuple = review.tuple
        val local = if (tuple.localSide == "SOURCE") tuple.source else tuple.target
        val peer = if (tuple.localSide == "SOURCE") tuple.target else tuple.source
        val maximumExpiry = tuple.maximumProofExpiresAt ?: run {
            val signer = parseObject(review.signingRequestJson, "Saved Owner signing request is invalid")
            optionalString(signer, "max_expiry") ?: throw HubSessionException("LINK_CONSENT_REVIEW_INVALID", "Owner signing expiry is missing")
        }
        return JsonObject().apply {
            addProperty("reviewId", review.reviewId)
            addProperty("consentDigest", review.consentDigest)
            addProperty("linkId", tuple.linkId)
            addProperty("linkVersion", tuple.linkVersion.toString())
            addProperty("side", tuple.localSide)
            addProperty("manifestDigest", tuple.manifestDigest)
            addProperty("contractDigest", tuple.contractDigest)
            addProperty("sourceEndpointId", tuple.source.endpointId)
            addProperty("sourceGroupId", tuple.source.groupId)
            addProperty("targetEndpointId", tuple.target.endpointId)
            addProperty("targetGroupId", tuple.target.groupId)
            addProperty("direction", tuple.direction)
            add("actions", JsonArray().apply { tuple.actions.forEach(::add) })
            add("dataScopes", JsonArray().apply { tuple.dataScopes.forEach(::add) })
            addProperty("expiresAt", tuple.expiresAt)
            addProperty("sourceKeyFingerprint", tuple.source.keyFingerprint)
            addProperty("targetKeyFingerprint", tuple.target.keyFingerprint)
            tuple.policyDigest?.let { addProperty("policyDigest", it) }
            tuple.policyVersion?.let { addProperty("policyVersion", it.toString()) }
            addProperty("maximumProofExpiresAt", maximumExpiry)
            addProperty("ownerKeyId", local.ownerKeyId)
            addProperty("ownerKeyFingerprint", "sha256:${local.ownerFingerprint}")
            addProperty("peerOwnerKeyFingerprint", "sha256:${peer.ownerFingerprint}")
            add("qualifications", JsonArray().apply {
                tuple.reviewers.forEach { qualification -> add(JsonObject().apply {
                    addProperty("endpointId", qualification.endpointId)
                    addProperty("groupId", qualification.groupId)
                    addProperty("membershipRevision", qualification.membershipRevision.toString())
                    addProperty("joinRevision", qualification.joinRevision.toString())
                    addProperty("groupVersion", qualification.groupVersion.toString())
                    addProperty("bindingId", qualification.bindingId)
                    addProperty("bindingEpoch", qualification.bindingEpoch.toString())
                    addProperty("leaseExpiresAt", qualification.leaseExpiresAt)
                    addProperty("action", qualification.action)
                }) }
            })
            addProperty("signingRequestJson", review.signingRequestJson)
            policyStatus?.let { add("currentPolicyStatus", it.deepCopy()) }
        }
    }

    private fun linkPolicyStatusDisplay(status: LinkReviewPolicyV164Status): JsonObject {
        val bySide = status.ownerApprovals.associateBy { it.side }
        // The wire's unconfigured NONE head has no approval rows or digest.
        val unconfigured = status.policyVersion == 0L
        val source = bySide["SOURCE"]
        val target = bySide["TARGET"]
        if (!unconfigured && (source == null || target == null)) {
            throw HubSessionException("LINK_REVIEW_POLICY_STATUS_INVALID", "Configured policy status omitted an Owner side")
        }
        val bilateral = !unconfigured && status.current &&
            source?.currentStatus == "VERIFIED" && target?.currentStatus == "VERIFIED" &&
            source.verifiedProof != null && target.verifiedProof != null
        return JsonObject().apply {
            addProperty("policyVersion", status.policyVersion.toString())
            addProperty("digest", status.policyDigest)
            addProperty("current", status.current)
            addProperty("sourceStatus", source?.currentStatus ?: "MISSING")
            addProperty("targetStatus", target?.currentStatus ?: "MISSING")
            addProperty("bilateralVerified", bilateral)
        }
    }

    private fun linkConsentFenceReceipt(state: State): JsonObject = JsonObject().apply {
        val fence = state.linkConsentLedger.writeFence
        addProperty("reconciliationRequired", fence != null)
        fence?.let {
            addProperty("operation", it.operation)
            addProperty("operationId", it.operationId)
            addProperty("requestSequence", it.requestSequence.toString())
            addProperty("state", it.state.name)
        }
    }

    private fun strictLong(value: JsonObject, key: String, minimum: Long, maximum: Long): Long {
        val token = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
            ?: throw IllegalArgumentException("Invalid integer")
        if (!token.matches(Regex("0|[1-9][0-9]*"))) throw IllegalArgumentException("Invalid integer")
        val parsed = token.toLongOrNull() ?: throw IllegalArgumentException("Integer out of range")
        if (parsed !in minimum..maximum) throw IllegalArgumentException("Integer out of range")
        return parsed
    }

    private fun strictInt(value: JsonObject, key: String, minimum: Int, maximum: Int): Int =
        strictLong(value, key, minimum.toLong(), maximum.toLong()).toInt()

    /** Reads a metadata-only policy status through the current scoped profile. */
    fun linkReviewPolicyStatus(linkId: String, expectedLinkVersion: Long): JsonObject =
        linkReviewPolicyStatus(linkId, expectedLinkVersion, 1L)

    /**
     * v1.6.4 adds proof-bearing fields to the status response. This legacy UI
     * read projects only the bounded metadata fields it already displays; it
     * never exposes or treats the embedded Owner evidence as verified consent.
     */
    fun linkReviewPolicyStatus(
        linkId: String,
        expectedLinkVersion: Long,
        profileGeneration: Long,
    ): JsonObject = PROCESS_LOCK.withLock {
        val selector = try {
            LinkReviewPolicyStatusValidation.validateLinkId(linkId)
        } catch (_: LinkReviewPolicyStatusValidationException) {
            throw HubSessionException("INVALID_CLIENT_READ_REQUEST", "Link policy status selector is invalid")
        }
        try {
            LinkReviewPolicyStatusValidation.validateExpectedLinkVersion(expectedLinkVersion)
        } catch (_: LinkReviewPolicyStatusValidationException) {
            throw HubSessionException("INVALID_CLIENT_READ_REQUEST", "Link policy status version is invalid")
        }

        val state = readState()
        requireLinkConsentSession(state, profileGeneration, setOf("link.review_policy_status"), allowFenceRead = false)

        val selection = freshOwnerLinkSelection(state, selector)
        if (selection.linkVersion != expectedLinkVersion) {
            throw HubSessionException("LINK_REVIEW_LINK_STALE", "Selected Link changed; refresh the Link list before reading its policy status")
        }
        val read = directLinkRead(state, "link.review_policy_status", selection.linkId, profileGeneration,
            selection = selection)
        val raw = read.result.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("LINK_REVIEW_STATUS_INVALID", "Hub returned no Link policy status DTO")
        val metadata = sanitizeV164PolicyStatusMetadata(raw, selector, expectedLinkVersion)
        try {
            LinkReviewPolicyStatusValidation.validateStatus(metadata, selector, expectedLinkVersion)
        } catch (_: Exception) {
            throw HubSessionException("LINK_REVIEW_STATUS_INVALID", "Authenticated Link policy metadata is malformed or out of scope")
        }
        metadata
    }

    private fun sanitizeV164PolicyStatusMetadata(
        raw: JsonObject,
        expectedLinkId: String,
        expectedLinkVersion: Long,
    ): JsonObject {
        try {
            val required = setOf("link_id", "link_version", "contract_digest", "policy_version", "policy_digest",
                "policy", "current", "accepted_sides", "verified_at", "owner_approvals")
            val optional = setOf("expires_at")
            if (!raw.keySet().containsAll(required) || raw.keySet().any { it !in required && it !in optional }) {
                throw IllegalArgumentException()
            }
            if (optionalString(raw, "link_id") != expectedLinkId || strictLong(raw, "link_version", 1L, Long.MAX_VALUE) != expectedLinkVersion ||
                optionalString(raw, "contract_digest")?.matches(Regex("[0-9a-f]{64}")) != true ||
                optionalString(raw, "verified_at") == null) throw IllegalArgumentException()
        val approvals = raw.get("owner_approvals")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException()
            val policyVersion = strictLong(raw, "policy_version", 0L, Long.MAX_VALUE)
            if ((policyVersion == 0L && approvals.size() != 0) ||
                (policyVersion > 0L && approvals.size() != 2)) throw IllegalArgumentException()
            val statusBySide = linkedMapOf<String, String>()
            for (item in approvals) {
                val row = item.takeIf { it.isJsonObject }?.asJsonObject ?: throw IllegalArgumentException()
                val rowRequired = setOf("side", "owner_id", "current_status")
                if (!row.keySet().containsAll(rowRequired) || row.keySet().any { it !in rowRequired && it != "evidence" }) {
                    throw IllegalArgumentException()
                }
                val side = optionalString(row, "side") ?: throw IllegalArgumentException()
                val owner = optionalString(row, "owner_id") ?: throw IllegalArgumentException()
                val status = optionalString(row, "current_status") ?: throw IllegalArgumentException()
                if (side !in setOf("SOURCE", "TARGET") || owner.isBlank() ||
                    status !in setOf("MISSING", "VERIFIED", "OWNER_KEY_REVOKED", "PROOF_EXPIRED", "SCOPE_STALE", "INVALID") ||
                    statusBySide.put(side, status) != null) throw IllegalArgumentException()
                row.get("evidence")?.takeUnless { it.isJsonNull }?.let { evidenceElement ->
                    val evidence = evidenceElement.takeIf { it.isJsonObject }?.asJsonObject ?: throw IllegalArgumentException()
                    val allowedEvidence = setOf("owner_key_id", "owner_public_identity", "owner_key_state", "owner_key_version", "signed_proof", "accepted_at")
                    if (!evidence.keySet().containsAll(allowedEvidence) || evidence.keySet().any { it !in allowedEvidence }) {
                        throw IllegalArgumentException()
                    }
                }
            }
            if (policyVersion == 0L) {
                if (statusBySide.isNotEmpty()) throw IllegalArgumentException()
            } else if (statusBySide.keys != setOf("SOURCE", "TARGET")) {
                throw IllegalArgumentException()
            }
            val accepted = raw.get("accepted_sides")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException()
            val acceptedSides = accepted.map { item ->
                item.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: throw IllegalArgumentException()
            }
            if (acceptedSides != listOf("SOURCE", "TARGET").filter { statusBySide[it] == "VERIFIED" }) {
                throw IllegalArgumentException()
            }
            val sanitized = JsonObject().apply {
                add("link_id", raw.get("link_id").deepCopy())
                add("link_version", raw.get("link_version").deepCopy())
                add("policy_version", raw.get("policy_version").deepCopy())
                add("policy_digest", raw.get("policy_digest").deepCopy())
                add("policy", raw.get("policy").deepCopy())
                add("current", raw.get("current").deepCopy())
                add("accepted_sides", raw.get("accepted_sides").deepCopy())
                raw.get("expires_at")?.let { add("expires_at", it.deepCopy()) }
            }
            return sanitized
        } catch (_: Exception) {
            throw HubSessionException("LINK_REVIEW_STATUS_INVALID", "Authenticated Link policy status is malformed")
        }
    }

    private fun freshOwnerLinkSelection(state: State, linkId: String): LinkReviewPolicySelection {
        val seenCursors = HashSet<String>()
        val seenLinkIds = HashSet<String>()
        var cursor: String? = null
        repeat(MAX_LINK_STATUS_LIST_PAGES) {
            val request = JsonObject().apply {
                addProperty("limit", LINK_STATUS_LIST_LIMIT)
                cursor?.let { addProperty("cursor", it) }
            }
            val response = createAndSend(state, "link.list", request)
            if (response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true) {
                throw HubSessionException("LINK_REVIEW_LIST_UNAVAILABLE", "Hub did not return the current Owner Link list")
            }
            val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw HubSessionException("LINK_REVIEW_LIST_INVALID", "Hub returned no Link list page")
            val page = try {
                LinkReviewPolicyStatusValidation.parseLinkListPage(result)
            } catch (_: LinkReviewPolicyStatusValidationException) {
                throw HubSessionException("LINK_REVIEW_LIST_INVALID", "Hub returned an invalid or unbounded Owner Link list page")
            }
            for (item in page.links) {
                if (!seenLinkIds.add(item.linkId)) {
                    throw HubSessionException("LINK_REVIEW_LIST_INVALID", "Hub repeated a Link while paging the Owner list")
                }
                if (item.linkId == linkId) return item
            }
            if (!page.hasMore) {
                throw HubSessionException("LINK_REVIEW_LINK_UNAVAILABLE", "Selected Link is not present in the authenticated Owner list")
            }
            if (!seenCursors.add(page.cursor)) {
                throw HubSessionException("LINK_REVIEW_LIST_INVALID", "Hub repeated a Link list cursor")
            }
            cursor = page.cursor
        }
        throw HubSessionException("LINK_REVIEW_LIST_TOO_LARGE", "Owner Link list exceeded the bounded page limit")
    }

    /** Reads only the authenticated Owner's bounded, explicitly opted-in Network directory. */
    private fun networkDirectoryRead(state: State, body: JsonObject, operationId: String?): JsonObject {
        requireExactBodyFields(body, setOf("network_id", "after_endpoint_id", "limit"), setOf("network_id"))
        val networkId = requestToken(body, "network_id")
        if (state.activeNetworkId != networkId) {
            throw HubSessionException("NETWORK_SELECTION_REQUIRED", "Select this Network explicitly in the active Hub profile")
        }
        val after = body.get("after_endpoint_id")?.let { requestToken(body, "after_endpoint_id") }
        val limit = body.get("limit")?.let { requestInteger(body, "limit", 1, 64) } ?: 64L
        val request = JsonObject().apply {
            addProperty("network_id", networkId)
            after?.let { addProperty("after_endpoint_id", it) }
            addProperty("limit", limit)
        }
        requireNetworkAvailability(state, setOf("topology.snapshot", "network.directory"))
        freshOwnerNetworkProjection(state, networkId)
        val response = createAndSend(state, "network.directory", request, operationId)
        validateNetworkDirectoryResult(response, networkId, limit)
        return response
    }

    /** Freshly previews one same-Owner endpoint admission; this method never applies it. */
    private fun topologyEndpointAdmissionPreview(
        state: State,
        body: JsonObject,
        operationId: String?,
    ): JsonObject {
        requireExactBodyFields(body, setOf("network_id", "group_id", "endpoint_id"),
            setOf("network_id", "group_id", "endpoint_id"))
        val networkId = requestToken(body, "network_id")
        val groupId = requestToken(body, "group_id")
        val endpointId = requestToken(body, "endpoint_id")
        if (state.activeNetworkId != networkId) {
            throw HubSessionException("NETWORK_SELECTION_REQUIRED", "Select this Network explicitly in the active Hub profile")
        }
        requireNetworkAvailability(state, setOf("topology.snapshot", "topology.endpoint_admission_preview"))
        val projection = freshOwnerNetworkProjection(state, networkId, groupId, endpointId)
        val group = projection.group!!
        val endpoint = projection.endpoint!!
        val response = createAndSend(state, "topology.endpoint_admission_preview", JsonObject().apply {
            addProperty("network_id", networkId)
            addProperty("group_id", groupId)
            addProperty("endpoint_id", endpointId)
        }, operationId)
        validateEndpointAdmissionPreview(response, state.enrollment!!.ownerId, networkId,
            groupId, endpointId, projection.network, group, endpoint)
        return response
    }

    /** Fetches a fresh Owner projection immediately before a v1.6 scoped read. */
    private fun freshOwnerNetworkProjection(
        state: State,
        networkId: String,
        groupId: String? = null,
        endpointId: String? = null,
    ): V16OwnerNetworkProjection {
        val response = createAndSend(state, "topology.snapshot", JsonObject())
        val snapshot = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
        try {
            require(response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true &&
                snapshot != null && longValue(snapshot, "contract_version") == 2L &&
                requiredString(snapshot, "owner_principal_id") == state.enrollment!!.ownerId &&
                requiredString(snapshot, "read_consistency") == "best_effort")
            val networks = snapshot.get("networks")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException("Network list is missing")
            val network = networks.filter { it.isJsonObject }.map { it.asJsonObject }
                .single { optionalString(it, "network_id") == networkId }
            require(requiredString(network, "state") == "ACTIVE" &&
                network.get("can_create_group")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true &&
                longValue(network, "version") > 0L)
            if (groupId == null && endpointId == null) return V16OwnerNetworkProjection(network)

            val groups = snapshot.get("groups")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException("Group list is missing")
            val group = groups.filter { it.isJsonObject }.map { it.asJsonObject }
                .single { optionalString(it, "group_id") == groupId }
            require(requiredString(group, "state") == "ACTIVE" &&
                requiredString(group, "network_id") == networkId && longValue(group, "version") > 0L)

            val endpoints = snapshot.get("endpoints")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException("Endpoint list is missing")
            val endpoint = endpoints.filter { it.isJsonObject }.map { it.asJsonObject }
                .single { optionalString(it, "endpoint_id") == endpointId }
            val endpointNetworks = endpoint.get("network_ids")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException("Endpoint Network list is missing")
            require(endpointNetworks.any { it.isJsonPrimitive && it.asJsonPrimitive.isString && it.asString == networkId } &&
                requiredString(endpoint, "principal_id").isNotBlank() &&
                optionalString(endpoint, "presence") != "left")
            return V16OwnerNetworkProjection(network, group, endpoint)
        } catch (_: Exception) {
            throw HubSessionException("NETWORK_TOPOLOGY_INVALID", "The current Owner topology does not contain the exact ACTIVE Network and same-Owner preview scope")
        }
    }

    private fun validateNetworkDirectoryResult(response: JsonObject, networkId: String, requestedLimit: Long) {
        val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
        try {
            require(response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true &&
                result != null)
            requireExactObjectFields(result, setOf("network_id", "endpoints", "next_cursor"),
                setOf("network_id", "endpoints"))
            require(requiredString(result, "network_id") == networkId)
            val endpoints = result.get("endpoints")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException("Directory endpoint list is missing")
            require(endpoints.size() <= 64 && endpoints.size().toLong() <= requestedLimit)
            val seen = HashSet<String>()
            endpoints.forEach { item ->
                require(item.isJsonObject)
                val card = item.asJsonObject
                requireExactObjectFields(card, setOf("network_id", "endpoint_id", "alias", "presence"),
                    setOf("network_id", "endpoint_id", "alias", "presence"))
                require(requiredString(card, "network_id") == networkId)
                val endpointId = responseToken(card, "endpoint_id")
                require(seen.add(endpointId))
                require(displayString(card, "alias").length <= 256)
                require(requiredString(card, "presence") in setOf("ACCESS_RECENT", "UNKNOWN"))
            }
            result.get("next_cursor")?.let { cursor ->
                require(cursor.isJsonPrimitive && cursor.asJsonPrimitive.isString &&
                    cursor.asString.length in 1..256)
            }
        } catch (_: Exception) {
            throw HubSessionException("NETWORK_DIRECTORY_INVALID", "Hub returned an invalid bounded Network directory page")
        }
    }

    private fun validateEndpointAdmissionPreview(
        response: JsonObject,
        ownerId: String,
        networkId: String,
        groupId: String,
        endpointId: String,
        network: JsonObject,
        group: JsonObject,
        endpoint: JsonObject,
    ) {
        val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
        val required = setOf(
            "owner_principal_id", "network_id", "network_name", "network_version", "group_id", "group_name",
            "group_version", "group_context_policy", "endpoint_id", "endpoint_name", "endpoint_principal_id",
            "endpoint_migration_state", "network_membership_revision", "endpoint_network_revision",
            "network_access_binding_id", "network_access_epoch", "native_binding_id", "native_binding_epoch",
            "membership_revision", "endpoint_group_revision", "admission_roles", "admission_grants",
            "history_included", "key_grant_created", "existing_thread_memory_retained",
        )
        val allowed = required + setOf(
            "existing_group_binding_id", "existing_group_binding_epoch", "membership_status", "endpoint_group_status",
        )
        try {
            require(response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true &&
                result != null)
            requireExactObjectFields(result, allowed, required)
            require(responseToken(result, "owner_principal_id") == ownerId &&
                responseToken(result, "network_id") == networkId && responseToken(result, "group_id") == groupId &&
                responseToken(result, "endpoint_id") == endpointId)
            require(displayString(result, "network_name") == displayString(network, "name") &&
                longValue(result, "network_version") == longValue(network, "version") &&
                displayString(result, "group_name") == displayString(group, "name") &&
                longValue(result, "group_version") == longValue(group, "version") &&
                displayString(result, "group_context_policy") == displayString(group, "context_policy") &&
                responseToken(result, "endpoint_principal_id") == responseToken(endpoint, "principal_id") &&
                displayString(result, "endpoint_name") == displayString(endpoint, "name"))
            require(responseToken(result, "endpoint_migration_state") in setOf("READY", "MIGRATION_PENDING_GROUP"))
            listOf("network_membership_revision", "endpoint_network_revision", "network_access_epoch",
                "native_binding_epoch").forEach { require(longValue(result, it) > 0L) }
            listOf("membership_revision", "endpoint_group_revision").forEach { require(longValue(result, it) >= 0L) }
            listOf("network_access_binding_id", "native_binding_id").forEach { responseToken(result, it) }
            require(result.getAsJsonArray("admission_roles").size() == 1 &&
                result.getAsJsonArray("admission_roles")[0].asString == "member" &&
                result.getAsJsonArray("admission_grants").size() == 0)
            require(requiredBoolean(result, "history_included") == false &&
                requiredBoolean(result, "key_grant_created") == false &&
                requiredBoolean(result, "existing_thread_memory_retained"))
            result.get("existing_group_binding_id")?.let { responseToken(result, "existing_group_binding_id") }
            result.get("existing_group_binding_epoch")?.let { require(longValue(result, "existing_group_binding_epoch") >= 0L) }
            result.get("membership_status")?.let { displayString(result, "membership_status") }
            result.get("endpoint_group_status")?.let { displayString(result, "endpoint_group_status") }
        } catch (_: Exception) {
            throw HubSessionException("TOPOLOGY_ADMISSION_PREVIEW_INVALID", "Hub returned an invalid or stale same-Owner Endpoint admission preview")
        }
    }

    private fun requireExactBodyFields(value: JsonObject, allowed: Set<String>, required: Set<String>) {
        if (value.entrySet().any { it.key !in allowed } || required.any { !value.has(it) || value.get(it).isJsonNull }) {
            throw HubSessionException("INVALID_CLIENT_READ_REQUEST", "Client read request does not match the supported v1.6 shape")
        }
    }

    private fun requireExactObjectFields(value: JsonObject, allowed: Set<String>, required: Set<String>) {
        require(value.entrySet().all { it.key in allowed } && required.all { value.has(it) && !value.get(it).isJsonNull })
    }

    private fun requestToken(value: JsonObject, key: String): String {
        val token = optionalString(value, key)
        if (token == null || token.isBlank() || token != token.trim() || token.length > 256) {
            throw HubSessionException("INVALID_CLIENT_READ_REQUEST", "Client read request contains an invalid selector")
        }
        return token
    }

    private fun requestInteger(value: JsonObject, key: String, minimum: Long, maximum: Long): Long {
        val number = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?.asString?.toLongOrNull()
        if (number == null || number !in minimum..maximum) {
            throw HubSessionException("INVALID_CLIENT_READ_REQUEST", "Client read request contains an invalid page limit")
        }
        return number
    }

    private fun responseToken(value: JsonObject, key: String): String {
        val token = optionalString(value, key)
        require(token != null && token.isNotBlank() && token == token.trim() && token.length <= 256)
        return token!!
    }

    private fun displayString(value: JsonObject, key: String): String {
        val text = optionalString(value, key)
        require(text != null && text.length <= 1024)
        return text!!
    }

    private fun requiredBoolean(value: JsonObject, key: String): Boolean {
        val item = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }
            ?: throw IllegalArgumentException("Boolean result field is invalid")
        return item.asBoolean
    }

    private fun verifiedNetworkManifest(state: State, networkId: String, endpointId: String,
                                        owner: ClientWireCrypto.PublicIdentity): JsonObject {
        val endpoint = freshNetworkEndpoint(state, networkId, endpointId)
        val response = createAndSend(state, "network.key_manifest", JsonObject().apply {
            addProperty("network_id", networkId)
            addProperty("endpoint_id", endpointId)
            addProperty("owner_key_id", owner.id)
        })
        val manifest = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
        if (response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true || manifest == null) {
            throw HubSessionException("NETWORK_MANIFEST_UNAVAILABLE", "Hub did not return a current Network Endpoint key manifest")
        }
        try {
            NetworkKeyConsent.verifyManifest(manifest, state.pin!!.hubId, state.enrollment!!.ownerId,
                networkId, endpointId)
            require(requiredString(manifest, "principal_id") == requiredString(endpoint, "principal_id") &&
                requiredString(manifest, "node_id") == requiredString(endpoint, "node_id") &&
                requiredString(manifest, "native_session_id") == requiredString(endpoint, "native_session_id"))
            // Topology's optional binding fields are Group leases, not Network direct bindings.
            // Network binding/revisions are covered by the complete signed candidate and manifest.
        } catch (_: Exception) {
            throw HubSessionException("NETWORK_MANIFEST_INVALID", "Network self-attestation, public key, native binding or manifest digest does not match current Owner topology")
        }
        return response.deepCopy().apply { addProperty("verified", true) }
    }

    private fun freshNetworkEndpoint(state: State, networkId: String, endpointId: String): JsonObject {
        val response = createAndSend(state, "topology.snapshot", JsonObject())
        val snapshot = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
        try {
            require(response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true &&
                snapshot != null && longValue(snapshot, "contract_version") == 2L &&
                requiredString(snapshot, "owner_principal_id") == state.enrollment!!.ownerId &&
                requiredString(snapshot, "read_consistency") == "best_effort")
            val network = snapshot.getAsJsonArray("networks").map { it.asJsonObject }
                .single { optionalString(it, "network_id") == networkId }
            require(requiredString(network, "state") == "ACTIVE" && longValue(network, "version") > 0)
            val endpoint = snapshot.getAsJsonArray("endpoints").map { it.asJsonObject }
                .single { optionalString(it, "endpoint_id") == endpointId }
            require(endpoint.getAsJsonArray("network_ids").any { item ->
                item.isJsonPrimitive && item.asJsonPrimitive.isString && item.asString == networkId
            })
            require(listOf("principal_id", "node_id", "native_session_id").all {
                requiredString(endpoint, it).isNotBlank()
            } && optionalString(endpoint, "presence") != "left")
            return endpoint
        } catch (_: Exception) {
            throw HubSessionException("NETWORK_ENDPOINT_NOT_AUTHORIZED", "The selected Endpoint is absent from this Owner's current ACTIVE Network projection, or its native identity is incomplete")
        }
    }

    private fun decodeNetworkOwnerProof(expectedDigest: String, signedProofBase64: String): ByteArray {
        if (!expectedDigest.matches(Regex("[0-9a-f]{64}"))) {
            throw HubSessionException("NETWORK_CONSENT_MISMATCH", "The reviewed Network manifest digest is invalid")
        }
        if (signedProofBase64.length > 43_692) {
            throw HubSessionException("NETWORK_OWNER_PROOF_INVALID", "Owner Network proof exceeds the protocol limit")
        }
        return try { decodeCanonicalBase64(signedProofBase64).also { require(it.isNotEmpty() && it.size <= 32 * 1024) } }
            catch (_: Exception) { throw HubSessionException("NETWORK_OWNER_PROOF_INVALID", "Owner Network proof is not bounded canonical base64") }
    }

    private fun verifiedNetworkManifestForOwnerProof(state: State, networkId: String, endpointId: String,
                                                     owner: ClientWireCrypto.PublicIdentity,
                                                     expectedDigest: String, proof: ByteArray): JsonObject {
        val verified = verifiedNetworkManifest(state, networkId, endpointId, owner)
        val manifest = verified.getAsJsonObject("result")
        if (requiredString(manifest, "digest") != expectedDigest) {
            throw HubSessionException("NETWORK_MANIFEST_STALE", "Network registration, native binding or key changed; review and independently sign a new complete manifest")
        }
        verifyNetworkOwnerProof(proof, manifest, owner)
        return verified
    }

    private fun verifyNetworkOwnerProof(proof: ByteArray, manifest: JsonObject,
                                        owner: ClientWireCrypto.PublicIdentity) {
        try { NetworkKeyConsent.verifyOwnerProof(proof, manifest, owner) }
        catch (_: Exception) {
            throw HubSessionException("NETWORK_OWNER_PROOF_INVALID", "Owner Network signature, expiry or complete manifest binding is invalid")
        }
    }

    private fun verifyNetworkGrantResult(response: JsonObject, state: State, networkId: String,
                                         endpointId: String, owner: ClientWireCrypto.PublicIdentity,
                                         expectedDigest: String? = null, proof: ByteArray? = null) {
        if (response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true) return
        try {
            val result = response.getAsJsonObject("result")
            require(requiredString(result, "network_id") == networkId &&
                requiredString(result, "endpoint_id") == endpointId &&
                requiredString(result, "owner_id") == state.enrollment!!.ownerId &&
                requiredString(result, "owner_key_id") == owner.id &&
                requiredString(result, "manifest_digest").matches(Regex("[0-9a-f]{64}")) &&
                requiredString(result, "proof_digest").matches(Regex("[0-9a-f]{64}")) &&
                requiredString(result, "nonce").matches(Regex("[0-9a-f]{64}")) &&
                requiredString(result, "state") in setOf("active", "stale") &&
                longValue(result, "revision") > 0)
            GroupKeyManifestVerifier.parseCanonicalUtc(requiredString(result, "accepted_at"))
            if (expectedDigest != null && proof != null) {
                val proofJson = JsonParser.parseString(String(proof, StandardCharsets.UTF_8)).asJsonObject
                require(requiredString(result, "state") == "active" &&
                    requiredString(result, "manifest_digest") == expectedDigest &&
                    requiredString(result, "proof_digest") == NetworkKeyConsent.sha256(proof) &&
                    requiredString(result, "nonce") == requiredString(proofJson, "nonce"))
            }
        } catch (_: Exception) {
            throw HubSessionException("NETWORK_GRANT_RESULT_INVALID", "Authenticated Network grant metadata does not match this Owner and reviewed proof; reconcile with key status")
        }
    }

    private fun verifiedGroupManifestForOwnerProof(state: State, groupId: String,
                                                    endpointId: String, ownerKeyId: String,
                                                    expectedDigest: String,
                                                    signedProofBase64: String): JsonObject {
        validateOperation(state, "group.key_manifest")
        val ownerJson = state.ownerApprovalPublicIdentityJson
            ?: throw HubSessionException("OWNER_PUBLIC_KEY_REQUIRED", "Re-enroll with a pinned owner approval key before signing Group consent")
        val owner = try { ClientWireCrypto.PublicIdentity.parse(parseObject(ownerJson, "Invalid owner key")) }
            catch (_: Exception) { throw HubSessionException("OWNER_PUBLIC_KEY_INVALID", "Saved owner approval key is invalid") }
        if (owner.id != ownerKeyId || !expectedDigest.matches(Regex("[0-9a-f]{64}"))) {
            throw HubSessionException("GROUP_CONSENT_MISMATCH", "Owner key or reviewed manifest digest differs")
        }
        val proof = try { decodeCanonicalBase64(signedProofBase64) }
            catch (_: Exception) { throw HubSessionException("GROUP_OWNER_PROOF_INVALID", "Owner proof is not canonical base64") }
        if (proof.size > 16 * 1024) throw HubSessionException("GROUP_OWNER_PROOF_INVALID", "Owner proof exceeds the protocol limit")
        val proofJson = try { JsonParser.parseString(String(proof, StandardCharsets.UTF_8)).asJsonObject }
            catch (_: Exception) { throw HubSessionException("GROUP_OWNER_PROOF_INVALID", "Owner proof is not JSON") }
        val issuedAt = try { requiredString(proofJson, "issued_at") }
            catch (_: Exception) { throw HubSessionException("GROUP_OWNER_PROOF_INVALID", "Owner proof has no issued_at") }
        val expiresAt = try { requiredString(proofJson, "expires_at") }
            catch (_: Exception) { throw HubSessionException("GROUP_OWNER_PROOF_INVALID", "Owner proof has no expires_at") }
        val manifestResponse = createAndSend(state, "group.key_manifest",
            groupManifestRequest(groupId, endpointId, ownerKeyId, issuedAt, expiresAt), null)
        val verified = verifiedGroupManifest(manifestResponse, state, groupId, endpointId, ownerKeyId)
        val manifest = verified.getAsJsonObject("result")
        if (requiredString(manifest, "digest") != expectedDigest) {
            throw HubSessionException("GROUP_MANIFEST_STALE", "Group key binding or manifest changed; review a new manifest")
        }
        try { GroupKeyOwnerProof.verify(proof, manifest, owner) }
        catch (_: Exception) { throw HubSessionException("GROUP_OWNER_PROOF_INVALID", "Owner signature or manifest binding is invalid") }
        return verified
    }

    private fun groupManifestRequest(groupId: String, endpointId: String, ownerKeyId: String,
                                     issuedAt: String, expiresAt: String): JsonObject = JsonObject().apply {
        addProperty("group_id", groupId)
        addProperty("endpoint_id", endpointId)
        addProperty("owner_key_id", ownerKeyId)
        addProperty("issued_at", issuedAt)
        addProperty("expires_at", expiresAt)
    }

    private fun verifiedGroupManifest(response: JsonObject, state: State, groupId: String,
                                      endpointId: String, ownerKeyId: String): JsonObject {
        val manifest = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("GROUP_MANIFEST_UNAVAILABLE", "Hub did not return a Group key manifest")
        try {
            GroupKeyManifestVerifier.verifyManifest(manifest, state.pin!!.hubId,
                state.enrollment!!.ownerId, groupId, endpointId, ownerKeyId)
        } catch (_: Exception) {
            throw HubSessionException("GROUP_MANIFEST_INVALID", "Endpoint proof, binding or manifest digest is invalid or expired")
        }
        return response.deepCopy().apply { addProperty("verified", true) }
    }

    /** Asks Hub to recover the exact persisted packet without dispatching the operation again. */
    fun recoverPending(): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireReadyForRpc(state)
        val pending = state.pending ?: throw HubSessionException("NO_PENDING_REQUEST", "There is no encrypted request to recover")
        if (pending.expectedResponseSequence == null) {
            throw HubSessionException("RECOVERY_SEQUENCE_UNAVAILABLE", "Older pending request has no persisted expected response sequence")
        }
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val device = loadDeviceIdentity()
        try {
            val control = loadControlIdentity(pin)
            val route = routeFromPacket(pending.packetJson)
            if (route.operationId != pending.operationId || route.sequence != pending.sequence ||
                route.operation != pending.operation) {
                throw HubSessionException("PENDING_PACKET_INVALID", "Persisted request metadata differs from its signed route")
            }
            val packetResponse = try {
                httpJsonRaw(pin.baseUrl, "/v2/client/rpc/recover", pending.packetJson, MAX_RESPONSE_BYTES)
            } catch (error: HubSessionException) {
                when (error.errorCode) {
                    "HTTP_409_STILL_PROCESSING" -> {
                        state.sessionError = "STILL_PROCESSING"
                        markLinkFenceFromPending(state, LinkConsentLedger.FenceState.STILL_PROCESSING)
                        writeState(state)
                        throw HubSessionException("STILL_PROCESSING", "Original encrypted request is still processing")
                    }
                    "HTTP_409_RECOVERY_UNAVAILABLE" -> {
                        state.recoveryBlocked = true
                        state.sessionError = "RECOVERY_UNAVAILABLE"
                        markLinkFenceFromPending(state, LinkConsentLedger.FenceState.RECOVERY_UNAVAILABLE)
                        writeState(state)
                        throw HubSessionException("RECOVERY_UNAVAILABLE", "Older uncertain request cannot be safely recovered")
                    }
                    "HTTP_409_RECOVERY_REJECTED" -> {
                        state.sessionError = "RECOVERY_REJECTED"
                        markLinkFenceFromPending(state, LinkConsentLedger.FenceState.RECOVERY_REJECTED)
                        writeState(state)
                    }
                    "HTTP_403" -> {
                        state.authFenced = true
                        state.sessionCapabilitiesReady = false
                        state.allowedOperations = emptyList()
                        state.role = null
                        state.sessionError = "RPC_HTTP_403"
                        markLinkFenceFromPending(state, LinkConsentLedger.FenceState.AUTH_REVOKED)
                        writeState(state)
                    }
                    "HTTP_409" -> {
                        state.recoveryBlocked = true
                        state.sessionError = "RPC_RECOVERY_CONFLICT"
                        markLinkFenceFromPending(state, LinkConsentLedger.FenceState.UNCERTAIN)
                        writeState(state)
                    }
                }
                throw error
            }
            finishResponse(state, device, control, route, packetResponse)
        } finally {
            device.close()
        }
    }

    /** Explicit exact retry for a request that may never have reached Hub. */
    fun retryPendingExact(): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        requireReadyForRpc(state)
        val pending = state.pending
            ?: throw HubSessionException("NO_PENDING_REQUEST", "There is no encrypted request to retry")
        if (state.sessionError != "RECOVERY_REJECTED") {
            throw HubSessionException("EXACT_RETRY_NOT_READY", "First ask Hub to recover the original request")
        }
        if (pending.expectedResponseSequence == null) {
            throw HubSessionException("RECOVERY_SEQUENCE_UNAVAILABLE", "Older pending request has no persisted response sequence")
        }
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val device = loadDeviceIdentity()
        try {
            val route = routeFromPacket(pending.packetJson)
            if (route.operationId != pending.operationId || route.sequence != pending.sequence ||
                route.operation != pending.operation) {
                throw HubSessionException("PENDING_PACKET_INVALID", "Persisted request metadata differs from its signed route")
            }
            val response = sendRpcPacket(state, pin.baseUrl, pending.packetJson)
            finishResponse(state, device, loadControlIdentity(pin), route, response)
        } finally {
            device.close()
        }
    }

    fun getStatus(): JsonObject = PROCESS_LOCK.withLock {
        val state = readState()
        val pending = state.pending
        val result = JsonObject().apply {
            addProperty("profileId", profileId)
            state.activeNetworkId?.let { addProperty("activeNetworkId", it) }
            addProperty("pinned", state.pin != null)
            addProperty("enrolled", state.enrollment != null)
            addProperty("sessionCapabilitiesReady", state.sessionCapabilitiesReady)
            addProperty("remoteEnabled", state.pin != null && state.enrollment != null &&
                state.sessionCapabilitiesReady && state.allowedOperations.isNotEmpty() &&
                state.pending == null && !state.authFenced && !state.recoveryBlocked)
            addProperty("authFenced", state.authFenced)
            addProperty("recoveryBlocked", state.recoveryBlocked)
            addProperty("previousDeviceMayRemainOnHub", state.previousDeviceMayRemainOnHub)
            addProperty("hasRetiredPending", state.retiredPending != null)
            addProperty("enrollmentRecoveryRequired", state.enrollmentAttempt != null)
            addProperty("hasUnresolvedMonitorOperations", hasUnresolvedMonitorOperation(state))
            addProperty("linkConsentReconciliationRequired", state.linkConsentLedger.writeFence != null)
            state.linkConsentLedger.writeFence?.let { addProperty("linkConsentUncertainOperationId", it.operationId) }
            state.outcomeUncertainOperationId?.let { addProperty("outcomeUncertainOperationId", it) }
            addProperty("uncertainNeedsReconciliation", state.uncertainNeedsReconciliation)
            addProperty("regroupReconciliationRequired", state.regroupUncertainPending != null)
            state.regroupUncertainPending?.let { addProperty("regroupUncertainOperationId", it.operationId) }
            addProperty("networkGrantReconciliationRequired", state.networkGrantUncertainPending != null)
            state.networkGrantUncertainPending?.let { addProperty("networkGrantUncertainOperationId", it.operationId) }
            state.enrollmentAttempt?.let { attempt ->
                addProperty("pendingEnrollmentOwnerId", attempt.ownerId)
                addProperty("pendingEnrollmentDeviceId", attempt.deviceId)
            }
            if (state.pin != null) {
                addProperty("hubId", state.pin!!.hubId)
                addProperty("baseUrl", state.pin!!.baseUrl)
            }
            if (state.enrollment != null) {
                addProperty("ownerId", state.enrollment!!.ownerId)
                addProperty("deviceId", state.enrollment!!.deviceId)
                addProperty("sessionEpoch", state.enrollment!!.sessionEpoch)
                state.ownerApprovalPublicIdentityJson?.let { ownerJson ->
                    val owner = ClientWireCrypto.PublicIdentity.parse(parseObject(ownerJson, "Owner identity is invalid"))
                    addProperty("ownerKeyId", owner.id)
                }
            }
            if (state.role != null) addProperty("role", state.role)
            if (state.sessionError != null) addProperty("sessionError", state.sessionError)
            add("allowedOperations", JsonArray().apply { state.allowedOperations.forEach(::add) })
            if (state.enrollment != null) addProperty("nextSequence", state.nextSequence)
            if (pending != null) {
                addProperty("pendingOperationId", pending.operationId)
                addProperty("pendingOperation", pending.operation)
            }
        }
        result
    }

    /** Selection is local; a fresh authenticated projection must first authorize its scope. */
    internal fun setActiveNetwork(networkId: String, beforePersistSelection: () -> Unit = {}): JsonObject = PROCESS_LOCK.withLock {
        val selected = networkId.trim()
        if (selected.isEmpty() || selected.length > 256) {
            throw HubSessionException("INVALID_NETWORK_ID", "Select a current authorized Network")
        }
        val state = readState()
        requireReadyForRpc(state)
        if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original request before selecting a Network")
        validateOperation(state, "topology.snapshot")
        val response = createAndSend(state, "topology.snapshot", JsonObject())
        val snapshot = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
        if (response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true ||
            snapshot == null || longValue(snapshot, "contract_version") != 2L ||
            requiredString(snapshot, "owner_principal_id") != state.enrollment!!.ownerId ||
            optionalString(snapshot, "read_consistency") != "best_effort") {
            throw HubSessionException("NETWORK_TOPOLOGY_INVALID", "Hub did not return an authenticated Owner Network projection")
        }
        val network = snapshot.get("networks")?.takeIf { it.isJsonArray }?.asJsonArray
            ?.filter { it.isJsonObject }?.map { it.asJsonObject }
            ?.singleOrNull { optionalString(it, "network_id") == selected }
        if (network == null || optionalString(network, "state") != "ACTIVE") {
            throw HubSessionException("NETWORK_NOT_AUTHORIZED", "The selected Network is not currently ACTIVE and visible to this Owner")
        }
        // The registry generation is advanced first so a failed state write still fences old callbacks.
        beforePersistSelection()
        regroupReviews.remove(directory.absolutePath)
        state.activeNetworkId = selected
        writeState(state)
        getStatus()
    }

    internal fun ensureProfileRemovable() = PROCESS_LOCK.withLock {
        val state = readState()
        requireNetworkGrantReconciled(state)
        requireLinkConsentReconciled(state)
        if (state.pending != null || state.enrollmentAttempt != null || state.recoveryBlocked ||
            state.uncertainNeedsReconciliation || hasUnresolvedMonitorOperation(state)) {
            throw HubSessionException("PROFILE_RECOVERY_REQUIRED", "Resolve the original enrollment, encrypted request and Monitor state before removing this Hub profile")
        }
    }

    /** Local removal never revokes the device on its Hub. The caller must confirm that boundary. */
    internal fun deleteProfileState() = PROCESS_LOCK.withLock {
        ensureProfileRemovable()
        deleteDeviceWrappingKey()
        if (!directory.deleteRecursively()) {
            throw HubSessionException("PROFILE_STORAGE_FAILED", "Could not remove local Hub profile state")
        }
    }

    private fun createAndSend(
        state: State,
        operation: String,
        body: JsonObject,
        operationId: String? = null,
        monitorOperationId: String? = null,
        bodyBuilder: ((ClientWireCrypto.Identity, Enrollment, Long) -> JsonObject)? = null,
        beforePersist: ((String, Long, JsonObject) -> Unit)? = null,
        processMonitorResponse: Boolean = true,
    ): JsonObject {
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val enrollment = state.enrollment ?: throw HubSessionException("DEVICE_NOT_ENROLLED", "Device enrollment is missing")
        val device = loadDeviceIdentity()
        try {
            val control = loadControlIdentity(pin)
            val sequence = state.nextSequence
            if (sequence < 1 || sequence == Long.MAX_VALUE || state.lastResponseSequence == Long.MAX_VALUE) {
                throw HubSessionException("SEQUENCE_EXHAUSTED", "Encrypted request sequence is exhausted")
            }
            val logicalId = operationId?.trim()?.takeIf { it.isNotEmpty() } ?: UUID.randomUUID().toString()
            if (logicalId.length > 256) throw HubSessionException("INVALID_OPERATION_ID", "Operation ID is too long")
            val route = ClientWireCrypto.Route().apply {
                version = 1
                direction = "REQUEST"
                hubId = pin.hubId
                ownerId = enrollment.ownerId
                deviceId = enrollment.deviceId
                sessionEpoch = enrollment.sessionEpoch
                this.sequence = sequence
                this.operationId = logicalId
                this.operation = operation
                senderKeyId = device.publicIdentity.id
                senderKeyVersion = enrollment.deviceKeyVersion
                receiverKeyId = control.id
                receiverKeyVersion = pin.controlKeyVersion
            }
            val requestBody = bodyBuilder?.invoke(device, enrollment, sequence) ?: body
            val bodyText = requestBody.toString()
            if (bodyText.toByteArray(StandardCharsets.UTF_8).size > MAX_BODY_BYTES) {
                throw HubSessionException("REQUEST_TOO_LARGE", "Encrypted RPC body exceeds the protocol limit")
            }
            val exactPacket = try {
                ClientWireCrypto.sealRequest(device, control, route, bodyText)
            } catch (_: Exception) {
                throw HubSessionException("ENCRYPTION_FAILED", "Could not seal the encrypted RPC request")
            }
            if (exactPacket.toByteArray(StandardCharsets.UTF_8).size > MAX_PACKET_BYTES) {
                throw HubSessionException("REQUEST_TOO_LARGE", "Encrypted RPC packet exceeds the protocol limit")
            }
            state.nextSequence = sequence + 1
            state.pending = Pending(operation, logicalId, sequence, state.lastResponseSequence + 1,
                exactPacket, monitorOperationId)
            beforePersist?.invoke(logicalId, sequence, requestBody)
            writeState(state) // Sequence and original ciphertext reach durable storage before network I/O.
            val response = sendRpcPacket(state, pin.baseUrl, exactPacket)
            return finishResponse(state, device, control, route, response, processMonitorResponse)
        } finally {
            device.close()
        }
    }

    private fun validateLinkReviewStatusContext(
        context: LinkReviewStatusReadContext,
        state: State,
        pending: Pending,
        route: ClientWireCrypto.Route,
    ) {
        val enrollment = state.enrollment
        val pin = state.pin
        try {
            LinkReviewPolicyStatusValidation.validateLinkId(context.linkId)
            LinkReviewPolicyStatusValidation.validateExpectedLinkVersion(context.linkVersion)
        } catch (_: LinkReviewPolicyStatusValidationException) {
            throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Original Link policy status selection is malformed")
        }
        if (pending.operation != "link.review_policy_status" || route.operation != pending.operation ||
            context.operationId != pending.operationId || context.operationId != route.operationId ||
            context.sequence != pending.sequence || context.sequence != route.sequence ||
            context.mySide !in setOf("SOURCE", "TARGET") ||
            context.hubId != route.hubId || pin?.hubId != route.hubId ||
            context.ownerId != route.ownerId || enrollment?.ownerId != route.ownerId ||
            context.deviceId != route.deviceId || enrollment?.deviceId != route.deviceId ||
            context.sessionEpoch != route.sessionEpoch || enrollment?.sessionEpoch != route.sessionEpoch) {
            throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Original Link policy status route no longer matches its selected Hub, Owner, device and Link")
        }
    }

    private fun validateLinkConsentStatusReadContext(
        context: LinkConsentStatusReadContext,
        state: State,
        pending: Pending,
        route: ClientWireCrypto.Route,
    ) {
        if (pending.operation != "link.review_policy_status" || route.operation != pending.operation ||
            context.operationId != pending.operationId || context.operationId != route.operationId ||
            context.sequence != pending.sequence || context.sequence != route.sequence ||
            context.linkVersion < 1 || context.mySide !in setOf("SOURCE", "TARGET") ||
            context.hubId != route.hubId || state.pin?.hubId != route.hubId ||
            context.ownerId != route.ownerId || state.enrollment?.ownerId != route.ownerId ||
            context.deviceId != route.deviceId || state.enrollment?.deviceId != route.deviceId ||
            context.sessionEpoch != route.sessionEpoch || state.enrollment?.sessionEpoch != route.sessionEpoch ||
            context.profileGeneration < 1) {
            throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Original candidate Link policy status route no longer matches its selected session and Link")
        }
    }

    /**
     * Verifies a terminal policy grant at the authenticated result's own historical
     * verification time. This is for reconciling that exact original packet only;
     * it does not make the cached result fresh for a later review or signature.
     */
    private fun verifyHistoricalLinkPolicyGrantResult(
        state: State,
        result: JsonObject,
        fence: LinkConsentLedger.WriteFence,
    ): LinkReviewPolicyV164Status? {
        return try {
            val review = state.linkConsentLedger.review ?: return null
            val tuple = review.tuple
            val policyVersion = tuple.policyVersion ?: return null
            val policyDigest = tuple.policyDigest ?: return null
            val expectedPolicyVersion = tuple.expectedPolicyVersion ?: return null
            if (review.reviewId != fence.reviewId || review.consentDigest != fence.consentDigest ||
                tuple.kind != "REVIEW_POLICY" || tuple.localSide !in setOf("SOURCE", "TARGET") ||
                fence.operation != "link.review_policy_grant" ||
                fence.tupleDigest != LinkConsentLedger.digestTuple(tuple) ||
                expectedPolicyVersion == Long.MAX_VALUE || policyVersion != expectedPolicyVersion + 1L) return null

            val verifiedAtText = optionalString(result, "verified_at") ?: return null
            val verifiedAt = Instant.parse(verifiedAtText)
            if (verifiedAt.toString() != verifiedAtText || verifiedAt > Instant.now()) return null

            fun pinnedPolicyOwner(scope: LinkConsentLedger.SideScope): LinkReviewPolicyV164OwnerPin {
                val record = state.linkConsentLedger.ownerPin(scope.ownerId, scope.ownerKeyId)
                    ?: throw IllegalArgumentException("Missing independent Owner pin")
                if (record.pinRevision != scope.ownerPinRevision || record.fingerprint != scope.ownerFingerprint) {
                    throw IllegalArgumentException("Owner pin revision differs from the saved review")
                }
                val identity = parseIndependentOwnerIdentity(record.publicIdentityJson)
                if (identity.id != scope.ownerKeyId || identity.fingerprint() != scope.ownerFingerprint) {
                    throw IllegalArgumentException("Owner public identity differs from the saved review")
                }
                return LinkReviewPolicyV164OwnerPin(record.ownerId, record.keyId, identity)
            }

            val currentLink = LinkReviewPolicyV164CurrentLink(
                linkId = tuple.linkId,
                linkVersion = tuple.linkVersion,
                contractDigest = tuple.contractDigest,
                localSide = tuple.localSide,
                sourceOwnerId = tuple.source.ownerId,
                targetOwnerId = tuple.target.ownerId,
                sourceEndpointId = tuple.source.endpointId,
                sourceGroupId = tuple.source.groupId,
                targetEndpointId = tuple.target.endpointId,
                targetGroupId = tuple.target.groupId,
                expiresAt = Instant.parse(tuple.expiresAt),
                sourceOwnerPin = pinnedPolicyOwner(tuple.source),
                targetOwnerPin = pinnedPolicyOwner(tuple.target),
            )
            val status = LinkReviewPolicyEvidenceV164.validateActiveStatus(
                result.toString().toByteArray(StandardCharsets.UTF_8), currentLink, verifiedAt,
            )
            if (status.linkId != tuple.linkId || status.linkVersion != tuple.linkVersion ||
                status.contractDigest != tuple.contractDigest || status.policyVersion != policyVersion ||
                status.policyDigest != policyDigest) return null
            val savedPolicyJson = review.policyJson ?: return null
            val savedPolicy = parseLinkConsentPolicy(JsonParser.parseString(savedPolicyJson).asJsonObject)
            if (LinkReviewPolicyConsentValidation.canonicalPolicyJson(savedPolicy) !=
                LinkReviewPolicyConsentValidation.canonicalPolicyJson(status.policy)) return null

            val approvals = status.ownerApprovals.associateBy { it.side }
            for ((side, scope) in listOf("SOURCE" to tuple.source, "TARGET" to tuple.target)) {
                val approval = approvals[side] ?: return null
                if (approval.currentStatus == "VERIFIED") {
                    val expectedLifecycle = LinkReviewPolicyV164OwnerLifecycle(
                        scope.ownerId,
                        scope.ownerKeyId,
                        scope.ownerKeyState ?: return null,
                        scope.ownerKeyVersion ?: return null,
                    )
                    if (approval.ownerLifecycle != expectedLifecycle) return null
                }
            }
            val localApproval = approvals[tuple.localSide] ?: return null
            if (localApproval.currentStatus != "VERIFIED") return null
            val localProof = localApproval.proofBytesCopy() ?: return null
            try {
                if (LinkConsentLedger.digest(localProof) != fence.signedProofSha256) return null
            } finally {
                localProof.fill(0)
            }
            status
        } catch (_: Exception) {
            null
        }
    }

    private fun finishResponse(
        state: State,
        device: ClientWireCrypto.Identity,
        control: ClientWireCrypto.PublicIdentity,
        route: ClientWireCrypto.Route,
        packetResponse: String,
        processMonitorResponse: Boolean = true,
    ): JsonObject {
        val opened = try {
            ClientWireCrypto.openResponse(device, control, route, packetResponse)
        } catch (_: Exception) {
            // Keep the original packet for exact retry if response authentication fails.
            throw HubSessionException("INVALID_ENCRYPTED_RESPONSE", "Hub response failed post-quantum authentication or decryption")
        }
        val pending = state.pending
            ?: throw HubSessionException("PENDING_PACKET_INVALID", "Encrypted response has no original pending request")
        if (pending.operationId != route.operationId || pending.sequence != route.sequence ||
            pending.expectedResponseSequence == null ||
            opened.route.sequence != pending.expectedResponseSequence ||
            opened.route.sequence != state.lastResponseSequence + 1) {
            throw HubSessionException("RESPONSE_SEQUENCE_CONFLICT", "Hub response sequence is not monotonic")
        }
        val body = opened.body
        val requestId = optionalString(body, "request_id")?.takeIf { it.isNotBlank() }
            ?: throw HubSessionException("INVALID_ENCRYPTED_RESPONSE", "Decrypted Hub response omitted request ID")
        val operationId = optionalString(body, "operation_id") ?: ""
        val ok = body.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
            ?: throw HubSessionException("INVALID_ENCRYPTED_RESPONSE", "Decrypted Hub response is missing its result status")
        if (operationId != route.operationId) throw HubSessionException("INVALID_ENCRYPTED_RESPONSE", "Decrypted operation ID does not match the request")

        val uncertain = optionalString(body, "error_code") == "OUTCOME_UNCERTAIN"
        if (uncertain) {
            val recovery = body.get("recovery")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw HubSessionException("INVALID_ENCRYPTED_RESPONSE", "Uncertain response omitted recovery context")
            if (ok || optionalString(recovery, "state") != "UNCERTAIN" ||
                longValue(recovery, "request_sequence") != pending.sequence) {
                throw HubSessionException("INVALID_ENCRYPTED_RESPONSE", "Uncertain response does not match original request")
            }
        }

        var verifiedLinkPolicyGrantStatus: LinkReviewPolicyV164Status? = null
        if (route.operation == "link.review_policy_grant") {
            val fence = state.linkConsentLedger.writeFence
                ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original policy consent packet is not durably fenced")
            if (fence.operation != route.operation || fence.operationId != pending.operationId ||
                fence.requestSequence != pending.sequence ||
                fence.packetSha256 != LinkConsentLedger.digest(pending.packetJson.toByteArray(StandardCharsets.UTF_8))) {
                throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Authenticated policy response differs from the original consent packet")
            }
            if (ok && !uncertain) {
                val result = body.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                val verified = result?.let { verifyHistoricalLinkPolicyGrantResult(state, it, fence) }
                if (verified == null) {
                    // This is an authenticated terminal response, so consume its transport
                    // sequence. Keep the durable business fence until a fresh active status
                    // proves the original proof and tuple; never leave a dead transport pending.
                    state.linkConsentLedger = state.linkConsentLedger.markFenceState(
                        fence.operationId, fence.requestSequence, LinkConsentLedger.FenceState.UNCERTAIN,
                    )
                    state.lastResponseSequence = opened.route.sequence
                    state.pending = null
                    state.recoveryBlocked = false
                    state.sessionError = "LINK_POLICY_RESULT_RECONCILIATION_REQUIRED"
                    state.uncertainNeedsReconciliation = true
                    state.outcomeUncertainOperationId = pending.operationId
                    state.retiredPending = pending
                    writeState(state)
                    return JsonObject().apply {
                        addProperty("requestId", requestId)
                        addProperty("operationId", operationId)
                        addProperty("ok", false)
                        addProperty("errorCode", "LINK_POLICY_RESULT_RECONCILIATION_REQUIRED")
                        addProperty("originalOperationCompleted", true)
                        addProperty("reconciliationRequired", true)
                    }
                }
                verifiedLinkPolicyGrantStatus = verified
            }
        }

        if (route.operation == "link.review_policy_status") {
            val candidateContext = state.linkConsentStatusReadContext
            var legacyStatusScope: Pair<String, Long>? = null
            if (candidateContext != null) {
                if (state.linkReviewStatusReadContext != null) {
                    throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Conflicting Link status contexts are saved")
                }
                validateLinkConsentStatusReadContext(candidateContext, state, pending, route)
            } else {
                val context = state.linkReviewStatusReadContext
                    ?: throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Original Link policy status selection is missing")
                validateLinkReviewStatusContext(context, state, pending, route)
                legacyStatusScope = context.linkId to context.linkVersion
            }
            if (ok && candidateContext == null) {
                val result = body.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                    ?: throw HubSessionException("LINK_REVIEW_STATUS_INVALID", "Encrypted Link status response omitted its result")
                val (linkId, linkVersion) = legacyStatusScope
                    ?: throw HubSessionException("LINK_REVIEW_STATUS_CONTEXT_INVALID", "Original Link policy status selection is missing")
                try {
                    LinkReviewPolicyStatusValidation.validateStatus(
                        sanitizeV164PolicyStatusMetadata(result, linkId, linkVersion), linkId, linkVersion,
                    )
                } catch (error: LinkReviewPolicyStatusValidationException) {
                    val code = if (error.code == "LINK_REVIEW_STATUS_SCOPE_MISMATCH") error.code else "LINK_REVIEW_STATUS_INVALID"
                    throw HubSessionException(code, "Encrypted Link policy status is malformed or differs from the selected Link version")
                }
            }
        }

        if (route.operation == "session.capabilities" && ok) {
            val result = body.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw HubSessionException("INVALID_SESSION_CAPABILITIES", "Encrypted session.capabilities response is malformed")
            val owner = optionalString(result, "owner_id")
            val role = optionalString(result, "role")
            val operations = result.get("available_rpc_operations")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw HubSessionException("INVALID_SESSION_CAPABILITIES", "Encrypted session.capabilities omitted the allowed operation list")
            if (owner != state.enrollment?.ownerId || (role != "manager" && role != "external")) {
                throw HubSessionException("INVALID_SESSION_CAPABILITIES", "Encrypted session capabilities do not match this enrolled owner")
            }
            val revision = optionalString(result, "contract_revision")
            val catalog = optionalString(result, "catalog_sha256")
            if (revision != CONTRACT_REVISION || catalog != CATALOG_SHA256) {
                // The response is authenticated and final. Consume its sequence, but
                // never authorize operations from an unknown contract or catalog.
                state.role = null
                state.sessionCapabilitiesReady = false
                state.validatedContractRevision = null
                state.validatedCatalogSha256 = null
                state.allowedOperations = emptyList()
                state.lastResponseSequence = opened.route.sequence
                state.pending = null
                state.sessionError = "CONTRACT_MISMATCH"
                writeState(state)
                throw HubSessionException("CONTRACT_MISMATCH", "Encrypted Hub contract revision or catalog digest differs from this Client build")
            }
            val allowed = operations.mapNotNull { item ->
                if (item.isJsonPrimitive && item.asJsonPrimitive.isString) item.asString else null
            }.distinct().filter { it in RPC_OPERATIONS }
            if ("session.capabilities" !in allowed) {
                throw HubSessionException("INVALID_SESSION_CAPABILITIES", "Hub did not authorize session.capabilities for this device")
            }
            state.role = role
            state.allowedOperations = allowed
            state.validatedContractRevision = revision
            state.validatedCatalogSha256 = catalog
            state.sessionCapabilitiesReady = true
        } else if (route.operation == "session.capabilities") {
            state.role = null
            state.allowedOperations = emptyList()
            state.validatedContractRevision = null
            state.validatedCatalogSha256 = null
            state.sessionCapabilitiesReady = false
        }
        if (route.operation == "nodes.confirm" && ok) {
            val result = body.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw HubSessionException("NODE_PAIRING_RESULT_INVALID", "Node confirmation omitted public binding evidence")
            val ownerJson = state.ownerApprovalPublicIdentityJson
                ?: throw HubSessionException("OWNER_IDENTITY_REQUIRED", "Node confirmation requires the trusted enrollment Owner identity")
            val owner = ClientWireCrypto.PublicIdentity.parse(parseObject(ownerJson, "Owner identity is invalid"))
            try {
                NodeControlKeyBindingVerifier.verify(result, route.hubId, route.ownerId, route.deviceId, owner.id)
            } catch (_: IllegalArgumentException) {
                throw HubSessionException("NODE_PAIRING_RESULT_INVALID", "Node confirmation public keys or approval scope are invalid")
            }
        }
        if (processMonitorResponse) applyMonitorRpcResult(state, route, pending, body, operationId, ok, uncertain)
        applyRegroupRpcResult(state, pending, body, ok, uncertain)
        if (route.operation in setOf("link.key_grant", "link.review_policy_grant")) {
            val fence = state.linkConsentLedger.writeFence
                ?: throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Original Link consent ciphertext is not durably fenced")
            if (fence.operation != route.operation || fence.operationId != pending.operationId ||
                fence.requestSequence != pending.sequence ||
                fence.packetSha256 != LinkConsentLedger.digest(pending.packetJson.toByteArray(StandardCharsets.UTF_8))) {
                throw HubSessionException("LINK_CONSENT_PACKET_CONTEXT_INVALID", "Authenticated Link response does not match the original consent packet")
            }
            state.linkConsentLedger = if (uncertain) {
                state.linkConsentLedger.markFenceState(fence.operationId, fence.requestSequence, LinkConsentLedger.FenceState.UNCERTAIN)
            } else {
                state.linkConsentLedger.completeOriginal(LinkConsentLedger.VerifiedOriginalCompletion(
                    operationId = pending.operationId,
                    requestSequence = pending.sequence,
                    responseSequence = opened.route.sequence,
                    packetSha256 = fence.packetSha256,
                    signedProofSha256 = fence.signedProofSha256,
                    tupleDigest = fence.tupleDigest,
                ))
            }
            if (!uncertain) clearLinkUncertainLatch(state, pending.operationId)
        }
        if (route.operation == "link.review_policy_status") state.linkReviewStatusReadContext = null
        if (route.operation == "link.review_policy_status") state.linkConsentStatusReadContext = null
        state.lastResponseSequence = opened.route.sequence
        state.pending = null
        state.recoveryBlocked = false
        state.sessionError = if (uncertain) "OUTCOME_UNCERTAIN" else null
        if (uncertain) {
            if (route.operation == "network.key_grant" && state.networkGrantUncertainPending == null) {
                state.networkGrantUncertainPending = pending
            }
            state.outcomeUncertainOperationId = pending.operationId
            state.uncertainNeedsReconciliation = true
            state.retiredPending = pending
        } else if (route.operation == "status.snapshot" && ok) {
            state.uncertainNeedsReconciliation = false
        }
        writeState(state)
        return JsonObject().apply {
            addProperty("requestId", requestId)
            addProperty("operationId", operationId)
            addProperty("ok", ok)
            if (ok && route.operation == "link.review_policy_grant") {
                verifiedLinkPolicyGrantStatus?.let { add("policyStatus", linkPolicyStatusDisplay(it)) }
            } else if (ok && body.has("result")) add("result", body.get("result"))
            if (!ok && body.has("error")) add("error", body.get("error"))
            if (uncertain) {
                addProperty("errorCode", "OUTCOME_UNCERTAIN")
                add("recovery", body.get("recovery"))
            }
        }
    }

    /** Keeps Monitor state coherent when generic exact-packet recovery completes a special route. */
    private fun applyMonitorRpcResult(
        state: State,
        route: ClientWireCrypto.Route,
        pending: Pending,
        body: JsonObject,
        operationId: String,
        ok: Boolean,
        uncertain: Boolean,
    ) {
        if (!route.operation.startsWith("monitor.broadcast_")) return
        val monitorOperationId = pending.monitorOperationId
            ?: if (route.operation == "monitor.broadcast_prepare") route.operationId
            else throw HubSessionException("PENDING_PACKET_INVALID", "Monitor request lost its original operation reference")
        val metadata = state.monitorOperations[monitorOperationId]
            ?: throw HubSessionException("PENDING_PACKET_INVALID", "Monitor request has no durable operation metadata")
        if (route.operation == "monitor.broadcast_prepare" && route.operationId != metadata.operationId) {
            throw HubSessionException("PENDING_PACKET_INVALID", "Monitor Prepare route differs from its durable operation ID")
        }
        if (uncertain) {
            metadata.state = when (route.operation) {
                "monitor.broadcast_prepare" -> "PREPARE_UNCERTAIN"
                "monitor.broadcast_confirm" -> "CONFIRM_UNCERTAIN"
                "monitor.broadcast_recover" -> "RECOVERY_UNCERTAIN"
                else -> metadata.state
            }
            return
        }
        if (!ok) {
            when (route.operation) {
                "monitor.broadcast_prepare" -> metadata.state = "REJECTED"
                "monitor.broadcast_confirm" -> metadata.state = "CONFIRM_REJECTED"
            }
            return
        }
        val result = body.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("INVALID_MONITOR_RESULT", "Authenticated Monitor response omitted its result")
        when (route.operation) {
            "monitor.broadcast_prepare", "monitor.broadcast_recover" -> {
                // A final authenticated response remains final after either signed
                // expiry. Ledger verification checks the full proof at the inferred
                // original Prepare instant and can never authorize confirmation.
                val verified = verifyMonitorPrepareAllowExpired(state, metadata, result)
                updateMonitorPreview(metadata, result, verified)
                metadata.state = monitorResultState(result)
                markMonitorAuthorizationExpired(metadata, verified)
                if (metadata.state in setOf("APPROVED", "DISPATCH_AUTHORIZED") && !metadata.confirmAttempted) {
                    metadata.confirmAttempted = true
                    metadata.confirmStatusReconciled = false
                }
                if (state.outcomeUncertainOperationId == metadata.operationId) {
                    clearMonitorUncertainLatch(state, metadata, persist = false)
                }
                // Reading one named property keeps this helper result anchored to the
                // verified structure and catches accidental contract drift early.
                if (verified.previewId != metadata.previewId) {
                    throw HubSessionException("MONITOR_PREVIEW_MISMATCH", "Verified Monitor preview ID changed")
                }
            }
            "monitor.broadcast_confirm" -> {
                if (metadata.confirmOperationId != route.operationId || metadata.confirmSequence != route.sequence ||
                    !metadata.confirmAttempted) {
                    throw HubSessionException("PENDING_PACKET_INVALID", "Monitor confirmation route differs from its durable seal")
                }
                validateMonitorConfirmResult(metadata, result)
                metadata.state = monitorResultState(result)
                metadata.confirmStatusReconciled = true
            }
            "monitor.broadcast_status" -> {
                validateMonitorStatusResult(metadata, result)
                metadata.state = monitorStatusDisplayState(metadata, result)
                metadata.confirmStatusReconciled = true
                if (state.outcomeUncertainOperationId == metadata.confirmOperationId) {
                    clearMonitorUncertainLatch(state, metadata, persist = false)
                }
            }
        }
    }

    private fun requireReadyForRpc(state: State) {
        if (state.pin == null) throw HubSessionException("HUB_NOT_PINNED", "Pin the Hub through an independent trusted channel first")
        if (state.authFenced) throw HubSessionException("CLIENT_SESSION_AUTH_FENCED", "Hub rejected Client authentication; remote RPC is disabled")
        if (state.enrollment == null) throw HubSessionException("DEVICE_NOT_ENROLLED", "Enroll this device with an owner-signed grant first")
        if (!hasAtomicFile(privateKeyFile)) throw HubSessionException("DEVICE_KEY_MISSING", "Device private key is unavailable")
    }

    private fun requireImplementedOperation(operation: String) {
        if (operation in UNIMPLEMENTED_CONSENT_OPERATIONS) {
            throw HubSessionException("CLIENT_CONSENT_FLOW_UNAVAILABLE", "This Client has not implemented the independent Owner consent and delegation workflow for this operation")
        }
        if (operation !in RPC_OPERATIONS) {
            throw HubSessionException("UNSUPPORTED_RPC_OPERATION", "This Client does not implement this RPC operation")
        }
    }

    private fun validateOperation(state: State, operation: String) {
        requireImplementedOperation(operation)
        if (state.linkConsentLedger.writeFence != null && operation in MUTATING_RPC_OPERATIONS) {
            throw HubSessionException("LINK_CONSENT_RECOVERY_REQUIRED", "Resolve the original Link consent packet before another managed write")
        }
        if (state.uncertainNeedsReconciliation && operation in MUTATING_RPC_OPERATIONS) {
            throw HubSessionException("BUSINESS_RECONCILIATION_REQUIRED", "Read an authenticated Hub status snapshot before another write")
        }
        if (!state.sessionCapabilitiesReady) {
            if (operation != "session.capabilities") {
                throw HubSessionException("SESSION_CAPABILITIES_REQUIRED", "First encrypted RPC must be session.capabilities")
            }
        } else if (operation !in state.allowedOperations) {
            throw HubSessionException("RPC_OPERATION_NOT_AUTHORIZED", "Encrypted session.capabilities did not authorize this operation")
        }
    }

    private fun routeFromPacket(packetJson: String): ClientWireCrypto.Route = try {
        val packet = JsonParser.parseString(packetJson).asJsonObject
        ClientWireCrypto.Route.parse(packet.getAsJsonObject("route"))
    } catch (_: Exception) {
        throw HubSessionException("PENDING_PACKET_INVALID", "Persisted encrypted request cannot be recovered")
    }

    private fun loadControlIdentity(pin: Pin): ClientWireCrypto.PublicIdentity = try {
        ClientWireCrypto.PublicIdentity.parse(JsonParser.parseString(pin.controlPublicIdentityJson).asJsonObject)
    } catch (_: Exception) {
        throw HubSessionException("HUB_PIN_INVALID", "Stored Hub trust pin is invalid")
    }

    /** Confirms the endpoint still presents the independently entered trust pin. */
    private fun verifyLivePinnedIdentity(pin: Pin) {
        val liveJson = httpJson(pin.baseUrl, "/v2/client/identity", "GET", null, MAX_METADATA_BYTES)
        val live = try {
            ClientWireCrypto.HubPin.parse(liveJson.toString())
        } catch (_: Exception) {
            throw HubSessionException("HUB_IDENTITY_MISMATCH", "Hub identity endpoint does not match the supported contract")
        }
        val pinned = try {
            ClientWireCrypto.HubPin(pin.hubId, loadControlIdentity(pin), pin.controlKeyVersion)
        } catch (_: Exception) {
            throw HubSessionException("HUB_PIN_INVALID", "Stored Hub trust pin is invalid")
        }
        if (!live.sameAs(pinned)) {
            throw HubSessionException("HUB_IDENTITY_MISMATCH", "Live Hub identity differs from the independently entered pin")
        }
    }

    private fun sendRpcPacket(state: State, baseUrl: String, packetJson: String): String {
        try {
            return httpJsonRaw(baseUrl, "/v2/client/rpc", packetJson, MAX_RESPONSE_BYTES)
        } catch (error: HubSessionException) {
            if (error.errorCode == "HTTP_403") {
                state.authFenced = true
                state.sessionCapabilitiesReady = false
                state.allowedOperations = emptyList()
                state.role = null
                state.sessionError = "RPC_HTTP_403"
                markLinkFenceFromPending(state, LinkConsentLedger.FenceState.AUTH_REVOKED)
                // Preserve the signed ciphertext for support/audit; do not keep retrying it.
                writeState(state)
            } else if (error.errorCode == "HTTP_409") {
                state.recoveryBlocked = true
                state.sessionError = "RPC_HTTP_409_UNCERTAIN"
                markLinkFenceFromPending(state, LinkConsentLedger.FenceState.UNCERTAIN)
                // A generic conflict does not identify whether the operation ran.
                // Do not retry or retire the original ciphertext without a Hub protocol.
                writeState(state)
            }
            throw error
        }
    }

    private fun markLinkFenceFromPending(state: State, next: LinkConsentLedger.FenceState) {
        val pending = state.pending ?: return
        val fence = state.linkConsentLedger.writeFence ?: return
        if (pending.operation == fence.operation && pending.operationId == fence.operationId &&
            pending.sequence == fence.requestSequence &&
            LinkConsentLedger.digest(pending.packetJson.toByteArray(StandardCharsets.UTF_8)) == fence.packetSha256) {
            state.linkConsentLedger = state.linkConsentLedger.markFenceState(fence.operationId, fence.requestSequence, next)
        }
    }

    private fun loadDeviceIdentity(): ClientWireCrypto.Identity {
        if (!hasAtomicFile(privateKeyFile)) throw HubSessionException("DEVICE_KEY_MISSING", "Generate a device identity before enrollment")
        val wrapped = try {
            privateKeyFile.openRead().use { input -> JsonParser.parseReader(java.io.InputStreamReader(input, StandardCharsets.UTF_8)).asJsonObject }
        } catch (_: Exception) {
            throw HubSessionException("DEVICE_KEY_STORAGE_INVALID", "Wrapped device key storage cannot be read")
        }
        val version = longValue(wrapped, "version")
        if (version != 1L) throw HubSessionException("DEVICE_KEY_STORAGE_INVALID", "Unsupported wrapped device key version")
        val nonce = decodeBase64(requiredString(wrapped, "nonce"))
        val ciphertext = decodeBase64(requiredString(wrapped, "ciphertext"))
        if (nonce.size != 12 || ciphertext.isEmpty()) throw HubSessionException("DEVICE_KEY_STORAGE_INVALID", "Wrapped device key has invalid dimensions")
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateWrappingKey(create = false), GCMParameterSpec(128, nonce))
            cipher.updateAAD(wrappingKeyAad)
            cipher.doFinal(ciphertext)
        } catch (_: Exception) {
            throw HubSessionException("DEVICE_KEY_UNAVAILABLE", "Android Keystore could not unwrap the device identity")
        }
        return try {
            val serialized = String(plaintext, StandardCharsets.UTF_8)
            ClientWireCrypto.Identity.fromPrivateJson(serialized)
        } catch (_: Exception) {
            throw HubSessionException("DEVICE_KEY_STORAGE_INVALID", "Unwrapped device identity is invalid")
        } finally {
            plaintext.fill(0)
        }
    }

    private fun writeWrappedPrivateJson(privateJson: String) {
        val plaintext = privateJson.toByteArray(StandardCharsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey(create = true))
        cipher.updateAAD(wrappingKeyAad)
        val ciphertext = try {
            cipher.doFinal(plaintext)
        } finally {
            plaintext.fill(0)
        }
        val wrapped = JsonObject().apply {
            addProperty("version", 1)
            addProperty("nonce", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            addProperty("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
        }
        val output = privateKeyFile.startWrite()
        try {
            output.write(wrapped.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            privateKeyFile.finishWrite(output)
        } catch (error: Exception) {
            privateKeyFile.failWrite(output)
            throw HubSessionException("DEVICE_KEY_STORAGE_FAILED", "Could not persist wrapped device identity")
        } finally {
            ciphertext.fill(0)
        }
    }

    private fun getOrCreateWrappingKey(create: Boolean): SecretKey {
        try {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val existing = store.getKey(wrappingKeyAlias, null) as? SecretKey
            if (existing != null) return existing
            if (!create) throw HubSessionException("DEVICE_KEY_UNAVAILABLE", "Android Keystore wrapping key is missing")
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                wrappingKeyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .setUserAuthenticationRequired(false)
                .build()
            generator.init(spec)
            return generator.generateKey()
        } catch (error: HubSessionException) {
            throw error
        } catch (_: Exception) {
            throw HubSessionException("KEYSTORE_UNAVAILABLE", "Android Keystore is unavailable")
        }
    }

    private fun deleteDeviceWrappingKey() {
        try {
            privateKeyFile.delete()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (store.containsAlias(wrappingKeyAlias)) store.deleteEntry(wrappingKeyAlias)
        } catch (_: Exception) {
            throw HubSessionException("DEVICE_KEY_RESET_FAILED", "Could not remove the prior local device identity")
        }
    }

    private fun acceptMonitorPreview(
        state: State,
        metadata: MonitorOperation,
        result: JsonObject,
        rpcResponse: JsonObject,
    ): JsonObject {
        val verified = verifyMonitorPrepareAllowExpired(state, metadata, result)
        updateMonitorPreview(metadata, result, verified)
        metadata.state = monitorResultState(result)
        markMonitorAuthorizationExpired(metadata, verified)
        if (metadata.state in setOf("APPROVED", "DISPATCH_AUTHORIZED")) metadata.confirmAttempted = true
        if (state.uncertainNeedsReconciliation && state.outcomeUncertainOperationId == metadata.operationId) {
            clearMonitorUncertainLatch(state, metadata)
        } else {
            writeState(state)
        }
        return monitorPrepareView(metadata, verified, result, rpcResponse)
    }

    private fun recoverMonitorPreviewForConfirm(
        state: State,
        metadata: MonitorOperation,
    ): MonitorBroadcastCrypto.VerifiedPrepare {
        validateOperation(state, "monitor.broadcast_recover")
        val response = createAndSend(state, "monitor.broadcast_recover", JsonObject().apply {
            addProperty("operation_id", metadata.operationId)
        }, monitorOperationId = metadata.operationId)
        if (response.get("ok")?.takeIf { it.isJsonPrimitive }?.asBoolean != true) {
            if (optionalString(response, "errorCode") == "OUTCOME_UNCERTAIN") {
                metadata.state = "RECOVERY_UNCERTAIN"
                writeState(state)
            }
            throw HubSessionException("MONITOR_PREVIEW_REFRESH_FAILED", "Could not refresh the same Monitor preview before confirmation")
        }
        val result = response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("INVALID_MONITOR_RECOVERY", "Hub returned no recovered Monitor preview")
        val verified = verifyMonitorPrepareAllowExpired(state, metadata, result)
        updateMonitorPreview(metadata, result, verified)
        metadata.state = monitorResultState(result)
        markMonitorAuthorizationExpired(metadata, verified)
        if (metadata.state != "PREPARED" || metadata.confirmAttempted || !verified.canConfirm) {
            if (metadata.state == "PREPARED" && !verified.canConfirm) metadata.state = "EXPIRED"
            writeState(state)
            throw HubSessionException("MONITOR_PREVIEW_NOT_CONFIRMABLE", "The recovered Monitor preview is no longer available for confirmation")
        }
        metadata.state = "PREPARED"
        writeState(state)
        return verified
    }

    /**
     * Refreshes the current source authorization after the same-preview recovery
     * and before any body is sealed. These reads use the current in-memory State
     * so their authenticated sequences are not reset by a nested generic rpc().
     */
    private fun preflightMonitorAuthorization(
        state: State,
        metadata: MonitorOperation,
        verified: MonitorBroadcastCrypto.VerifiedPrepare,
    ) {
        try {
            val topology = monitorPreflightRead(state, "topology.snapshot", JsonObject())
            verifyMonitorTopologySource(topology, state.enrollment?.ownerId
                ?: throw IllegalArgumentException("Owner enrollment is missing"), metadata.groupId, verified.source)

            val groupKeyStatus = monitorPreflightRead(state, "group.key_status", JsonObject().apply {
                addProperty("group_id", metadata.groupId)
                addProperty("endpoint_id", metadata.monitorEndpointId)
            })
            verifyCurrentMonitorGroupGrant(state, metadata, verified, groupKeyStatus)
        } catch (error: Exception) {
            if (error is HubSessionException && error.errorCode == "MONITOR_PREVIEW_REFRESH_FAILED") throw error
            throw HubSessionException("MONITOR_PREVIEW_REFRESH_FAILED", "Current Group authorization changed or could not be verified")
        }
    }

    private fun monitorPreflightRead(state: State, operation: String, body: JsonObject): JsonObject {
        if (state.pending != null) throw HubSessionException("PENDING_RECOVERY_REQUIRED", "Recover the original request before Monitor confirmation")
        validateOperation(state, operation)
        val response = createAndSend(state, operation, body)
        if (response.get("ok")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean != true) {
            throw HubSessionException("MONITOR_PREVIEW_REFRESH_FAILED", "Hub could not confirm current Monitor authorization")
        }
        return response.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("MONITOR_PREVIEW_REFRESH_FAILED", "Hub returned no current Monitor authorization")
    }

    /**
     * topology.snapshot versions are management CAS versions, not the separate
     * Group and membership revisions inside the signed Group key manifest.
     */
    private fun verifyMonitorTopologySource(
        snapshot: JsonObject,
        ownerId: String,
        groupId: String,
        source: MonitorBroadcastCrypto.ConsentEndpoint,
    ) {
        require(requiredString(snapshot, "owner_principal_id") == ownerId &&
            longValue(snapshot, "contract_version") == 2L &&
            requiredString(snapshot, "read_consistency") == "best_effort") {
            "Topology snapshot scope is invalid"
        }
        val groups = snapshot.get("groups")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Topology Group list is missing")
        val group = groups.mapNotNull { it.takeIf { item -> item.isJsonObject }?.asJsonObject }
            .filter { optionalString(it, "group_id") == groupId }
            .singleOrNull() ?: throw IllegalArgumentException("Source Group is missing or duplicated")
        require(requiredString(group, "state") == "ACTIVE" && longValue(group, "version") > 0) {
            "Source Group is no longer active"
        }

        val endpoints = snapshot.get("endpoints")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Topology Endpoint list is missing")
        val endpoint = endpoints.mapNotNull { it.takeIf { item -> item.isJsonObject }?.asJsonObject }
            .filter { optionalString(it, "endpoint_id") == source.endpointId }
            .singleOrNull() ?: throw IllegalArgumentException("Source Endpoint is missing or duplicated")
        val endpointGroups = endpoint.get("group_ids")?.takeIf { it.isJsonArray }?.asJsonArray
            ?.mapNotNull { item -> item.takeIf { it.isJsonPrimitive }?.asString }
            ?: throw IllegalArgumentException("Source Endpoint Group list is missing")
        require(requiredString(endpoint, "principal_id") == source.principalId &&
            requiredString(endpoint, "node_id") == source.nodeId &&
            requiredString(endpoint, "binding_id") == source.bindingId &&
            longValue(endpoint, "binding_epoch") == source.bindingEpoch &&
            requiredString(endpoint, "binding_status") == "leased" &&
            groupId in endpointGroups) {
            "Source Endpoint identity or binding changed"
        }

        val memberships = snapshot.get("memberships")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Topology membership list is missing")
        val membership = memberships.mapNotNull { it.takeIf { item -> item.isJsonObject }?.asJsonObject }
            .filter { optionalString(it, "group_id") == groupId &&
                optionalString(it, "principal_id") == source.principalId }
            .singleOrNull() ?: throw IllegalArgumentException("Source membership is missing or duplicated")
        val roles = membership.get("roles")?.takeIf { it.isJsonArray }?.asJsonArray
            ?.mapNotNull { item -> item.takeIf { it.isJsonPrimitive }?.asString }.orEmpty()
        val hasMonitorRole = optionalString(membership, "role") == "monitor" || "monitor" in roles
        require(requiredString(membership, "status") == "active" && hasMonitorRole &&
            membership.get("broadcast_permission_enabled")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true &&
            longValue(membership, "version") > 0) {
            "Source Monitor membership is no longer authorized"
        }
    }

    /** Verifies the latest CURRENT grant independently; Hub status alone is not authority. */
    private fun verifyCurrentMonitorGroupGrant(
        state: State,
        metadata: MonitorOperation,
        verified: MonitorBroadcastCrypto.VerifiedPrepare,
        grant: JsonObject,
    ) {
        require(requiredString(grant, "current_status") == "CURRENT") {
            "Source Monitor Group grant is no longer current"
        }
        val ownerJson = state.ownerApprovalPublicIdentityJson
            ?: throw IllegalArgumentException("Pinned Owner approval key is missing")
        val owner = ClientWireCrypto.PublicIdentity.parse(parseObject(ownerJson, "Saved Owner key is invalid"))
        val manifest = grant.get("manifest")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Current Group grant manifest is missing")
        val currentManifest = GroupKeyManifestVerifier.verifyManifest(
            manifest,
            state.pin?.hubId ?: throw IllegalArgumentException("Pinned Hub identity is missing"),
            state.enrollment?.ownerId ?: throw IllegalArgumentException("Owner enrollment is missing"),
            metadata.groupId,
            metadata.monitorEndpointId,
            owner.id,
            Instant.now(),
        )
        val signedProofText = requiredString(grant, "signed_proof")
        val signedProof = decodeCanonicalBase64(signedProofText)
        require(signedProof.isNotEmpty() && signedProof.size <= 16 * 1024) {
            "Current Owner Group proof exceeds its protocol limit"
        }
        GroupKeyOwnerProof.verify(signedProof, currentManifest, owner, Instant.now())

        val source = verified.source
        val currentPublic = ClientWireCrypto.PublicIdentity.parse(
            currentManifest.getAsJsonObject("candidate_public_identity"),
        )
        require(verified.hubId == state.pin?.hubId && verified.ownerId == state.enrollment?.ownerId &&
            requiredString(currentManifest, "owner_id") == source.ownerId &&
            requiredString(currentManifest, "group_id") == metadata.groupId &&
            longValue(currentManifest, "group_revision") == verified.groupRevision &&
            requiredString(currentManifest, "endpoint_id") == source.endpointId &&
            requiredString(currentManifest, "principal_id") == source.principalId &&
            requiredString(currentManifest, "node_id") == source.nodeId &&
            longValue(currentManifest, "membership_revision") == source.membershipRevision &&
            longValue(currentManifest, "endpoint_join_revision") == source.groupJoinRevision &&
            requiredString(currentManifest, "binding_id") == source.bindingId &&
            longValue(currentManifest, "binding_epoch") == source.bindingEpoch &&
            requiredString(currentManifest, "candidate_key_id") == source.keyId &&
            longValue(currentManifest, "candidate_version") == source.keyVersion &&
            requiredString(currentManifest, "candidate_fingerprint") == source.keyFingerprint &&
            requiredString(currentManifest, "candidate_proof_digest") == source.keyProofDigest &&
            currentPublic.sameAs(verified.monitorPublicIdentity)) {
            "Current Owner grant differs from the reviewed Monitor key and consent revisions"
        }
    }

    private fun verifyMonitorPrepare(
        state: State,
        metadata: MonitorOperation,
        result: JsonObject,
    ): MonitorBroadcastCrypto.VerifiedPrepare {
        val (trusted, owner) = monitorPrepareTrust(state, metadata)
        return verifyMonitorPrepareAt(trusted, owner, result, Instant.now())
    }

    private fun monitorPrepareTrust(
        state: State,
        metadata: MonitorOperation,
    ): Pair<MonitorBroadcastCrypto.TrustedPrepare, ClientWireCrypto.PublicIdentity> {
        val pin = state.pin ?: throw HubSessionException("HUB_NOT_PINNED", "Hub pin is missing")
        val enrollment = state.enrollment ?: throw HubSessionException("DEVICE_NOT_ENROLLED", "Device enrollment is missing")
        val ownerText = state.ownerApprovalPublicIdentityJson
            ?: throw HubSessionException("OWNER_PUBLIC_KEY_REQUIRED", "Enrollment has no trusted owner public key for Monitor consent verification")
        val owner = try {
            ClientWireCrypto.PublicIdentity.parse(parseObject(ownerText, "Invalid owner key"))
        } catch (_: Exception) {
            throw HubSessionException("OWNER_PUBLIC_KEY_REQUIRED", "Enrollment owner public key is invalid")
        }
        val trusted = MonitorBroadcastCrypto.TrustedPrepare(
            pin.hubId,
            enrollment.ownerId,
            metadata.groupId,
            metadata.monitorEndpointId,
            metadata.bodySha256,
        )
        return trusted to owner
    }

    private fun verifyMonitorPrepareAllowExpired(
        state: State,
        metadata: MonitorOperation,
        result: JsonObject,
    ): MonitorBroadcastCrypto.VerifiedPrepare {
        try {
            return verifyMonitorPrepare(state, metadata, result)
        } catch (error: HubSessionException) {
            val (trusted, owner) = try { monitorPrepareTrust(state, metadata) } catch (_: Exception) { throw error }
            // Ledger-only historical verification applies only after current proof
            // expiry. It verifies the exact signed grant, owner proof and snapshot at
            // the inferred original Prepare instant; it never enables confirmation.
            return try {
                MonitorBroadcastCrypto.verifyPrepareForLedger(result, trusted, owner, Instant.now())
            } catch (_: Exception) {
                throw error
            }
        }
    }

    private fun verifyMonitorPrepareAt(
        trusted: MonitorBroadcastCrypto.TrustedPrepare,
        owner: ClientWireCrypto.PublicIdentity,
        result: JsonObject,
        now: Instant,
    ): MonitorBroadcastCrypto.VerifiedPrepare = try {
            MonitorBroadcastCrypto.verifyPrepare(result, trusted, owner, now)
        } catch (error: HubSessionException) {
            throw error
        } catch (_: Exception) {
            throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor preview evidence failed independent verification")
        }

    private fun updateMonitorPreview(
        metadata: MonitorOperation,
        result: JsonObject,
        verified: MonitorBroadcastCrypto.VerifiedPrepare,
    ) {
        val previewId = requiredString(result, "preview_id")
        val broadcastId = requiredString(result, "broadcast_id")
        val group = requiredString(result, "group_id")
        val monitor = requiredString(result, "monitor_endpoint_id")
        val bodyDigest = requiredString(result, "body_sha256")
        val snapshotDigest = requiredString(result, "snapshot_digest")
        val expiresAt = requiredString(result, "expires_at")
        val grantExpiresAt = verified.grantExpiresAt
        val status = monitorResultState(result)
        if (group != metadata.groupId || monitor != metadata.monitorEndpointId || bodyDigest != metadata.bodySha256 ||
            !bodyDigest.matches(Regex("^[0-9a-f]{64}$")) ||
            !snapshotDigest.matches(Regex("^[0-9a-f]{64}$")) ||
            status !in setOf("PREPARED", "APPROVED", "DISPATCH_AUTHORIZED")) {
            throw HubSessionException("MONITOR_PREVIEW_MISMATCH", "Recovered Monitor preview differs from this device's original request")
        }
        try {
            Instant.parse(expiresAt)
        } catch (_: Exception) {
            throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor preview expiry is invalid")
        }
        val preview = result.get("preview")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor preview omitted verified consent evidence")
        val scope = preview.get("consent_scope")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor preview omitted consent scope")
        if (requiredString(scope, "group_id") != metadata.groupId ||
            requiredString(scope, "broadcast_id") != broadcastId) {
            throw HubSessionException("MONITOR_PREVIEW_MISMATCH", "Monitor consent scope differs from its preview")
        }
        val consentDigest = requiredString(preview, "consent_sha256")
        if (!consentDigest.matches(Regex("^[0-9a-f]{64}$"))) {
            throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor consent digest is invalid")
        }
        val source = scope.get("source")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor consent omitted its source Endpoint")
        if (requiredString(source, "endpoint_id") != metadata.monitorEndpointId) {
            throw HubSessionException("MONITOR_PREVIEW_MISMATCH", "Monitor consent source differs from the selected Endpoint")
        }
        val recipients = scope.getAsJsonArray("recipients")
            ?: throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor consent omitted its recipient snapshot")
        if (recipients.size() > 32) throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor recipient snapshot exceeds the protocol limit")
        val recipientIds = recipients.map { item ->
            if (!item.isJsonObject) throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor recipient card is invalid")
            requiredString(item.asJsonObject, "endpoint_id")
        }
        if (recipientIds.distinct().size != recipientIds.size ||
            recipientIds != recipientIds.sorted() || metadata.monitorEndpointId in recipientIds) {
            throw HubSessionException("MONITOR_PREVIEW_INVALID", "Monitor consent recipient ordering or source is invalid")
        }
        if (metadata.previewId != null && metadata.previewId != previewId ||
            metadata.broadcastId != null && metadata.broadcastId != broadcastId ||
            metadata.snapshotDigest != null && metadata.snapshotDigest != snapshotDigest ||
            metadata.consentDigest != null && metadata.consentDigest != consentDigest ||
            metadata.expiresAt != null && metadata.expiresAt != expiresAt ||
            metadata.grantExpiresAt != null && metadata.grantExpiresAt != grantExpiresAt) {
            throw HubSessionException("MONITOR_PREVIEW_CHANGED", "Monitor recovery returned different consent evidence")
        }
        metadata.previewId = previewId
        metadata.broadcastId = broadcastId
        metadata.snapshotDigest = snapshotDigest
        metadata.consentDigest = consentDigest
        metadata.expiresAt = expiresAt
        metadata.grantExpiresAt = grantExpiresAt
        metadata.recipientEndpointIds = recipientIds
        if (status in setOf("APPROVED", "DISPATCH_AUTHORIZED") && !metadata.confirmAttempted) {
            metadata.confirmAttempted = true
            metadata.confirmStatusReconciled = false
        }
    }

    private fun monitorPrepareView(
        metadata: MonitorOperation,
        verified: MonitorBroadcastCrypto.VerifiedPrepare,
        result: JsonObject,
        rpcResponse: JsonObject,
    ): JsonObject {
        if (verified.previewId != metadata.previewId || verified.broadcastId != metadata.broadcastId ||
            verified.groupId != metadata.groupId || verified.monitorEndpointId != metadata.monitorEndpointId ||
            verified.bodySha256 != metadata.bodySha256 || verified.snapshotDigest != metadata.snapshotDigest ||
            verified.consentSha256 != metadata.consentDigest) {
            throw HubSessionException("MONITOR_PREVIEW_MISMATCH", "Verified Monitor evidence differs from the saved operation")
        }
        val preview = result.getAsJsonObject("preview")
        val scope = preview.getAsJsonObject("consent_scope")
        val source = scope.getAsJsonObject("source")
        val recipients = scope.getAsJsonArray("recipients")
        val status = verified.status
        val canConfirm = verified.canConfirm && !metadata.confirmAttempted
        return JsonObject().apply {
            addProperty("operationId", metadata.operationId)
            addProperty("previewId", metadata.previewId)
            addProperty("broadcastId", metadata.broadcastId)
            addProperty("groupId", metadata.groupId)
            addProperty("monitorEndpointId", metadata.monitorEndpointId)
            addProperty("bodySha256", metadata.bodySha256)
            addProperty("snapshotDigest", metadata.snapshotDigest)
            addProperty("expiresAt", metadata.expiresAt)
            addProperty("grantExpiresAt", verified.grantExpiresAt)
            addProperty("validUntil", verified.validUntil.toString())
            addProperty("status", status)
            addProperty("groupRevision", verified.groupRevision)
            addProperty("consentDigest", metadata.consentDigest)
            add("consentScope", scope.deepCopy())
            add("source", monitorConsentEndpointView(source))
            add("recipients", JsonArray().apply {
                recipients.forEach { item -> add(monitorConsentEndpointView(item.asJsonObject)) }
            })
            addProperty("monitorKeyId", verified.monitorKeyId)
            addProperty("monitorBindingId", verified.monitorBindingId)
            addProperty("monitorBindingEpoch", verified.monitorBindingEpoch)
            addProperty("canConfirm", canConfirm)
            addProperty("verified", true)
            optionalString(rpcResponse, "requestId")?.let { addProperty("requestId", it) }
        }
    }

    private fun monitorConsentEndpointView(endpoint: JsonObject): JsonObject = JsonObject().apply {
        addProperty("endpointId", requiredString(endpoint, "endpoint_id"))
        addProperty("principalId", requiredString(endpoint, "principal_id"))
        addProperty("ownerId", requiredString(endpoint, "owner_id"))
        addProperty("nodeId", requiredString(endpoint, "node_id"))
        addProperty("membershipRevision", longValue(endpoint, "membership_revision"))
        addProperty("groupJoinRevision", longValue(endpoint, "group_join_revision"))
        addProperty("bindingId", requiredString(endpoint, "binding_id"))
        addProperty("bindingEpoch", longValue(endpoint, "binding_epoch"))
        addProperty("keyId", requiredString(endpoint, "key_id"))
        addProperty("keyVersion", longValue(endpoint, "key_version"))
        addProperty("keyFingerprint", requiredString(endpoint, "key_fingerprint"))
        addProperty("keyProofDigest", requiredString(endpoint, "key_proof_digest"))
    }

    private fun monitorOperationSummary(operation: MonitorOperation): JsonObject = JsonObject().apply {
        addProperty("operationId", operation.operationId)
        addProperty("groupId", operation.groupId)
        addProperty("monitorEndpointId", operation.monitorEndpointId)
        addProperty("bodySha256", operation.bodySha256)
        addProperty("state", operation.state)
        operation.previewId?.let { addProperty("previewId", it) }
        operation.broadcastId?.let { addProperty("broadcastId", it) }
        operation.snapshotDigest?.let { addProperty("snapshotDigest", it) }
        operation.consentDigest?.let { addProperty("consentDigest", it) }
        operation.expiresAt?.let { addProperty("expiresAt", it) }
        operation.grantExpiresAt?.let { addProperty("grantExpiresAt", it) }
        monitorValidUntil(operation)?.let { addProperty("validUntil", it.toString()) }
        add("recipientEndpointIds", JsonArray().apply { operation.recipientEndpointIds.forEach(::add) })
        addProperty("confirmAttempted", operation.confirmAttempted)
        addProperty("confirmStatusReconciled", operation.confirmStatusReconciled)
        operation.confirmOperationId?.let { addProperty("confirmOperationId", it) }
        operation.confirmSequence?.let { addProperty("confirmSequence", it) }
    }

    private fun monitorResultState(result: JsonObject): String = requiredString(result, "status").also {
        if (it !in setOf("PREPARED", "APPROVED", "DISPATCH_AUTHORIZED")) {
            throw HubSessionException("INVALID_MONITOR_RESULT", "Hub returned an unsupported Monitor status")
        }
    }

    private fun validateMonitorConfirmResult(metadata: MonitorOperation, result: JsonObject) {
        if (requiredString(result, "preview_id") != metadata.previewId ||
            requiredString(result, "broadcast_id") != metadata.broadcastId ||
            requiredString(result, "group_id") != metadata.groupId ||
            requiredString(result, "monitor_endpoint_id") != metadata.monitorEndpointId ||
            requiredString(result, "body_sha256") != metadata.bodySha256 ||
            requiredString(result, "snapshot_digest") != metadata.snapshotDigest ||
            requiredString(result, "expires_at") != metadata.expiresAt ||
            monitorResultState(result) !in setOf("APPROVED", "DISPATCH_AUTHORIZED")) {
            throw HubSessionException("INVALID_MONITOR_CONFIRM", "Monitor confirmation response differs from the sealed preview")
        }
        val expectedDigest = requiredString(result, "sealed_payload_digest")
        val exactSealed = metadata.sealedPayload
            ?: throw HubSessionException("MONITOR_SEAL_MISSING", "Exact sealed Monitor payload is missing from durable state")
        val decoded = try { Base64.decode(exactSealed, Base64.NO_WRAP) } catch (_: Exception) {
            throw HubSessionException("MONITOR_SEAL_MISSING", "Persisted Monitor ciphertext is invalid")
        }
        if (!expectedDigest.matches(Regex("^[0-9a-f]{64}$")) || expectedDigest != sha256Hex(decoded)) {
            throw HubSessionException("INVALID_MONITOR_CONFIRM", "Monitor confirmation ciphertext digest does not match the saved envelope")
        }
    }

    private fun validateMonitorStatusResult(metadata: MonitorOperation, result: JsonObject) {
        val approvalStatus = optionalString(result, "approval_status")
        if (requiredString(result, "preview_id") != metadata.previewId ||
            requiredString(result, "broadcast_id") != metadata.broadcastId ||
            requiredString(result, "group_id") != metadata.groupId ||
            requiredString(result, "expires_at") != metadata.expiresAt ||
            approvalStatus !in setOf("PREPARED", "APPROVED", "DISPATCH_AUTHORIZED")) {
            throw HubSessionException("INVALID_MONITOR_STATUS", "Monitor status differs from the verified preview")
        }
        val recipients = result.getAsJsonArray("recipients")
            ?: throw HubSessionException("INVALID_MONITOR_STATUS", "Monitor status omitted recipient outcomes")
        if (recipients.size() > 32 ||
            approvalStatus == "DISPATCH_AUTHORIZED" && recipients.size() != metadata.recipientEndpointIds.size) {
            throw HubSessionException("INVALID_MONITOR_STATUS", "Monitor status recipient set differs from the consent snapshot")
        }
        val seenOrdinals = mutableSetOf<Int>()
        recipients.forEach { item ->
            if (!item.isJsonObject) throw HubSessionException("INVALID_MONITOR_STATUS", "Monitor recipient outcome is invalid")
            val outcome = item.asJsonObject
            val ordinalValue = longValue(outcome, "ordinal")
            if (ordinalValue !in 0..31) {
                throw HubSessionException("INVALID_MONITOR_STATUS", "Monitor status ordinal is outside the protocol limit")
            }
            val ordinal = ordinalValue.toInt()
            if (ordinal !in metadata.recipientEndpointIds.indices || !seenOrdinals.add(ordinal) ||
                requiredString(outcome, "endpoint_id") != metadata.recipientEndpointIds[ordinal] ||
                requiredString(outcome, "state") !in setOf("PENDING", "FAILED", "UNKNOWN", "ACCEPTED")) {
                throw HubSessionException("INVALID_MONITOR_STATUS", "Monitor status contains an outcome outside the consent snapshot")
            }
        }
        if (approvalStatus == "DISPATCH_AUTHORIZED" && seenOrdinals.size != metadata.recipientEndpointIds.size) {
            throw HubSessionException("INVALID_MONITOR_STATUS", "Dispatch-authorized Monitor status omitted a consent recipient")
        }
    }

    /** Keep local expiry visible when Hub has not seeded a dispatch ledger. */
    private fun monitorStatusDisplayState(metadata: MonitorOperation, result: JsonObject): String {
        val approvalStatus = requiredString(result, "approval_status")
        if (approvalStatus == "PREPARED") {
            if (monitorValidUntil(metadata)?.isAfter(Instant.now()) == false) return "EXPIRED"
        }
        return approvalStatus
    }

    private fun monitorValidUntil(metadata: MonitorOperation): Instant? {
        val previewExpiry = try {
            metadata.expiresAt?.let { GroupKeyManifestVerifier.parseCanonicalUtc(it) }
        } catch (_: Exception) { null }
        val grantExpiry = try {
            metadata.grantExpiresAt?.let { GroupKeyManifestVerifier.parseCanonicalUtc(it) }
        } catch (_: Exception) { null }
        return when {
            previewExpiry != null && grantExpiry != null -> minOf(previewExpiry, grantExpiry)
            previewExpiry != null -> previewExpiry
            else -> grantExpiry
        }
    }

    private fun markMonitorAuthorizationExpired(
        metadata: MonitorOperation,
        verified: MonitorBroadcastCrypto.VerifiedPrepare,
    ) {
        if (metadata.state == "PREPARED" && !verified.validUntil.isAfter(Instant.now())) {
            metadata.state = "EXPIRED"
        }
    }

    private fun validateMonitorSelector(value: String, name: String): String {
        val normalized = value.trim()
        if (normalized.isEmpty() || normalized.length > 256) {
            throw HubSessionException("INVALID_MONITOR_SELECTOR", "$name is invalid")
        }
        return normalized
    }

    private fun monitorBodyDigest(body: String): String {
        val bytes = try { strictUtf8(body) } catch (_: Exception) {
            throw HubSessionException("INVALID_MONITOR_BODY", "Message text contains invalid Unicode")
        }
        if (bytes.size > MAX_MONITOR_BODY_BYTES) {
            throw HubSessionException("MONITOR_BODY_TOO_LARGE", "Monitor message exceeds the 16 KiB UTF-8 limit")
        }
        return sha256Hex(bytes)
    }

    private fun strictUtf8(value: String): ByteArray {
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        val encoded = encoder.encode(java.nio.CharBuffer.wrap(value))
        return ByteArray(encoded.remaining()).apply { encoded.get(this) }
    }

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun constantTimeHexEquals(left: String, right: String?): Boolean {
        if (right == null || !left.matches(Regex("^[0-9a-f]{64}$")) || !right.matches(Regex("^[0-9a-f]{64}$"))) return false
        return MessageDigest.isEqual(left.toByteArray(StandardCharsets.US_ASCII), right.toByteArray(StandardCharsets.US_ASCII))
    }

    private fun clearMonitorUncertainLatch(state: State, metadata: MonitorOperation, persist: Boolean = true) {
        val uncertainOperationId = state.outcomeUncertainOperationId
        if (uncertainOperationId != null && (uncertainOperationId == metadata.operationId ||
                uncertainOperationId == metadata.confirmOperationId)) {
            state.outcomeUncertainOperationId = null
            state.uncertainNeedsReconciliation = false
            state.sessionError = null
        }
        if (persist) writeState(state)
    }

    /** Clears only the business uncertainty created by this exact Link operation. */
    private fun clearLinkUncertainLatch(state: State, operationId: String) {
        if (state.outcomeUncertainOperationId == operationId) {
            state.outcomeUncertainOperationId = null
            state.uncertainNeedsReconciliation = false
            state.sessionError = null
        }
    }

    private fun pruneMonitorOperations(state: State) {
        val now = Instant.now()
        val removable = state.monitorOperations.values.filter { operation ->
            if (operation.state == "REJECTED") return@filter true
            if (operation.state in setOf("PREPARE_PENDING", "PREPARE_UNCERTAIN", "RECOVERY_UNCERTAIN", "CONFIRM_PENDING", "CONFIRM_UNCERTAIN")) {
                return@filter false
            }
            if (operation.confirmAttempted && !operation.confirmStatusReconciled) return@filter false
            val expiry = monitorValidUntil(operation)
            expiry != null && !now.isBefore(expiry)
        }
        removable.forEach { operation ->
            state.monitorOperations.remove(operation.operationId)
            state.retiredMonitorOperationIds.add(operation.operationId)
        }
    }

    private fun hasUnresolvedMonitorOperation(state: State): Boolean = state.monitorOperations.values.any { operation ->
        operation.state in setOf("PREPARE_PENDING", "PREPARE_UNCERTAIN", "RECOVERY_UNCERTAIN", "CONFIRM_PENDING", "CONFIRM_UNCERTAIN") ||
            operation.confirmAttempted && !operation.confirmStatusReconciled
    }

    private fun readState(): State {
        if (!hasAtomicFile(stateFile)) return State()
        val json = try {
            stateFile.openRead().use { input ->
                if (input.channel.size() > MAX_SESSION_STATE_BYTES) throw IllegalArgumentException("oversized state")
                JsonParser.parseReader(java.io.InputStreamReader(input, StandardCharsets.UTF_8)).asJsonObject
            }
        } catch (_: Exception) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Hub session state cannot be read")
        }
        val state = State()
        state.linkConsentLedger = try {
            json.get("linkConsentLedger")?.takeIf { it.isJsonObject }?.let {
                LinkConsentLedger.decode(it.toString().toByteArray(StandardCharsets.UTF_8))
            } ?: LinkConsentLedger.empty()
        } catch (_: Exception) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Link consent reconciliation state is invalid")
        }
        state.activeNetworkId = optionalString(json, "activeNetworkId")
        state.pin = json.getAsJsonObject("pin")?.let { value ->
            Pin(
                requiredString(value, "baseUrl"),
                requiredString(value, "hubId"),
                requiredString(value, "controlPublicIdentityJson"),
                optionalLong(value, "controlKeyVersion") ?: 1L,
            )
        }
        state.enrollment = json.getAsJsonObject("enrollment")?.let { value ->
            Enrollment(
                requiredString(value, "ownerId"),
                requiredString(value, "deviceId"),
                longValue(value, "sessionEpoch"),
                longValue(value, "deviceKeyVersion"),
                requiredString(value, "state"),
            )
        }
        state.ownerApprovalPublicIdentityJson = optionalString(json, "ownerApprovalPublicIdentityJson")
        state.nextSequence = optionalLong(json, "nextSequence") ?: 1L
        state.lastResponseSequence = optionalLong(json, "lastResponseSequence") ?: 0L
        state.role = optionalString(json, "role")
        state.sessionCapabilitiesReady = json.get("sessionCapabilitiesReady")?.takeIf { it.isJsonPrimitive }?.asBoolean ?: false
        state.validatedContractRevision = optionalString(json, "validatedContractRevision")
        state.validatedCatalogSha256 = optionalString(json, "validatedCatalogSha256")
        state.authFenced = json.get("authFenced")?.takeIf { it.isJsonPrimitive }?.asBoolean ?: false
        state.recoveryBlocked = json.get("recoveryBlocked")?.takeIf { it.isJsonPrimitive }?.asBoolean ?: false
        state.sessionError = optionalString(json, "sessionError")
        state.previousDeviceMayRemainOnHub = json.get("previousDeviceMayRemainOnHub")?.takeIf { it.isJsonPrimitive }?.asBoolean ?: false
        state.retiredPending = json.getAsJsonObject("retiredPending")?.let { value ->
            Pending(
                requiredString(value, "operation"),
                requiredString(value, "operationId"),
                longValue(value, "sequence"),
                optionalLong(value, "expectedResponseSequence"),
                requiredString(value, "packetJson"),
                optionalString(value, "monitorOperationId"),
            )
        }
        state.networkGrantUncertainPending = json.get("networkGrantUncertainPending")?.let { element ->
            if (element.isJsonNull) null else {
                try {
                    val value = element.asJsonObject
                    validateNetworkGrantFence(Pending(
                        requiredString(value, "operation"), requiredString(value, "operationId"),
                        longValue(value, "sequence"), optionalLong(value, "expectedResponseSequence"),
                        requiredString(value, "packetJson"), optionalString(value, "monitorOperationId"),
                    ))
                } catch (_: Exception) {
                    throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Network grant reconciliation fence is invalid")
                }
            }
        }
        // Older builds kept only one retired request. Preserve a surviving Network grant even
        // if a generic snapshot already cleared its transient UNCERTAIN flags. No read resets it.
        if (state.networkGrantUncertainPending == null && state.retiredPending?.operation == "network.key_grant") {
            state.networkGrantUncertainPending = validateNetworkGrantFence(state.retiredPending!!)
        }
        json.get("regroupUncertainPending")?.let { element ->
            try {
                require(element.isJsonObject)
                val value = element.asJsonObject
                val pending = Pending(requiredString(value, "operation"), requiredString(value, "operationId"),
                    longValue(value, "sequence"), optionalLong(value, "expectedResponseSequence"),
                    requiredString(value, "packetJson"))
                require(pending.operation in setOf("topology.delegation_issue", "topology.delegation_revoke") &&
                    pending.operationId.isNotBlank() && pending.sequence > 0 &&
                    pending.expectedResponseSequence?.let { it > 0 } == true && pending.packetJson.isNotBlank())
                val context = json.get("regroupWriteContext")?.takeIf { it.isJsonObject }?.asJsonObject
                    ?: throw IllegalArgumentException("Missing delegation context")
                requireExactObjectFields(context, setOf("operation", "proposal_id", "hub_id", "owner_id", "input", "request"),
                    setOf("operation", "proposal_id", "hub_id", "owner_id", "input", "request"))
                require(optionalString(context, "operation") == pending.operation && context.toString().length <= 8192)
                state.regroupUncertainPending = pending
                state.regroupWriteContext = context
            } catch (_: Exception) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved delegation recovery fence is invalid")
            }
        }
        if (state.regroupUncertainPending == null && json.has("regroupWriteContext")) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Delegation context has no original ciphertext")
        }
        state.allowedOperations = json.getAsJsonArray("allowedOperations")?.mapNotNull { element ->
            if (element.isJsonPrimitive && element.asJsonPrimitive.isString) element.asString else null
        }?.distinct()?.filter { it in RPC_OPERATIONS } ?: emptyList()
        state.pending = json.getAsJsonObject("pending")?.let { value ->
            Pending(
                requiredString(value, "operation"),
                requiredString(value, "operationId"),
                longValue(value, "sequence"),
                optionalLong(value, "expectedResponseSequence"),
                requiredString(value, "packetJson"),
                optionalString(value, "monitorOperationId"),
            )
        }
        if (json.has("linkReviewStatusReadContext")) {
            try {
                val value = json.get("linkReviewStatusReadContext")?.takeIf { it.isJsonObject }?.asJsonObject
                    ?: throw IllegalArgumentException("Link status context is not an object")
                requireExactObjectFields(value,
                    setOf("link_id", "link_version", "my_side", "hub_id", "owner_id", "device_id", "session_epoch", "operation_id", "sequence"),
                    setOf("link_id", "link_version", "my_side", "hub_id", "owner_id", "device_id", "session_epoch", "operation_id", "sequence"))
                val context = LinkReviewStatusReadContext(
                    LinkReviewPolicyStatusValidation.validateLinkId(requiredString(value, "link_id")),
                    longValue(value, "link_version"),
                    requiredString(value, "my_side"),
                    requiredString(value, "hub_id"),
                    requiredString(value, "owner_id"),
                    requiredString(value, "device_id"),
                    longValue(value, "session_epoch"),
                    requiredString(value, "operation_id"),
                    longValue(value, "sequence"),
                )
                val pending = state.pending ?: throw IllegalArgumentException("Link status context has no pending packet")
                require(context.hubId.length <= 256 && context.ownerId.length <= 256 && context.deviceId.length <= 256 &&
                    context.operationId.length <= 256)
                LinkReviewPolicyStatusValidation.validateExpectedLinkVersion(context.linkVersion)
                require(context.mySide in setOf("SOURCE", "TARGET") &&
                    context.hubId.isNotBlank() && context.ownerId.isNotBlank() && context.deviceId.isNotBlank() &&
                    context.sessionEpoch > 0L && context.operationId.isNotBlank() && context.sequence > 0L &&
                    pending.operation == "link.review_policy_status" && pending.operationId == context.operationId &&
                    pending.sequence == context.sequence && state.pin?.hubId == context.hubId &&
                    state.enrollment?.ownerId == context.ownerId && state.enrollment?.deviceId == context.deviceId &&
                    state.enrollment?.sessionEpoch == context.sessionEpoch)
                state.linkReviewStatusReadContext = context
            } catch (_: Exception) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Link policy status recovery context is invalid")
            }
        }
        if (json.has("linkConsentStatusReadContext")) {
            try {
                val value = json.get("linkConsentStatusReadContext")?.takeIf { it.isJsonObject }?.asJsonObject
                    ?: throw IllegalArgumentException()
                requireExactObjectFields(value,
                    setOf("link_id", "link_version", "my_side", "hub_id", "owner_id", "device_id", "session_epoch", "operation_id", "sequence", "profile_generation"),
                    setOf("link_id", "link_version", "my_side", "hub_id", "owner_id", "device_id", "session_epoch", "operation_id", "sequence", "profile_generation"))
                val context = LinkConsentStatusReadContext(
                    LinkReviewPolicyStatusValidation.validateLinkId(requiredString(value, "link_id")),
                    longValue(value, "link_version"), requiredString(value, "my_side"),
                    requiredString(value, "hub_id"), requiredString(value, "owner_id"),
                    requiredString(value, "device_id"), longValue(value, "session_epoch"),
                    requiredString(value, "operation_id"), longValue(value, "sequence"),
                    longValue(value, "profile_generation"),
                )
                val pending = state.pending ?: throw IllegalArgumentException()
                require(context.linkVersion > 0 && context.mySide in setOf("SOURCE", "TARGET") &&
                    context.hubId.length <= 256 && context.ownerId.length <= 256 && context.deviceId.length <= 256 &&
                    context.operationId.length <= 256 && context.profileGeneration > 0 &&
                    pending.operation == "link.review_policy_status" && pending.operationId == context.operationId &&
                    pending.sequence == context.sequence && state.pin?.hubId == context.hubId &&
                    state.enrollment?.ownerId == context.ownerId && state.enrollment?.deviceId == context.deviceId &&
                    state.enrollment?.sessionEpoch == context.sessionEpoch)
                state.linkConsentStatusReadContext = context
            } catch (_: Exception) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved candidate Link policy status context is invalid")
            }
        }
        if (state.pending?.operation == "link.review_policy_status" &&
            state.linkReviewStatusReadContext == null && state.linkConsentStatusReadContext == null) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Original Link policy status packet has no saved selection context")
        }
        state.enrollmentAttempt = json.getAsJsonObject("enrollmentAttempt")?.let { value ->
            EnrollmentAttempt(
                requiredString(value, "ownerId"),
                requiredString(value, "deviceId"),
                requiredString(value, "deviceKeyId"),
                requiredString(value, "grantSha256"),
                optionalString(value, "requestJson"),
            )
        }
        state.outcomeUncertainOperationId = optionalString(json, "outcomeUncertainOperationId")
        state.uncertainNeedsReconciliation = json.get("uncertainNeedsReconciliation")
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
            ?: (state.outcomeUncertainOperationId != null)
        json.getAsJsonArray("monitorOperations")?.forEach { item ->
            if (!item.isJsonObject) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Monitor recovery metadata is invalid")
            }
            val value = item.asJsonObject
            val operationId = requiredString(value, "operationId")
            val groupId = requiredString(value, "groupId")
            val monitorEndpointId = requiredString(value, "monitorEndpointId")
            val bodySha256 = requiredString(value, "bodySha256")
            val status = requiredString(value, "state")
            if (operationId.isBlank() || operationId.length > 256 || groupId.isBlank() ||
                monitorEndpointId.isBlank() || !bodySha256.matches(Regex("^[0-9a-f]{64}$")) ||
                status !in MONITOR_OPERATION_STATES || operationId in state.monitorOperations) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Monitor recovery metadata is invalid")
            }
            val recipients = value.getAsJsonArray("recipientEndpointIds")?.map { element ->
                if (!element.isJsonPrimitive || !element.asJsonPrimitive.isString) {
                    throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Monitor recipient snapshot is invalid")
                }
                element.asString
            } ?: emptyList()
            if (recipients.size > 32 || recipients.any { it.isBlank() } || recipients.distinct().size != recipients.size) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Monitor recipient snapshot is invalid")
            }
            state.monitorOperations[operationId] = MonitorOperation(
                operationId = operationId,
                groupId = groupId,
                monitorEndpointId = monitorEndpointId,
                bodySha256 = bodySha256,
                state = status,
                previewId = optionalString(value, "previewId"),
                broadcastId = optionalString(value, "broadcastId"),
                snapshotDigest = optionalString(value, "snapshotDigest"),
                consentDigest = optionalString(value, "consentDigest"),
                expiresAt = optionalString(value, "expiresAt"),
                grantExpiresAt = optionalString(value, "grantExpiresAt"),
                recipientEndpointIds = recipients,
                confirmAttempted = value.get("confirmAttempted")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean ?: false,
                confirmStatusReconciled = value.get("confirmStatusReconciled")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean ?: false,
                confirmOperationId = optionalString(value, "confirmOperationId"),
                confirmSequence = optionalLong(value, "confirmSequence"),
                sealedPayload = optionalString(value, "sealedPayload"),
            )
        }
        json.getAsJsonArray("retiredMonitorOperationIds")?.forEach { item ->
            if (!item.isJsonPrimitive || !item.asJsonPrimitive.isString ||
                item.asString.isBlank() || item.asString.length > 256 || item.asString in state.monitorOperations) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Saved Monitor operation tombstone is invalid")
            }
            state.retiredMonitorOperationIds.add(item.asString)
        }
        if (state.validatedContractRevision != CONTRACT_REVISION || state.validatedCatalogSha256 != CATALOG_SHA256) {
            // An app update must not reuse an authorization from an older catalog.
            state.sessionCapabilitiesReady = false
            state.role = null
            state.allowedOperations = emptyList()
        }
        if (state.nextSequence < 1 || state.lastResponseSequence < 0) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Saved encrypted RPC sequence is invalid")
        }
        return state
    }

    private fun hasAtomicFile(file: AtomicFile): Boolean = file.baseFile.exists() ||
        File(file.baseFile.path + ".bak").exists()

    private fun writeState(state: State) {
        val json = JsonObject()
        state.activeNetworkId?.let { json.addProperty("activeNetworkId", it) }
        state.pin?.let { pin ->
            json.add("pin", JsonObject().apply {
                addProperty("baseUrl", pin.baseUrl)
                addProperty("hubId", pin.hubId)
                addProperty("controlPublicIdentityJson", pin.controlPublicIdentityJson)
                addProperty("controlKeyVersion", pin.controlKeyVersion)
            })
        }
        state.enrollment?.let { enrollment ->
            json.add("enrollment", JsonObject().apply {
                addProperty("ownerId", enrollment.ownerId)
                addProperty("deviceId", enrollment.deviceId)
                addProperty("sessionEpoch", enrollment.sessionEpoch)
                addProperty("deviceKeyVersion", enrollment.deviceKeyVersion)
                addProperty("state", enrollment.state)
            })
        }
        json.addProperty("ownerApprovalPublicIdentityJson", state.ownerApprovalPublicIdentityJson)
        json.addProperty("nextSequence", state.nextSequence)
        json.addProperty("lastResponseSequence", state.lastResponseSequence)
        json.addProperty("role", state.role)
        json.addProperty("sessionCapabilitiesReady", state.sessionCapabilitiesReady)
        json.addProperty("validatedContractRevision", state.validatedContractRevision)
        json.addProperty("validatedCatalogSha256", state.validatedCatalogSha256)
        json.addProperty("authFenced", state.authFenced)
        json.addProperty("recoveryBlocked", state.recoveryBlocked)
        json.addProperty("sessionError", state.sessionError)
        json.addProperty("previousDeviceMayRemainOnHub", state.previousDeviceMayRemainOnHub)
        json.addProperty("outcomeUncertainOperationId", state.outcomeUncertainOperationId)
        json.addProperty("uncertainNeedsReconciliation", state.uncertainNeedsReconciliation)
        json.add("linkConsentLedger", state.linkConsentLedger.toJsonObject())
        state.retiredPending?.let { pending ->
            json.add("retiredPending", JsonObject().apply {
                addProperty("operation", pending.operation)
                addProperty("operationId", pending.operationId)
                addProperty("sequence", pending.sequence)
                pending.expectedResponseSequence?.let { addProperty("expectedResponseSequence", it) }
                addProperty("packetJson", pending.packetJson)
                pending.monitorOperationId?.let { addProperty("monitorOperationId", it) }
            })
        }
        state.networkGrantUncertainPending?.let { pending ->
            json.add("networkGrantUncertainPending", JsonObject().apply {
                addProperty("operation", pending.operation)
                addProperty("operationId", pending.operationId)
                addProperty("sequence", pending.sequence)
                pending.expectedResponseSequence?.let { addProperty("expectedResponseSequence", it) }
                addProperty("packetJson", pending.packetJson)
                pending.monitorOperationId?.let { addProperty("monitorOperationId", it) }
            })
        }
        state.regroupUncertainPending?.let { pending ->
            json.add("regroupUncertainPending", JsonObject().apply {
                addProperty("operation", pending.operation)
                addProperty("operationId", pending.operationId)
                addProperty("sequence", pending.sequence)
                pending.expectedResponseSequence?.let { addProperty("expectedResponseSequence", it) }
                addProperty("packetJson", pending.packetJson)
            })
            json.add("regroupWriteContext", state.regroupWriteContext
                ?: throw HubSessionException("SESSION_STORAGE_INVALID", "Original delegation context is missing"))
        }
        json.add("allowedOperations", JsonArray().apply { state.allowedOperations.forEach(::add) })
        state.pending?.let { pending ->
            json.add("pending", JsonObject().apply {
                addProperty("operation", pending.operation)
                addProperty("operationId", pending.operationId)
                addProperty("sequence", pending.sequence)
                pending.expectedResponseSequence?.let { addProperty("expectedResponseSequence", it) }
                addProperty("packetJson", pending.packetJson)
                pending.monitorOperationId?.let { addProperty("monitorOperationId", it) }
            })
        }
        state.linkReviewStatusReadContext?.let { context ->
            val pending = state.pending
            if (pending == null || pending.operation != "link.review_policy_status" ||
                pending.operationId != context.operationId || pending.sequence != context.sequence) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Link policy status context has no exact original packet")
            }
            LinkReviewPolicyStatusValidation.validateLinkId(context.linkId)
            LinkReviewPolicyStatusValidation.validateExpectedLinkVersion(context.linkVersion)
            if (context.mySide !in setOf("SOURCE", "TARGET")) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Link policy status Owner side is invalid")
            }
            json.add("linkReviewStatusReadContext", JsonObject().apply {
                addProperty("link_id", context.linkId)
                addProperty("link_version", context.linkVersion)
                addProperty("my_side", context.mySide)
                addProperty("hub_id", context.hubId)
                addProperty("owner_id", context.ownerId)
                addProperty("device_id", context.deviceId)
                addProperty("session_epoch", context.sessionEpoch)
                addProperty("operation_id", context.operationId)
                addProperty("sequence", context.sequence)
            })
        }
        state.linkConsentStatusReadContext?.let { context ->
            val pending = state.pending
            if (pending == null || pending.operation != "link.review_policy_status" ||
                pending.operationId != context.operationId || pending.sequence != context.sequence ||
                state.linkReviewStatusReadContext != null) {
                throw HubSessionException("SESSION_STORAGE_INVALID", "Candidate Link status context has no exact original packet")
            }
            json.add("linkConsentStatusReadContext", JsonObject().apply {
                addProperty("link_id", context.linkId); addProperty("link_version", context.linkVersion)
                addProperty("my_side", context.mySide); addProperty("hub_id", context.hubId)
                addProperty("owner_id", context.ownerId); addProperty("device_id", context.deviceId)
                addProperty("session_epoch", context.sessionEpoch); addProperty("operation_id", context.operationId)
                addProperty("sequence", context.sequence); addProperty("profile_generation", context.profileGeneration)
            })
        }
        if (state.pending?.operation == "link.review_policy_status" && state.linkReviewStatusReadContext == null &&
            state.linkConsentStatusReadContext == null) {
            throw HubSessionException("SESSION_STORAGE_INVALID", "Original Link policy status packet has no saved selection context")
        }
        state.enrollmentAttempt?.let { attempt ->
            json.add("enrollmentAttempt", JsonObject().apply {
                addProperty("ownerId", attempt.ownerId)
                addProperty("deviceId", attempt.deviceId)
                addProperty("deviceKeyId", attempt.deviceKeyId)
                addProperty("grantSha256", attempt.grantSha256)
                attempt.requestJson?.let { addProperty("requestJson", it) }
            })
        }
        json.add("retiredMonitorOperationIds", JsonArray().apply {
            state.retiredMonitorOperationIds.forEach(::add)
        })
        json.add("monitorOperations", JsonArray().apply {
            state.monitorOperations.values.forEach { operation ->
                add(JsonObject().apply {
                    addProperty("operationId", operation.operationId)
                    addProperty("groupId", operation.groupId)
                    addProperty("monitorEndpointId", operation.monitorEndpointId)
                    addProperty("bodySha256", operation.bodySha256)
                    addProperty("state", operation.state)
                    operation.previewId?.let { addProperty("previewId", it) }
                    operation.broadcastId?.let { addProperty("broadcastId", it) }
                    operation.snapshotDigest?.let { addProperty("snapshotDigest", it) }
                    operation.consentDigest?.let { addProperty("consentDigest", it) }
                    operation.expiresAt?.let { addProperty("expiresAt", it) }
                    operation.grantExpiresAt?.let { addProperty("grantExpiresAt", it) }
                    add("recipientEndpointIds", JsonArray().apply { operation.recipientEndpointIds.forEach(::add) })
                    addProperty("confirmAttempted", operation.confirmAttempted)
                    addProperty("confirmStatusReconciled", operation.confirmStatusReconciled)
                    operation.confirmOperationId?.let { addProperty("confirmOperationId", it) }
                    operation.confirmSequence?.let { addProperty("confirmSequence", it) }
                    // This is the exact signed ciphertext envelope, never the message body.
                    operation.sealedPayload?.let { addProperty("sealedPayload", it) }
                })
            }
        })
        val encodedState = json.toString().toByteArray(StandardCharsets.UTF_8)
        if (encodedState.size > MAX_SESSION_STATE_BYTES) {
            throw HubSessionException("SESSION_STORAGE_LIMIT", "Saved Hub state exceeds its storage limit")
        }
        val output = stateFile.startWrite()
        try {
            output.write(encodedState)
            output.fd.sync()
            stateFile.finishWrite(output)
        } catch (_: Exception) {
            stateFile.failWrite(output)
            throw HubSessionException("SESSION_STORAGE_FAILED", "Could not persist encrypted RPC state")
        }
    }

    private fun validateBaseUrl(baseUrl: String): String {
        val uri = try { URI(baseUrl.trim()) } catch (_: Exception) {
            throw HubSessionException("INVALID_HUB_URL", "Hub URL is invalid")
        }
        val scheme = uri.scheme?.lowercase() ?: ""
        val host = uri.host?.lowercase() ?: ""
        if (uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null ||
            (uri.rawPath.isNotEmpty() && uri.rawPath != "/") || host.isEmpty()) {
            throw HubSessionException("INVALID_HUB_URL", "Hub URL must contain only a scheme and host")
        }
        if (scheme == "https") {
            if (uri.port != -1 && uri.port !in 1..65535) throw HubSessionException("INVALID_HUB_URL", "Hub HTTPS port is invalid")
        } else if (scheme == "http") {
            if (!isDebugHttpHubAllowed(host, uri.port, BuildConfig.DEBUG, isAndroidEmulator())) {
                throw HubSessionException("INSECURE_HUB_URL", "HTTP is allowed only from a debug emulator to approved local Hub ports")
            }
        } else {
            throw HubSessionException("INSECURE_HUB_URL", "Hub URL must use HTTPS")
        }
        val port = if (uri.port == -1) "" else ":${uri.port}"
        return "$scheme://$host$port"
    }

    private fun isAndroidEmulator(): Boolean {
        val hardware = Build.HARDWARE.lowercase()
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val product = Build.PRODUCT.lowercase()
        return hardware == "ranchu" || hardware == "goldfish" ||
            model.contains("android sdk built for") ||
            (fingerprint.startsWith("generic/") &&
                (model.contains("emulator") || product.startsWith("sdk_gphone")))
    }

    private fun httpJson(
        baseUrl: String,
        path: String,
        method: String,
        body: String?,
        maxBytes: Int,
        expectedStatus: Int = 200,
    ): JsonObject {
        val response = httpRequest(baseUrl, path, method, body, maxBytes, expectedStatus)
        return parseObject(response, "Hub returned malformed JSON")
    }

    private fun httpJsonRaw(baseUrl: String, path: String, packetJson: String, maxBytes: Int): String =
        httpRequest(baseUrl, path, "POST", packetJson, maxBytes, 200)

    private fun httpRequest(
        baseUrl: String,
        path: String,
        method: String,
        body: String?,
        maxBytes: Int,
        expectedStatus: Int,
    ): String {
        val normalizedBaseUrl = validateBaseUrl(baseUrl)
        val url = URL(normalizedBaseUrl + path)
        val connection = (url.openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            requestMethod = method
            instanceFollowRedirects = false
            useCaches = false
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Connection", "close")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        try {
            if (body != null) {
                connection.outputStream.use { output ->
                    output.write(body.toByteArray(StandardCharsets.UTF_8))
                }
            }
            val status = connection.responseCode
            if (status != expectedStatus) {
                if (status == 409 && path == "/v2/client/rpc/recover") {
                    val code = try {
                        connection.errorStream?.use { errorStream ->
                            optionalString(parseObject(String(readBounded(errorStream, 2048), StandardCharsets.UTF_8),
                                "Invalid recovery conflict"), "code")
                        }
                    } catch (_: Exception) { null }
                    if (code in setOf("STILL_PROCESSING", "RECOVERY_UNAVAILABLE", "RECOVERY_REJECTED")) {
                        throw HubSessionException("HTTP_409_$code", "Hub recovery returned $code")
                    }
                }
                throw HubSessionException("HTTP_$status", "Hub request failed with HTTP $status")
            }
            val stream = connection.inputStream
            val bytes = stream.use { readBounded(it, maxBytes) }
            if (bytes.isEmpty()) throw HubSessionException("EMPTY_HUB_RESPONSE", "Hub returned an empty response")
            return String(bytes, StandardCharsets.UTF_8)
        } catch (error: HubSessionException) {
            throw error
        } catch (_: Exception) {
            throw HubSessionException("NETWORK_ERROR", "Hub connection failed; encrypted request state is preserved")
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream, maxBytes: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(maxBytes, 16 * 1024))
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > maxBytes) throw HubSessionException("HUB_RESPONSE_TOO_LARGE", "Hub response exceeds the protocol size limit")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun parseObject(text: String, message: String): JsonObject = try {
        val parsed = JsonParser.parseString(text)
        if (!parsed.isJsonObject) throw IllegalArgumentException("Expected object")
        parsed.asJsonObject
    } catch (_: Exception) {
        throw HubSessionException("INVALID_JSON", message)
    }

    private fun decodeCanonicalBase64(text: String): ByteArray {
        val decoded = decodeBase64(text)
        if (Base64.encodeToString(decoded, Base64.NO_WRAP) != text) {
            throw HubSessionException("INVALID_OWNER_GRANT", "Owner grant must use standard padded base64")
        }
        return decoded
    }

    private fun decodeBase64(text: String): ByteArray = try {
        Base64.decode(text, Base64.DEFAULT)
    } catch (_: Exception) {
        throw HubSessionException("INVALID_BASE64", "A public key or grant contains invalid base64")
    }

    private fun requiredString(value: JsonObject, key: String): String = optionalString(value, key)
        ?: throw HubSessionException("INVALID_JSON", "Hub session data is missing a required field")

    private fun optionalString(value: JsonObject, key: String): String? =
        value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

    private fun longValue(value: JsonObject, key: String): Long = optionalLong(value, key)
        ?: throw HubSessionException("INVALID_JSON", "Hub session data is missing an integer field")

    private fun optionalLong(value: JsonObject, key: String): Long? = try {
        value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asLong
    } catch (_: Exception) { null }
}

class HubSessionException(val errorCode: String, message: String) : RuntimeException(message)
