package ai.cicada.client.hub

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.facebook.react.uimanager.ViewManager
import com.cicadaclient.BuildConfig
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import java.math.BigDecimal
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Narrow React Native bridge. All cryptography and networking stay native. */
class ClientHubNativeModule(context: ReactApplicationContext) : ReactContextBaseJavaModule(context), LifecycleEventListener {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "cicada-client-hub").apply { isDaemon = true }
    }
    private val profiles by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { HubProfileStore(reactApplicationContext) }

    init { context.addLifecycleEventListener(this) }

    override fun onHostResume() = Unit
    override fun onHostPause() = ClientHubSession.clearRegroupReviews()
    override fun onHostDestroy() = ClientHubSession.clearRegroupReviews()

    override fun invalidate() {
        reactApplicationContext.removeLifecycleEventListener(this)
        ClientHubSession.clearRegroupReviews()
        worker.shutdown()
        super.invalidate()
    }

    override fun getName(): String = "CicadaClientHub"

    override fun getConstants(): MutableMap<String, Any> =
        mutableMapOf("linkConsentDiagnosticsEnabled" to BuildConfig.DEBUG)

    @com.facebook.react.bridge.ReactMethod
    fun recordLinkConsentDiagnosticStage(stage: String) {
        LinkConsentDebugObservation.recordUiStage(stage)
    }

    @com.facebook.react.bridge.ReactMethod
    fun listHubProfiles(promise: Promise) = run(promise) { profiles.listHubProfiles() }

    @com.facebook.react.bridge.ReactMethod
    fun createHubProfile(options: ReadableMap, promise: Promise) = run(promise) {
        profiles.createHubProfile(requiredString(options, "label"), requiredScope(options))
    }

    @com.facebook.react.bridge.ReactMethod
    fun activateHubProfile(options: ReadableMap, promise: Promise) = run(promise) {
        profiles.activateHubProfile(requiredString(options, "profileId"), requiredScope(options))
    }

    @com.facebook.react.bridge.ReactMethod
    fun removeHubProfile(options: ReadableMap, promise: Promise) = run(promise) {
        profiles.removeHubProfile(requiredString(options, "profileId"), requiredScope(options))
    }

    @com.facebook.react.bridge.ReactMethod
    fun getStatus(options: ReadableMap, promise: Promise) = run(promise) {
        profiles.getStatus(requiredScope(options))
    }

    @com.facebook.react.bridge.ReactMethod
    fun setActiveNetwork(options: ReadableMap, promise: Promise) = run(promise) {
        profiles.setActiveNetwork(requiredString(options, "networkId"), requiredScope(options))
    }

    @com.facebook.react.bridge.ReactMethod
    fun fetchHubMetadata(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.fetchHubMetadata(requiredString(options, "baseUrl"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun pinHub(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.pinHub(
            requiredString(options, "baseUrl"),
            requiredString(options, "hubId"),
            requiredString(options, "controlPublicIdentityJson"),
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun createDeviceIdentity(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session -> session.createDeviceIdentity() }

    @com.facebook.react.bridge.ReactMethod
    fun startNewDeviceEnrollment(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session -> session.startNewDeviceEnrollment() }

    @com.facebook.react.bridge.ReactMethod
    fun enroll(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.enroll(
            requiredString(options, "ownerId"),
            requiredString(options, "ownerKeyId"),
            requiredString(options, "ownerPublicIdentityJson"),
            requiredString(options, "deviceId"),
            requiredString(options, "ownerDeviceGrantBase64"),
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun recoverEnrollment(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session -> session.recoverEnrollment() }

    @com.facebook.react.bridge.ReactMethod
    fun linkReviewPolicyStatus(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        val expectedLinkVersion = try { options.getDouble("expectedLinkVersion") } catch (_: Exception) { Double.NaN }
        if (!expectedLinkVersion.isFinite() || expectedLinkVersion < 1 ||
            expectedLinkVersion > 9_007_199_254_740_991.0 || expectedLinkVersion % 1 != 0.0) {
            throw HubSessionException("INVALID_LINK_REVIEW_VERSION", "Link review expected version is invalid")
        }
        session.linkReviewPolicyStatus(requiredString(options, "linkId"), expectedLinkVersion.toLong(),
            requiredScope(options).selectionGeneration)
    }

    @com.facebook.react.bridge.ReactMethod
    fun prepareLinkConsent(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        val policy = if (options.hasKey("policy") && !options.isNull("policy")) {
            try { options.getMap("policy")?.let(::readableMapToJson) }
            catch (_: Exception) { throw HubSessionException("INVALID_LINK_CONSENT_POLICY", "Review policy must be a JSON object") }
                ?: throw HubSessionException("INVALID_LINK_CONSENT_POLICY", "Review policy must be a JSON object")
        } else null
        session.prepareLinkConsent(
            linkId = requiredString(options, "linkId"),
            expectedLinkVersion = requiredSafeLong(options, "expectedLinkVersion", minimum = 1L),
            kind = requiredString(options, "kind"),
            policyJson = policy,
            profileGeneration = requiredScope(options).selectionGeneration,
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun confirmLinkOwnerPin(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.confirmLinkOwnerPin(
            ownerId = requiredString(options, "ownerId"),
            publicIdentityJson = requiredString(options, "publicIdentityJson"),
            expectedFingerprint = requiredString(options, "expectedFingerprint"),
            confirmed = options.hasKey("confirmed") && !options.isNull("confirmed") && options.getBoolean("confirmed"),
            profileGeneration = requiredScope(options).selectionGeneration,
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun submitLinkConsent(options: ReadableMap, promise: Promise) {
        LinkConsentDebugObservation.recordNativeBridgeEntered()
        runScoped(options, promise, observeLinkConsentSubmit = true) { session ->
            val reviewId = requiredString(options, "reviewId")
            val consentDigest = requiredString(options, "consentDigest")
            val signedProofBase64 = requiredString(options, "signedProofBase64")
            val confirmed = options.hasKey("confirmed") && !options.isNull("confirmed") && options.getBoolean("confirmed")
            val profileGeneration = requiredScope(options).selectionGeneration
            LinkConsentDebugObservation.recordNativeCallStarted()
            session.submitLinkConsent(
                reviewId = reviewId,
                consentDigest = consentDigest,
                signedProofBase64 = signedProofBase64,
                confirmed = confirmed,
                profileGeneration = profileGeneration,
            )
        }
    }

    @com.facebook.react.bridge.ReactMethod
    fun readLinkKeyGrants(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.readLinkKeyGrants(
            linkId = requiredString(options, "linkId"),
            expectedLinkVersion = requiredSafeLong(options, "expectedLinkVersion", minimum = 1L),
            profileGeneration = requiredScope(options).selectionGeneration,
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun recoverLinkConsent(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.recoverLinkConsent(requiredScope(options).selectionGeneration)
    }

    @com.facebook.react.bridge.ReactMethod
    fun rpc(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        val operation = requiredString(options, "operation")
        val body = options.getMap("body")?.let(::readableMapToJson)
            ?: throw HubSessionException("INVALID_RPC_BODY", "Encrypted RPC body must be a JSON object")
        val operationId = optionalString(options, "operationId")
        session.rpc(operation, body, operationId)
    }

    @com.facebook.react.bridge.ReactMethod
    fun recoverPending(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session -> session.recoverPending() }

    @com.facebook.react.bridge.ReactMethod
    fun retryPendingExact(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session -> session.retryPendingExact() }

    @com.facebook.react.bridge.ReactMethod
    fun previewRegroupDelegation(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.previewRegroupDelegation(requiredString(options, "proposalId"), requiredScope(options).selectionGeneration)
    }

    @com.facebook.react.bridge.ReactMethod
    fun issueRegroupDelegation(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.issueRegroupDelegation(requiredString(options, "reviewId"), requiredString(options, "expiresAt"),
            options.hasKey("confirmed") && !options.isNull("confirmed") && options.getBoolean("confirmed"),
            requiredScope(options).selectionGeneration)
    }

    @com.facebook.react.bridge.ReactMethod
    fun revokeRegroupDelegation(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        val version = options.getDouble("expectedVersion")
        if (!version.isFinite() || version < 1 || version >= 9_007_199_254_740_991.0 || version % 1 != 0.0) {
            throw HubSessionException("INVALID_REGROUP_VERSION", "Delegation CAS version is invalid")
        }
        session.revokeRegroupDelegation(requiredString(options, "reviewId"), requiredString(options, "delegationId"),
            version.toLong(), options.hasKey("confirmed") && !options.isNull("confirmed") && options.getBoolean("confirmed"),
            requiredScope(options).selectionGeneration)
    }

    @com.facebook.react.bridge.ReactMethod
    fun previewGroupKey(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.previewGroupKey(requiredString(options, "groupId"),
            requiredString(options, "endpointId"), requiredString(options, "ownerKeyId"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun grantGroupKey(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.grantGroupKey(requiredString(options, "groupId"),
            requiredString(options, "endpointId"), requiredString(options, "ownerKeyId"),
            requiredString(options, "expectedDigest"), requiredString(options, "signedProofBase64"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun getGroupKeyStatus(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.groupKeyStatus(requiredString(options, "groupId"),
            requiredString(options, "endpointId"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun previewNetworkKey(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.previewNetworkKey(requiredString(options, "networkId"),
            requiredString(options, "endpointId"), requiredString(options, "ownerKeyId"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun previewNetworkKeyGrant(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.previewNetworkKeyGrant(requiredString(options, "networkId"),
            requiredString(options, "endpointId"), requiredString(options, "ownerKeyId"),
            requiredString(options, "expectedDigest"), requiredString(options, "signedProofBase64"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun grantNetworkKey(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.grantNetworkKey(requiredString(options, "networkId"),
            requiredString(options, "endpointId"), requiredString(options, "ownerKeyId"),
            requiredString(options, "expectedDigest"), requiredString(options, "signedProofBase64"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun getNetworkKeyStatus(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.networkKeyStatus(requiredString(options, "networkId"), requiredString(options, "endpointId"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun getMonitorBroadcastOperations(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.monitorBroadcastOperations()
    }

    @com.facebook.react.bridge.ReactMethod
    fun monitorBroadcastBodyMatches(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.monitorBroadcastBodyMatches(
            requiredString(options, "previewId"),
            requiredString(options, "body"),
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun monitorBroadcastPrepare(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.monitorBroadcastPrepare(
            requiredString(options, "groupId"),
            requiredString(options, "monitorEndpointId"),
            requiredString(options, "body"),
            optionalString(options, "operationId"),
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun monitorBroadcastRecover(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.monitorBroadcastRecover(requiredString(options, "operationId"))
    }

    @com.facebook.react.bridge.ReactMethod
    fun monitorBroadcastConfirm(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.monitorBroadcastConfirm(
            requiredString(options, "previewId"),
            requiredString(options, "body"),
            requiredString(options, "consentDigest"),
        )
    }

    @com.facebook.react.bridge.ReactMethod
    fun monitorBroadcastStatus(options: ReadableMap, promise: Promise) = runScoped(options, promise) { session ->
        session.monitorBroadcastStatus(requiredString(options, "previewId"))
    }

    private fun run(promise: Promise, observeLinkConsentSubmit: Boolean = false, action: () -> JsonObject) {
        try {
            worker.execute {
                try {
                    val result = action()
                    val writable = jsonToWritable(result)
                    promise.resolve(writable)
                    if (observeLinkConsentSubmit) LinkConsentDebugObservation.recordNativeResolved(result)
                } catch (error: HubSessionException) {
                    if (observeLinkConsentSubmit) LinkConsentDebugObservation.recordNativeRejected(error.errorCode)
                    promise.reject(error.errorCode, error.message, error)
                } catch (_: Exception) {
                    if (observeLinkConsentSubmit) LinkConsentDebugObservation.recordNativeRejected("CLIENT_HUB_ERROR")
                    promise.reject("CLIENT_HUB_ERROR", "Client Hub operation failed")
                }
            }
        } catch (_: Exception) {
            if (observeLinkConsentSubmit) LinkConsentDebugObservation.recordNativeRejected("CLIENT_HUB_UNAVAILABLE")
            promise.reject("CLIENT_HUB_UNAVAILABLE", "Client Hub worker is unavailable")
        }
    }

    private fun runScoped(
        options: ReadableMap,
        promise: Promise,
        observeLinkConsentSubmit: Boolean = false,
        action: (ClientHubSession) -> JsonObject,
    ) = run(promise, observeLinkConsentSubmit) { profiles.withActiveScope(requiredScope(options), action) }

    private fun requiredScope(options: ReadableMap): HubProfileStore.Scope {
        val scope = try { options.getMap("scope") } catch (_: Exception) { null }
            ?: throw HubSessionException("INVALID_PROFILE_SCOPE", "A captured Hub profile scope is required")
        val generation = try { scope.getDouble("selectionGeneration") } catch (_: Exception) { Double.NaN }
        if (!generation.isFinite() || generation < 1 || generation > 9_007_199_254_740_991.0 || generation % 1 != 0.0) {
            throw HubSessionException("INVALID_PROFILE_SCOPE", "Hub profile selection generation is invalid")
        }
        return HubProfileStore.Scope(requiredString(scope, "profileId"), generation.toLong())
    }

    private fun requiredString(map: ReadableMap, key: String): String = optionalString(map, key)
        ?: throw HubSessionException("INVALID_ARGUMENT", "Missing required argument: $key")

    private fun requiredSafeLong(map: ReadableMap, key: String, minimum: Long): Long {
        val value = try { map.getDouble(key) } catch (_: Exception) { Double.NaN }
        if (!value.isFinite() || value < minimum.toDouble() || value > 9_007_199_254_740_991.0 || value % 1.0 != 0.0) {
            throw HubSessionException("INVALID_ARGUMENT", "Argument $key must be a bounded integer")
        }
        return value.toLong()
    }

    private fun optionalString(map: ReadableMap, key: String): String? = try {
        if (!map.hasKey(key) || map.isNull(key)) null else map.getString(key)
    } catch (_: Exception) {
        throw HubSessionException("INVALID_ARGUMENT", "Argument $key must be a string")
    }

    private fun readableMapToJson(map: ReadableMap): JsonObject {
        val result = JsonObject()
        val keys = map.keySetIterator()
        while (keys.hasNextKey()) {
            val key = keys.nextKey()
            result.add(key, readableValueToJson(map, key))
        }
        return result
    }

    private fun readableArrayToJson(array: ReadableArray): JsonArray {
        val result = JsonArray()
        for (index in 0 until array.size()) {
            result.add(when (array.getType(index)) {
                ReadableType.Null -> JsonNull.INSTANCE
                ReadableType.Boolean -> JsonPrimitive(array.getBoolean(index))
                ReadableType.Number -> numberToJson(array.getDouble(index))
                ReadableType.String -> JsonPrimitive(array.getString(index))
                ReadableType.Map -> array.getMap(index)?.let(::readableMapToJson) ?: JsonNull.INSTANCE
                ReadableType.Array -> array.getArray(index)?.let(::readableArrayToJson) ?: JsonNull.INSTANCE
            })
        }
        return result
    }

    private fun readableValueToJson(map: ReadableMap, key: String): JsonElement = when (map.getType(key)) {
        ReadableType.Null -> JsonNull.INSTANCE
        ReadableType.Boolean -> JsonPrimitive(map.getBoolean(key))
        ReadableType.Number -> numberToJson(map.getDouble(key))
        ReadableType.String -> JsonPrimitive(map.getString(key))
        ReadableType.Map -> map.getMap(key)?.let(::readableMapToJson) ?: JsonNull.INSTANCE
        ReadableType.Array -> map.getArray(key)?.let(::readableArrayToJson) ?: JsonNull.INSTANCE
    }

    private fun numberToJson(number: Double): JsonPrimitive {
        if (!number.isFinite()) throw HubSessionException("INVALID_RPC_BODY", "RPC numbers must be finite")
        if (number == kotlin.math.floor(number) && number >= Long.MIN_VALUE.toDouble() && number < Long.MAX_VALUE.toDouble()) {
            return JsonPrimitive(number.toLong())
        }
        return JsonPrimitive(BigDecimal.valueOf(number))
    }

    private fun jsonToWritable(value: JsonElement): Any? = when {
        value.isJsonNull -> null
        value.isJsonObject -> {
            val result = Arguments.createMap()
            for ((key, child) in value.asJsonObject.entrySet()) put(result, key, child)
            result
        }
        value.isJsonArray -> {
            val result = Arguments.createArray()
            value.asJsonArray.forEach { push(result, it) }
            result
        }
        value.asJsonPrimitive.isBoolean -> value.asBoolean
        value.asJsonPrimitive.isString -> value.asString
        value.asJsonPrimitive.isNumber -> value.asDouble
        else -> null
    }

    private fun put(map: WritableMap, key: String, value: JsonElement) {
        when {
            value.isJsonNull -> map.putNull(key)
            value.isJsonObject -> map.putMap(key, jsonToWritable(value) as WritableMap)
            value.isJsonArray -> map.putArray(key, jsonToWritable(value) as WritableArray)
            value.asJsonPrimitive.isBoolean -> map.putBoolean(key, value.asBoolean)
            value.asJsonPrimitive.isString -> map.putString(key, value.asString)
            value.asJsonPrimitive.isNumber -> map.putDouble(key, value.asDouble)
        }
    }

    private fun push(array: WritableArray, value: JsonElement) {
        when {
            value.isJsonNull -> array.pushNull()
            value.isJsonObject -> array.pushMap(jsonToWritable(value) as WritableMap)
            value.isJsonArray -> array.pushArray(jsonToWritable(value) as WritableArray)
            value.asJsonPrimitive.isBoolean -> array.pushBoolean(value.asBoolean)
            value.asJsonPrimitive.isString -> array.pushString(value.asString)
            value.asJsonPrimitive.isNumber -> array.pushDouble(value.asDouble)
        }
    }
}

class ClientHubNativePackage : ReactPackage {
    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
        listOf(ClientHubNativeModule(reactContext))

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> = emptyList()
}
