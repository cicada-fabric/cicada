package ai.cicada.client.hub

import android.util.AtomicFile
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.util.Base64

/** Bounded fresh-profile v1.6.4 onboarding and encrypted Link consent phases. */
@RunWith(AndroidJUnit4::class)
class LinkConsentInteropTest {
    private val target get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v164-[A-Za-z0-9_-]{1,72}")) }
        ?: error("A bounded v1.6.4 run ID is required")
    private val directory get() = File(File(target.noBackupFilesDir, "link-v164"), runId)
    private fun profileLabel(ownerRole: String) = "Link v1.6.4 $ownerRole $runId"

    private data class Onboarding(
        val baseUrl: String,
        val hubId: String,
        val ownerId: String,
        val ownerKeyId: String,
        val deviceId: String,
        val controlIdentity: ClientWireCrypto.PublicIdentity,
        val ownerIdentity: ClientWireCrypto.PublicIdentity,
    )

    private data class DeviceHandoff(
        val ownerRole: String,
        val profileId: String,
        val profileGeneration: Long,
        val onboarding: Onboarding,
        val deviceIdentityJson: String,
    )

    private data class OwnerPin(
        val ownerId: String,
        val keyId: String,
        val publicIdentityJson: String,
        val fingerprint: String,
        val identity: ClientWireCrypto.PublicIdentity,
    )

    private data class Selection(
        val ownerRole: String,
        val profileId: String,
        val profileGeneration: Long,
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val linkId: String,
        val linkVersion: Long,
        val catalogSha256: String,
        val sourcePin: OwnerPin,
        val targetPin: OwnerPin,
    )

    private data class Review(
        val json: JsonObject,
        val reviewId: String,
        val consentDigest: String,
        val linkId: String,
        val linkVersion: Long,
        val side: String,
        val ownerId: String,
        val ownerKeyId: String,
        val signingRequestJson: String,
        val signingRequest: JsonObject,
        val policyJson: JsonObject?,
    )

    private data class SignedProof(
        val reviewId: String,
        val consentDigest: String,
        val linkId: String,
        val linkVersion: String,
        val side: String,
        val ownerId: String,
        val ownerKeyId: String,
        val encoded: String,
        val proofSha256: String,
    )

    private fun text(value: JsonObject, key: String): String = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Required bounded Link consent field is missing")

    private fun safeInteger(value: JsonObject, key: String): Long {
        val element = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: error("Required bounded Link consent integer is missing")
        val token = element.asString
        require(token.matches(Regex("0|[1-9][0-9]*"))) { "Invalid bounded Link consent integer" }
        return token.toLongOrNull()?.also {
            require(it in 0L..9_007_199_254_740_991L) { "Link consent integer is out of range" }
        } ?: error("Link consent integer is out of range")
    }

    /** Read canonical JSON integer fields whose contract range is the full signed Long range. */
    private fun safeLongNumber(value: JsonObject, key: String, minimum: Long = 0L): Long {
        val element = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: error("Required bounded Link consent integer is missing")
        val token = element.asString
        require(token.matches(Regex("0|[1-9][0-9]*"))) { "Invalid bounded Link consent integer" }
        return token.toLongOrNull()?.also {
            require(it >= minimum) { "Link consent integer is out of range" }
        } ?: error("Link consent integer is out of range")
    }

    private fun hash(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun hash(text: String): String = hash(text.toByteArray(StandardCharsets.UTF_8))

    private fun scope(): HubProfileStore.Scope {
        val selected = profiles.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(selected, "profileId"), safeInteger(selected, "selectionGeneration"))
    }

    private fun requiredDirectory() {
        require(directory.isDirectory || directory.mkdirs()) { "Could not create bounded Link consent directory" }
        require(!Files.isSymbolicLink(directory.toPath()) &&
            !Files.isSymbolicLink(directory.parentFile.toPath())) { "Link consent directory cannot be a symlink" }
    }

    private fun readJson(name: String, maxBytes: Long = 256 * 1024): JsonObject? {
        val file = File(directory, name)
        if (!file.exists()) return null
        require(!Files.isSymbolicLink(file.toPath()) && file.isFile && file.length() in 1..maxBytes) {
            "Bounded Link consent input file is invalid"
        }
        val root = JsonParser.parseString(file.readText(StandardCharsets.UTF_8))
        require(root.isJsonObject) { "Bounded Link consent input must be an object" }
        return root.asJsonObject
    }

    private fun writePrivate(name: String, value: JsonObject) {
        requiredDirectory()
        val file = AtomicFile(File(directory, name))
        val stream = file.startWrite()
        try {
            stream.write(value.toString().toByteArray(StandardCharsets.UTF_8))
            stream.fd.sync()
            file.finishWrite(stream)
        } catch (_: Exception) {
            file.failWrite(stream)
            error("Could not save private Link signer handoff")
        }
        require(file.baseFile.setReadable(false, false) && file.baseFile.setReadable(true, true) &&
            file.baseFile.setWritable(false, false) && file.baseFile.setWritable(true, true)) {
            "Could not restrict private Link signer handoff permissions"
        }
    }

    private fun onboarding(ownerRole: String): Onboarding {
        require(ownerRole in OWNER_ROLES)
        val value = readJson("$ownerRole-setup-public.json")
            ?: notRun("$ownerRole-onboarding", "public v1.6.4 Hub/Owner setup is missing")
        require(value.keySet() == setOf(
            "schema", "run_id", "base_url", "hub_id", "owner_id", "owner_key_id", "device_id",
            "catalog_sha256", "control_public_identity", "owner_public_identity",
        ) && text(value, "schema") == ONBOARDING_SCHEMA && text(value, "run_id") == runId) {
            "Public onboarding fixture does not match this bounded run"
        }
        require(text(value, "catalog_sha256") == CATALOG_SHA256) {
            "Public onboarding fixture is not pinned to the imported v1.6.4 catalog"
        }
        val baseUrl = text(value, "base_url")
        require(baseUrl.length in 8..2048 && baseUrl == baseUrl.trim()) { "Public Hub URL is invalid" }
        val hubId = text(value, "hub_id")
        val ownerId = text(value, "owner_id")
        val ownerKeyId = text(value, "owner_key_id")
        val deviceId = text(value, "device_id")
        listOf(hubId, ownerId, ownerKeyId, deviceId).forEach { item ->
            require(item.isNotBlank() && item.length <= 256 && item == item.trim() &&
                item.none { Character.isISOControl(it) }) { "Public onboarding identity is invalid" }
        }
        val control = ClientWireCrypto.PublicIdentity.parse(value.getAsJsonObject("control_public_identity"))
        val owner = ClientWireCrypto.PublicIdentity.parse(value.getAsJsonObject("owner_public_identity"))
        require(owner.id == ownerKeyId) { "Owner key ID differs from the supplied public Owner identity" }
        return Onboarding(baseUrl, hubId, ownerId, ownerKeyId, deviceId, control, owner)
    }

    private fun deviceHandoff(ownerRole: String): DeviceHandoff {
        require(ownerRole in OWNER_ROLES)
        val value = readJson("$ownerRole-device-public.private.json", 32 * 1024)
            ?: notRun("$ownerRole-onboarding-enroll", "fresh Android device public identity handoff is missing")
        require(value.keySet() == setOf(
            "schema", "run_id", "owner_role", "profile_id", "profile_generation", "hub_id", "owner_id", "owner_key_id",
            "device_id", "catalog_sha256", "device_public_identity", "device_public_identity_sha256",
        ) && text(value, "schema") == DEVICE_HANDOFF_SCHEMA && text(value, "run_id") == runId) {
            "Android device identity handoff does not match this bounded run"
        }
        val fixture = onboarding(ownerRole)
        val profileId = text(value, "profile_id")
        val generation = safeInteger(value, "profile_generation")
        require(profileId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,95}")) && generation > 0L &&
            text(value, "hub_id") == fixture.hubId && text(value, "owner_id") == fixture.ownerId &&
            text(value, "owner_key_id") == fixture.ownerKeyId && text(value, "device_id") == fixture.deviceId &&
            text(value, "catalog_sha256") == CATALOG_SHA256) {
            "Android device identity handoff is outside the supplied v1.6.4 enrollment scope"
        }
        val publicJson = value.getAsJsonObject("device_public_identity").toString()
        val identity = ClientWireCrypto.PublicIdentity.parse(value.getAsJsonObject("device_public_identity"))
        require(text(value, "device_public_identity_sha256") == hash(publicJson)) {
            "Android device public identity digest does not match the host signer input"
        }
        require(text(value, "owner_role") == ownerRole) { "Android device handoff belongs to another Owner side" }
        return DeviceHandoff(ownerRole, profileId, generation, fixture, identity.toJson())
    }

    private fun createOwnerProfileAndExportDeviceIdentity(ownerRole: String) {
        require(ownerRole in OWNER_ROLES)
        val fixture = onboarding(ownerRole)
        val before = scope()
        val label = profileLabel(ownerRole)
        require(!File(directory, "$ownerRole-device-public.private.json").exists()) {
            "A device identity was already exported for this bounded Owner side"
        }
        require(profiles.listHubProfiles().getAsJsonArray("profiles").none {
            it.isJsonObject && it.asJsonObject.get("label")?.asString == label
        }) { "A profile already exists for this bounded Owner side; use a new run ID" }
        val created = profiles.createHubProfile(label, before)
        val profileId = created.getAsJsonArray("profiles").mapNotNull { item ->
            item.takeIf { it.isJsonObject }?.asJsonObject?.takeIf { it.get("label")?.asString == label }
                ?.get("profileId")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        }.singleOrNull() ?: error("Fresh v1.6.4 Hub profile was not created exactly once")
        profiles.activateHubProfile(profileId, scope())
        val activeScope = scope()
        require(activeScope.profileId == profileId) { "Fresh v1.6.4 profile did not become active" }
        profiles.withActiveScope(activeScope) { session ->
            val initial = session.getStatus()
            require(initial.get("pinned")?.asBoolean == false && initial.get("enrolled")?.asBoolean == false) {
                "Fresh v1.6.4 profile unexpectedly contains prior trust or enrollment"
            }
            session.pinHub(fixture.baseUrl, fixture.hubId, fixture.controlIdentity.toJson())
            val identityJson = session.createDeviceIdentity().getAsJsonObject("devicePublicIdentity")
            val identity = ClientWireCrypto.PublicIdentity.parse(identityJson)
            val canonicalPublicJson = identity.toJson()
            val handoff = JsonObject().apply {
                addProperty("schema", DEVICE_HANDOFF_SCHEMA)
                addProperty("run_id", runId)
                addProperty("owner_role", ownerRole)
                addProperty("profile_id", activeScope.profileId)
                addProperty("profile_generation", activeScope.selectionGeneration)
                addProperty("hub_id", fixture.hubId)
                addProperty("owner_id", fixture.ownerId)
                addProperty("owner_key_id", fixture.ownerKeyId)
                addProperty("device_id", fixture.deviceId)
                addProperty("catalog_sha256", CATALOG_SHA256)
                add("device_public_identity", identityJson.deepCopy())
                addProperty("device_public_identity_sha256", hash(canonicalPublicJson))
            }
            writePrivate("$ownerRole-device-public.private.json", handoff)
            writeReceipt("$ownerRole-onboarding-device.redacted.json", "$ownerRole-onboarding-device", "PASS") {
                addProperty("profile_id_sha256", hash(activeScope.profileId))
                addProperty("profile_generation", activeScope.selectionGeneration)
                addProperty("hub_id_sha256", hash(fixture.hubId))
                addProperty("owner_id_sha256", hash(fixture.ownerId))
                addProperty("device_id_sha256", hash(fixture.deviceId))
                addProperty("device_key_id_sha256", hash(identity.id))
                addProperty("device_public_identity_sha256", hash(canonicalPublicJson))
                addProperty("hub_public_identity_pinned", true)
                addProperty("owner_private_material_exported", false)
            }
        }
    }

    private fun enrollOwnerDeviceGrant(ownerRole: String) {
        require(ownerRole in OWNER_ROLES)
        val device = deviceHandoff(ownerRole)
        val grantInput = readJson("$ownerRole-owner-device-grant.private.json", 64 * 1024)
            ?: notRun("$ownerRole-onboarding-enroll", "host-signed public OwnerDeviceGrant handoff is missing")
        require(grantInput.keySet() == OWNER_DEVICE_GRANT_FIELDS &&
            text(grantInput, "schema") == OWNER_DEVICE_GRANT_SCHEMA && text(grantInput, "run_id") == runId) {
            "Host OwnerDeviceGrant handoff has an invalid bounded schema"
        }
        require(text(grantInput, "profile_id") == device.profileId &&
            safeInteger(grantInput, "profile_generation") == device.profileGeneration &&
            text(grantInput, "hub_id") == device.onboarding.hubId &&
            text(grantInput, "owner_id") == device.onboarding.ownerId &&
            text(grantInput, "owner_key_id") == device.onboarding.ownerKeyId &&
            text(grantInput, "device_id") == device.onboarding.deviceId &&
            text(grantInput, "catalog_sha256") == CATALOG_SHA256 &&
            text(grantInput, "device_public_identity_sha256") == hash(device.deviceIdentityJson)) {
            "Host OwnerDeviceGrant handoff is not bound to this fresh Android profile and device key"
        }
        val encodedGrant = text(grantInput, "owner_device_grant_base64")
        val grantBytes = try { Base64.getDecoder().decode(encodedGrant) }
        catch (_: IllegalArgumentException) { error("OwnerDeviceGrant is not canonical base64") }
        require(grantBytes.isNotEmpty() && grantBytes.size <= 32 * 1024 &&
            Base64.getEncoder().encodeToString(grantBytes) == encodedGrant &&
            text(grantInput, "grant_sha256") == hash(grantBytes)) {
            "OwnerDeviceGrant bytes or digest are invalid"
        }
        val selectedScope = requireFreshProfileScope(device.profileId, device.profileGeneration)
        profiles.withActiveScope(selectedScope) { session ->
            val before = session.getStatus()
            require(before.get("pinned")?.asBoolean == true && before.get("enrolled")?.asBoolean == false &&
                before.get("enrollmentRecoveryRequired")?.asBoolean == false &&
                text(before, "hubId") == device.onboarding.hubId) {
                "Fresh Hub-pinned device is not ready for first OwnerDeviceGrant enrollment"
            }
            val enrollment = session.enroll(
                device.onboarding.ownerId, device.onboarding.ownerKeyId,
                device.onboarding.ownerIdentity.toJson(), device.onboarding.deviceId, encodedGrant,
            )
            require(text(enrollment, "ownerId") == device.onboarding.ownerId &&
                text(enrollment, "deviceId") == device.onboarding.deviceId && text(enrollment, "state") == "ACTIVE") {
                "Hub enrollment response does not match the public OwnerDeviceGrant scope"
            }
            val capabilitiesPacket = session.rpc("session.capabilities", JsonObject())
            require(capabilitiesPacket.get("ok")?.asBoolean == true) {
                "Fresh encrypted v1.6.4 session capabilities were refused after enrollment"
            }
            val capabilities = capabilitiesPacket.getAsJsonObject("result")
            require(text(capabilities, "contract_revision") == "client-hub-v1.6.4" &&
                text(capabilities, "catalog_sha256") == CATALOG_SHA256 &&
                text(capabilities, "owner_id") == device.onboarding.ownerId &&
                text(capabilities, "role") in setOf("manager", "external")) {
                "Fresh encrypted enrollment capabilities are outside v1.6.4"
            }
            val operations = capabilities.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
            require(operations.containsAll(REQUIRED_OPERATIONS)) {
                "Fresh encrypted capabilities do not advertise the complete candidate Link consent routes"
            }
            val after = session.getStatus()
            require(after.get("sessionCapabilitiesReady")?.asBoolean == true &&
                text(after, "hubId") == device.onboarding.hubId && text(after, "ownerId") == device.onboarding.ownerId &&
                text(after, "deviceId") == device.onboarding.deviceId &&
                safeInteger(after, "sessionEpoch") == safeInteger(enrollment, "sessionEpoch")) {
                "Local verified session state does not match the newly enrolled v1.6.4 device"
            }
            writeReceipt("$ownerRole-onboarding-enroll.redacted.json", "$ownerRole-onboarding-enroll", "PASS") {
                addProperty("profile_id_sha256", hash(device.profileId))
                addProperty("profile_generation", device.profileGeneration)
                addProperty("hub_id_sha256", hash(device.onboarding.hubId))
                addProperty("owner_id_sha256", hash(device.onboarding.ownerId))
                addProperty("device_id_sha256", hash(device.onboarding.deviceId))
                addProperty("device_key_id_sha256", hash(JsonParser.parseString(device.deviceIdentityJson).asJsonObject.get("id").asString))
                addProperty("grant_sha256", hash(grantBytes))
                addProperty("session_epoch", safeInteger(after, "sessionEpoch"))
                addProperty("contract_revision", text(capabilities, "contract_revision"))
                addProperty("catalog_sha256", text(capabilities, "catalog_sha256"))
                addProperty("owner_private_material_exported", false)
            }
        }
    }

    private fun requireFreshProfileScope(profileId: String, generation: Long): HubProfileStore.Scope {
        val current = scope()
        require(current.profileId == profileId && current.selectionGeneration == generation) {
            "Active Hub profile or selection generation differs from the v1.6.4 device handoff"
        }
        return current
    }

    private fun sideFile(selection: Selection, name: String) = "${selection.ownerRole}-$name"

    private fun writeReceipt(name: String, phase: String, result: String, fields: JsonObject.() -> Unit = {}) {
        requiredDirectory()
        val receipt = JsonObject().apply {
            addProperty("schema", "cicada.client-v164-link-consent-redacted-receipt.v1")
            addProperty("phase", phase)
            addProperty("result", result)
            addProperty("run_id_sha256", hash(runId))
            fields()
        }
        writePrivate(name, receipt)
    }

    private fun notRun(phase: String, reason: String): Nothing {
        writeReceipt("$phase.redacted.json", phase, "NOT_RUN") {
            addProperty("reason", reason)
        }
        assumeTrue("$phase is NOT_RUN: $reason", false)
        error("Unreachable after bounded NOT_RUN assumption")
    }

    private fun parsePin(value: JsonObject): OwnerPin {
        require(value.keySet() == setOf("owner_id", "key_id", "public_identity_json", "fingerprint")) {
            "Owner pin selection fields are invalid"
        }
        val ownerId = text(value, "owner_id")
        val keyId = text(value, "key_id")
        val identityJson = text(value, "public_identity_json")
        val fingerprint = text(value, "fingerprint").removePrefix("sha256:")
        require(ownerId.isNotBlank() && ownerId.length <= 256 && ownerId == ownerId.trim()) {
            "Owner pin selection identity is invalid"
        }
        require(keyId.matches(Regex("pq1-[0-9a-f]{32}")) && fingerprint.matches(Regex("[0-9a-f]{64}"))) {
            "Owner pin selection key identifier or fingerprint is invalid"
        }
        val parsed = JsonParser.parseString(identityJson)
        require(parsed.isJsonObject && parsed.asJsonObject.keySet().toList() ==
            listOf("id", "kem_public", "signing_public") && parsed.asJsonObject.toString() == identityJson) {
            "Owner public identity JSON is not canonical"
        }
        val identity = ClientWireCrypto.PublicIdentity.parse(parsed.asJsonObject)
        require(identity.id == keyId && identity.fingerprint() == fingerprint) {
            "Owner public identity does not match its independent fingerprint"
        }
        return OwnerPin(ownerId, keyId, identityJson, fingerprint, identity)
    }

    private fun selection(): Selection {
        val value = readJson("selection.json") ?: notRun("selection", "public selection fixture is missing")
        val expectedFields = setOf(
            "schema", "run_id", "profile_id", "profile_generation", "hub_id", "owner_id", "device_id", "link_id",
            "expected_link_version", "catalog_sha256", "source_owner_pin", "target_owner_pin",
        )
        require(value.keySet() == expectedFields &&
            text(value, "schema") == SELECTION_SCHEMA &&
            text(value, "run_id") == runId) {
            "Public Link consent selection does not match this bounded run"
        }
        val version = safeInteger(value, "expected_link_version")
        val profileGeneration = safeInteger(value, "profile_generation")
        val profileId = text(value, "profile_id")
        val catalog = text(value, "catalog_sha256")
        require(version in 1L..9_007_199_254_740_991L && profileGeneration > 0L &&
            profileId.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,95}")) && catalog == CATALOG_SHA256) {
            "Public Link consent selection is not pinned to the imported v1.6.4 catalog"
        }
        val sourcePin = parsePin(value.getAsJsonObject("source_owner_pin"))
        val targetPin = parsePin(value.getAsJsonObject("target_owner_pin"))
        require(sourcePin.ownerId != targetPin.ownerId && sourcePin.keyId != targetPin.keyId) {
            "Source and target Owners require distinct full public pins"
        }
        val ownerId = text(value, "owner_id")
        val ownerRole = when (ownerId) {
            sourcePin.ownerId -> "source"
            targetPin.ownerId -> "target"
            else -> error("Selected Hub Owner is not one of the independently pinned Link Owners")
        }
        require(ownerRole in OWNER_ROLES) {
            "Selected Hub Owner is not one of the independently pinned Link Owners"
        }
        listOf("hub_id", "device_id", "link_id").forEach { field ->
            val item = text(value, field)
            require(item.isNotBlank() && item.length <= 256 && item == item.trim() &&
                item.none { Character.isISOControl(it) || it == '/' || it == '\\' }) {
                "Public Link consent selector is invalid"
            }
        }
        return Selection(
            ownerRole, profileId, profileGeneration,
            text(value, "hub_id"), ownerId, text(value, "device_id"),
            text(value, "link_id"), version, catalog, sourcePin, targetPin,
        )
    }

    private fun activeOwnerSession(
        stage: String,
        allowPending: Boolean = false,
        block: (ClientHubSession, HubProfileStore.Scope, Selection, JsonObject) -> Unit,
    ) {
        val selected = selection()
        val scope = scope()
        require(scope.profileId == selected.profileId && scope.selectionGeneration == selected.profileGeneration) {
            "Public selection does not match the active v1.6.4 Hub profile generation"
        }
        val device = deviceHandoff(selected.ownerRole)
        val localPin = if (selected.ownerRole == "source") selected.sourcePin else selected.targetPin
        require(device.profileId == scope.profileId && device.profileGeneration == scope.selectionGeneration &&
            device.onboarding.hubId == selected.hubId && device.onboarding.ownerId == selected.ownerId &&
            device.onboarding.deviceId == selected.deviceId && localPin.ownerId == selected.ownerId &&
            localPin.keyId == device.onboarding.ownerKeyId &&
            localPin.identity.sameAs(device.onboarding.ownerIdentity)) {
            "Public selection, local enrollment and independently pinned local Owner identity differ"
        }
        val before = profiles.getStatus(scope)
        if (before.get("enrolled")?.asBoolean != true ||
            before.get("sessionCapabilitiesReady")?.asBoolean != true) {
            notRun("${selected.ownerRole}-$stage", "fresh OwnerDeviceGrant enrollment or encrypted capabilities are missing")
        }
        require(text(before, "hubId") == selected.hubId && text(before, "ownerId") == selected.ownerId &&
            text(before, "deviceId") == selected.deviceId && safeInteger(before, "sessionEpoch") > 0) {
            "Selected profile is not the enrolled v1.6.4 Owner session"
        }
        if (!allowPending && before.has("pendingOperationId")) {
            notRun("${selected.ownerRole}-$stage", "the selected profile has an unresolved encrypted request")
        }

        profiles.withActiveScope(scope) { session ->
            val packet = session.rpc("session.capabilities", JsonObject())
            require(packet.get("ok")?.asBoolean == true) { "Fresh encrypted Owner capabilities were refused" }
            val capabilities = packet.getAsJsonObject("result")
            require(text(capabilities, "contract_revision") == "client-hub-v1.6.4" &&
                text(capabilities, "catalog_sha256") == CATALOG_SHA256 &&
                text(capabilities, "owner_id") == selected.ownerId &&
                text(capabilities, "role") in setOf("manager", "external")) {
                "Fresh encrypted capabilities are outside the imported v1.6.4 contract"
            }
            val advertised = capabilities.getAsJsonArray("available_rpc_operations")
                .map { it.asString }.toSet()
            val allowed = session.getStatus().getAsJsonArray("allowedOperations")
                .map { it.asString }.toSet()
            if (!advertised.containsAll(REQUIRED_OPERATIONS) || !allowed.containsAll(REQUIRED_OPERATIONS)) {
                notRun("${selected.ownerRole}-$stage", "fresh encrypted capabilities or local verified gates do not authorize the candidate flow")
            }
            try {
                block(session, scope, selected, capabilities)
            } catch (failure: HubSessionException) {
                if (failure.errorCode == "VERIFIED_LINK_CONSENT_FLOW_NOT_READY") {
                    notRun("${selected.ownerRole}-$stage", "native verified Link consent candidate gate remains closed")
                }
                throw failure
            }
        }
        require(scope() == scope) { "Active Hub profile changed during Link consent phase" }
        val after = profiles.getStatus(scope)
        require(text(after, "hubId") == selected.hubId && text(after, "ownerId") == selected.ownerId &&
            text(after, "deviceId") == selected.deviceId &&
            safeInteger(after, "sessionEpoch") == safeInteger(before, "sessionEpoch")) {
            "Owner session changed during Link consent phase"
        }
    }

    private fun pinBothOwners(session: ClientHubSession, selection: Selection, generation: Long) {
        listOf(selection.sourcePin, selection.targetPin).forEach { pin ->
            val result = session.confirmLinkOwnerPin(
                pin.ownerId, pin.publicIdentityJson, pin.fingerprint, true, generation,
            )
            require(text(result, "ownerId") == pin.ownerId && text(result, "ownerKeyId") == pin.keyId &&
                text(result, "ownerKeyFingerprint") == "sha256:${pin.fingerprint}" &&
                result.get("confirmed")?.asBoolean == true) {
                "Native Owner pin confirmation result does not match the independent public pin"
            }
        }
    }

    private fun review(
        value: JsonObject,
        expected: Selection,
        kind: String,
        policyJson: JsonObject? = null,
    ): Review {
        val commonFields = setOf(
            "reviewId", "consentDigest", "linkId", "linkVersion", "side", "manifestDigest", "contractDigest",
            "sourceEndpointId", "sourceGroupId", "targetEndpointId", "targetGroupId", "direction", "actions",
            "dataScopes", "expiresAt", "sourceKeyFingerprint", "targetKeyFingerprint", "maximumProofExpiresAt",
            "ownerKeyId", "ownerKeyFingerprint", "peerOwnerKeyFingerprint", "qualifications", "signingRequestJson",
        )
        val allowedFields = if (kind == "KEY") commonFields else commonFields + setOf(
            "policyDigest", "policyVersion", "currentPolicyStatus",
        )
        require(value.keySet().containsAll(commonFields) && value.keySet().all { it in allowedFields } &&
            ((kind == "KEY" && value.keySet() == commonFields) ||
                (kind == "REVIEW_POLICY" && value.keySet().containsAll(commonFields + setOf("policyDigest", "policyVersion"))))) {
            "Native Link review result has a missing or unexpected field"
        }
        val reviewId = text(value, "reviewId")
        val digest = text(value, "consentDigest")
        val linkId = text(value, "linkId")
        val version = text(value, "linkVersion")
        val side = text(value, "side")
        val signingText = text(value, "signingRequestJson")
        require(reviewId.isNotBlank() && reviewId.length <= 256 && digest.matches(HEX_64) &&
            linkId == expected.linkId && version == expected.linkVersion.toString() &&
            side == expected.ownerRole.uppercase()) {
            "Native Link review result does not match the selected current scope"
        }
        val signerRoot = JsonParser.parseString(signingText)
        require(signerRoot.isJsonObject) { "Native signing request is invalid" }
        val signer = signerRoot.asJsonObject
        val signerFields = setOf(
            "schema", "kind", "owner_id", "owner_key_id", "owner_key_fingerprint", "link_id", "link_version",
            "contract_digest", "side", "max_expiry", "expires_at",
        ) + if (kind == "KEY") setOf("manifest_digest")
            else setOf("policy_digest", "expected_policy_version", "policy_version")
        require(signer.keySet() == signerFields) { "Native Owner signing request has a missing or unexpected field" }
        require(text(signer, "schema") == SIGNING_SCHEMA && text(signer, "kind") == kind &&
            text(signer, "owner_id") == expected.ownerId && text(signer, "link_id") == expected.linkId &&
            safeLongNumber(signer, "link_version", minimum = 1L).toString() == version && text(signer, "side") == side &&
            text(signer, "contract_digest") == text(value, "contractDigest")) {
            "Native signer request is not bound to the reviewed Link scope"
        }
        val selectedPin = if (side == "SOURCE") expected.sourcePin else expected.targetPin
        require(selectedPin.ownerId == expected.ownerId &&
            text(signer, "owner_key_id") == selectedPin.keyId &&
            text(signer, "owner_key_fingerprint") == selectedPin.fingerprint) {
            "Native signer request does not match the independently confirmed local Owner key"
        }
        require(signer.keySet().none { it.lowercase() in FORBIDDEN_SIGNER_FIELDS }) {
            "Native signer request contains a private credential field"
        }
        if (kind == "KEY") {
            require(text(signer, "manifest_digest") == text(value, "manifestDigest") &&
                !value.has("policyDigest") && !value.has("policyVersion")) {
                "Owner key signer request is not bound to the fresh manifest"
            }
        } else {
            val expectedPolicyVersion = safeLongNumber(signer, "expected_policy_version")
            val policyVersion = safeLongNumber(signer, "policy_version", minimum = 1L)
            require(text(signer, "policy_digest") == text(value, "policyDigest") &&
                policyVersion.toString() == text(value, "policyVersion") && expectedPolicyVersion < Long.MAX_VALUE &&
                policyVersion == expectedPolicyVersion + 1L) {
                "Policy signer request is not bound to the fresh policy preview"
            }
        }
        return Review(
            value.deepCopy(), reviewId, digest, linkId, expected.linkVersion, side,
            text(signer, "owner_id"), text(signer, "owner_key_id"), signingText, signer,
            policyJson?.deepCopy(),
        )
    }

    private fun saveReviewHandoff(name: String, kind: String, review: Review) {
        writePrivate(name, JsonObject().apply {
            addProperty("schema", REVIEW_HANDOFF_SCHEMA)
            addProperty("run_id", runId)
            addProperty("kind", kind)
            addProperty("review_id", review.reviewId)
            addProperty("consent_digest", review.consentDigest)
            addProperty("link_id", review.linkId)
            addProperty("link_version", review.linkVersion.toString())
            addProperty("side", review.side)
            addProperty("owner_id", review.ownerId)
            addProperty("owner_key_id", review.ownerKeyId)
            addProperty("signing_request_json", review.signingRequestJson)
            add("native_review_json", review.json.deepCopy())
            review.policyJson?.let { addProperty("policy_json", it.toString()) }
        })
    }

    private fun readReviewHandoff(name: String, expected: Selection, kind: String): Review? {
        val value = readJson(name, 256 * 1024) ?: return null
        val requiredFields = if (kind == "REVIEW_POLICY") REVIEW_HANDOFF_FIELDS + "policy_json" else REVIEW_HANDOFF_FIELDS
        require(value.keySet() == requiredFields && text(value, "schema") == REVIEW_HANDOFF_SCHEMA &&
            text(value, "run_id") == runId && text(value, "kind") == kind) {
            "Host signer review handoff has an invalid schema"
        }
        val policyJson = value.get("policy_json")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
            ?.asString?.let { raw -> JsonParser.parseString(raw).takeIf { it.isJsonObject }?.asJsonObject }
        require((kind == "KEY" && policyJson == null) || (kind == "REVIEW_POLICY" && policyJson != null)) {
            "Host signer policy handoff is inconsistent with its review kind"
        }
        val nativeReview = value.getAsJsonObject("native_review_json")
        require(text(value, "review_id") == text(nativeReview, "reviewId") &&
            text(value, "consent_digest") == text(nativeReview, "consentDigest")) {
            "Host signer handoff differs from the native review"
        }
        val parsed = review(nativeReview, expected, kind, policyJson)
        require(parsed.reviewId == text(value, "review_id") &&
            parsed.consentDigest == text(value, "consent_digest") &&
            parsed.side == text(value, "side") && parsed.ownerId == text(value, "owner_id") &&
            parsed.ownerKeyId == text(value, "owner_key_id")) {
            "Host signer handoff tuple changed after native review"
        }
        return parsed
    }

    private fun readSignedProof(name: String, review: Review): SignedProof? {
        val value = readJson(name, 64 * 1024) ?: return null
        require(value.keySet() == SIGNED_PROOF_FIELDS && text(value, "schema") == SIGNED_PROOF_SCHEMA &&
            text(value, "run_id") == runId) {
            "Host signed proof handoff has an invalid schema"
        }
        val proof = SignedProof(
            text(value, "review_id"), text(value, "consent_digest"), text(value, "link_id"),
            text(value, "link_version"), text(value, "side"), text(value, "owner_id"),
            text(value, "owner_key_id"), text(value, "signed_proof_base64"), text(value, "proof_sha256"),
        )
        require(proof.reviewId == review.reviewId && proof.consentDigest == review.consentDigest &&
            proof.linkId == review.linkId && proof.linkVersion == review.linkVersion.toString() &&
            proof.side == review.side && proof.ownerId == review.ownerId && proof.ownerKeyId == review.ownerKeyId &&
            proof.proofSha256.matches(HEX_64) && proof.encoded.length in 4..21_848) {
            "Host proof is not bound to the exact saved native review"
        }
        val decoded = try { Base64.getDecoder().decode(proof.encoded) }
        catch (_: IllegalArgumentException) { error("Host proof is not canonical base64") }
        require(decoded.isNotEmpty() && decoded.size <= LinkConsentLedger.MAX_PROOF_BYTES &&
            Base64.getEncoder().encodeToString(decoded) == proof.encoded && hash(decoded) == proof.proofSha256) {
            "Host proof is not the bounded canonical proof recorded by its handoff"
        }
        return proof
    }

    @Test fun exportSourceOwnerDeviceIdentityForHostGrant() =
        createOwnerProfileAndExportDeviceIdentity("source")

    @Test fun enrollSourceOwnerDeviceGrantAndVerifyFreshCapabilities() =
        enrollOwnerDeviceGrant("source")

    @Test fun exportTargetOwnerDeviceIdentityForHostGrant() =
        createOwnerProfileAndExportDeviceIdentity("target")

    @Test fun enrollTargetOwnerDeviceGrantAndVerifyFreshCapabilities() =
        enrollOwnerDeviceGrant("target")

    @Test fun confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval() {
        activeOwnerSession("owner-pins") { session, selectedScope, selected, _ ->
            val before = safeInteger(session.getStatus(), "nextSequence")
            pinBothOwners(session, selected, selectedScope.selectionGeneration)
            val after = session.getStatus()
            assertTrue("Owner pin confirmation must not create an RPC packet", !after.has("pendingOperationId"))
            assertTrue("Owner pin confirmation must not consume an RPC sequence", safeInteger(after, "nextSequence") == before)
            writeReceipt(sideFile(selected, "owner-pins.redacted.json"), "${selected.ownerRole}-owner-pins", "PASS") {
                addProperty("hub_id_sha256", hash(selected.hubId))
                addProperty("owner_id_sha256", hash(selected.ownerId))
                addProperty("device_id_sha256", hash(selected.deviceId))
                addProperty("link_id_sha256", hash(selected.linkId))
                addProperty("link_version", selected.linkVersion)
                addProperty("source_owner_key_id_sha256", hash(selected.sourcePin.keyId))
                addProperty("target_owner_key_id_sha256", hash(selected.targetPin.keyId))
                addProperty("native_confirmed_argument", true)
                addProperty("phone_ui_confirmation_observed", false)
                addProperty("sequence_unchanged", true)
            }
        }
    }

    @Test fun exportsFreshCurrentKeyReviewForExternalSigner() {
        activeOwnerSession("key-review-export") { session, selectedScope, selected, _ ->
            pinBothOwners(session, selected, selectedScope.selectionGeneration)
            val result = session.prepareLinkConsent(
                selected.linkId, selected.linkVersion, "KEY", null, selectedScope.selectionGeneration,
            )
            val parsed = review(result, selected, "KEY")
            saveReviewHandoff(sideFile(selected, "key-review.private.json"), "KEY", parsed)
            writeReceipt(sideFile(selected, "key-review-export.redacted.json"), "${selected.ownerRole}-key-review-export", "PASS") {
                addProperty("link_id_sha256", hash(parsed.linkId))
                addProperty("link_version", parsed.linkVersion)
                addProperty("review_id_sha256", hash(parsed.reviewId))
                addProperty("consent_digest", parsed.consentDigest)
                addProperty("manifest_digest", text(result, "manifestDigest"))
                addProperty("signing_request_sha256", hash(parsed.signingRequestJson))
                addProperty("host_signature_present", false)
            }
        }
    }

    @Test fun submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus() {
        activeOwnerSession("key-proof-submit") { session, selectedScope, selected, _ ->
            val parsed = readReviewHandoff(sideFile(selected, "key-review.private.json"), selected, "KEY")
                ?: notRun("${selected.ownerRole}-key-proof-submit", "fresh native KEY review handoff is missing")
            val proof = readSignedProof(sideFile(selected, "key-proof.private.json"), parsed)
                ?: notRun("${selected.ownerRole}-key-proof-submit", "host-signed OwnerLinkKeyGrant input is missing")
            val sent = session.submitLinkConsent(
                parsed.reviewId, parsed.consentDigest, proof.encoded, true, selectedScope.selectionGeneration,
            )
            require(sent.get("ok")?.asBoolean == true) { "Hub refused the native verified OwnerLinkKeyGrant" }
            val status = session.readLinkKeyGrants(
                selected.linkId, selected.linkVersion, selectedScope.selectionGeneration,
            )
            val source = status.getAsJsonObject("sourceStatus")
            val target = status.getAsJsonObject("targetStatus")
            require(text(source, "currentStatus") in OWNER_STATUS_VALUES &&
                text(target, "currentStatus") in OWNER_STATUS_VALUES) {
                "Fresh OwnerLinkKeyGrant status uses an unknown current-status value"
            }
            val sideStatus = if (parsed.side == "SOURCE") source else target
            val localAccepted = sideStatus.get("accepted")?.asBoolean == true &&
                text(sideStatus, "currentStatus") == "ACCEPTED"
            require(localAccepted) { "Fresh Link key-grant status did not retain the submitted local proof" }
            val bilateral = status.get("bilateralVerified")?.asBoolean == true
            val sourceAccepted = source.get("accepted")?.asBoolean == true && text(source, "currentStatus") == "ACCEPTED"
            val targetAccepted = target.get("accepted")?.asBoolean == true && text(target, "currentStatus") == "ACCEPTED"
            require(!bilateral || sourceAccepted && targetAccepted) {
                "Native bilateral status claimed verification without two current Owner proofs"
            }
            require(sourceAccepted.not() || targetAccepted.not() || bilateral) {
                "Fresh bilateral current Owner proofs were not reported as verified"
            }
            require(status.get("reconciliationRequired")?.asBoolean != true) {
                "Current key-grant read left an unresolved original packet"
            }
            writeReceipt(sideFile(selected, "key-proof-submit.redacted.json"), "${selected.ownerRole}-key-proof-submit", "PASS") {
                addProperty("link_id_sha256", hash(selected.linkId))
                addProperty("link_version", selected.linkVersion)
                addProperty("review_id_sha256", hash(parsed.reviewId))
                addProperty("proof_sha256", proof.proofSha256)
                addProperty("submit_operation_id_sha256", hash(text(sent, "operationId")))
                addProperty("local_status", text(sideStatus, "currentStatus"))
                addProperty("source_status", text(source, "currentStatus"))
                addProperty("target_status", text(target, "currentStatus"))
                addProperty("bilateral_verified", bilateral)
                addProperty("native_confirmed_argument", true)
                addProperty("phone_ui_confirmation_observed", false)
                addProperty("reconciliation_required", false)
            }
        }
    }

    @Test fun exportsReviewPolicyCandidateForExternalSigner() {
        activeOwnerSession("policy-review-export") { session, selectedScope, selected, _ ->
            pinBothOwners(session, selected, selectedScope.selectionGeneration)
            val policyInput = readJson("review-policy.json", 32 * 1024)
                ?: JsonObject().apply {
                    addProperty("schema", POLICY_FIXTURE_SCHEMA)
                    addProperty("run_id", runId)
                    add("policy", nonePolicy())
                }
            require(text(policyInput, "schema") == POLICY_FIXTURE_SCHEMA &&
                text(policyInput, "run_id") == runId && policyInput.keySet() == setOf("schema", "run_id", "policy")) {
                "Review policy fixture does not match this bounded run"
            }
            val policy = policyInput.getAsJsonObject("policy")
            validatePolicy(policy)
            val result = session.prepareLinkConsent(
                selected.linkId, selected.linkVersion, "REVIEW_POLICY", policy, selectedScope.selectionGeneration,
            )
            val parsed = review(result, selected, "REVIEW_POLICY")
            saveReviewHandoff(sideFile(selected, "policy-review.private.json"), "REVIEW_POLICY", parsed.copy(policyJson = policy.deepCopy()))
            val mode = text(policy, "mode")
            val currentHead = result.get("currentPolicyStatus")?.takeIf { it.isJsonObject }?.asJsonObject
            writeReceipt(sideFile(selected, "policy-review-export.redacted.json"), "${selected.ownerRole}-policy-review-export", "PASS") {
                addProperty("link_id_sha256", hash(selected.linkId))
                addProperty("link_version", selected.linkVersion)
                addProperty("review_id_sha256", hash(parsed.reviewId))
                addProperty("consent_digest", parsed.consentDigest)
                addProperty("policy_mode", mode)
                addProperty("policy_digest", text(result, "policyDigest"))
                addProperty("policy_version", text(result, "policyVersion"))
                addProperty("signing_request_sha256", hash(parsed.signingRequestJson))
                addProperty("current_policy_head_present", result.has("currentPolicyStatus"))
                currentHead?.let {
                    addProperty("current_policy_head_sha256", hash(it.toString()))
                    addProperty("current_policy_bilateral_verified", it.get("bilateralVerified")?.asBoolean == true)
                }
                addProperty("host_signature_present", false)
            }
        }
    }

    @Test fun submitsHostSignedPolicyProofAndRevalidatesFreshV164Status() {
        activeOwnerSession("policy-proof-submit") { session, selectedScope, selected, _ ->
            val parsed = readReviewHandoff(sideFile(selected, "policy-review.private.json"), selected, "REVIEW_POLICY")
                ?: notRun("${selected.ownerRole}-policy-proof-submit", "fresh native review-policy handoff is missing")
            val proof = readSignedProof(sideFile(selected, "policy-proof.private.json"), parsed)
                ?: notRun("${selected.ownerRole}-policy-proof-submit", "host-signed OwnerLinkReviewPolicy proof input is missing")
            val policy = parsed.policyJson
                ?: error("Saved policy review handoff does not contain its exact reviewed policy")
            validatePolicy(policy)
            val sent = session.submitLinkConsent(
                parsed.reviewId, parsed.consentDigest, proof.encoded, true, selectedScope.selectionGeneration,
            )
            require(sent.get("ok")?.asBoolean == true) {
                safePolicySubmitFailure(sent)
            }
            val grantStatus = sent.get("policyStatus")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: error("Native submit did not return its sanitized verified policy-grant status")
            validateCandidatePolicyGrantStatus(grantStatus, parsed.signingRequest, selected.ownerRole)

            // A new candidate read re-authenticates and re-verifies the current
            // policy status and preview. A partial SOURCE grant leaves HEAD0 current;
            // the TARGET grant activates the candidate policy HEAD only after both proofs verify.
            val fresh = session.prepareLinkConsent(
                selected.linkId, selected.linkVersion, "REVIEW_POLICY", policy, selectedScope.selectionGeneration,
            )
            val head = fresh.get("currentPolicyStatus")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: error("Fresh v1.6.4 prepare did not return a verified current policy-head receipt")
            validateCurrentPolicyHead(head, parsed.signingRequest, selected.ownerRole)
            val sourceStatus = text(head, "sourceStatus")
            val targetStatus = text(head, "targetStatus")
            writeReceipt(sideFile(selected, "policy-proof-submit.redacted.json"), "${selected.ownerRole}-policy-proof-submit", "PASS") {
                addProperty("link_id_sha256", hash(selected.linkId))
                addProperty("link_version", selected.linkVersion)
                addProperty("review_id_sha256", hash(parsed.reviewId))
                addProperty("proof_sha256", proof.proofSha256)
                addProperty("submit_operation_id_sha256", hash(text(sent, "operationId")))
                addProperty("grant_status_sha256", hash(grantStatus.toString()))
                addProperty("grant_current", grantStatus.get("current")?.asBoolean == true)
                addProperty("grant_source_status", text(grantStatus, "sourceStatus"))
                addProperty("grant_target_status", text(grantStatus, "targetStatus"))
                addProperty("policy_head_sha256", hash(head.toString()))
                addProperty("policy_version", text(head, "policyVersion"))
                addProperty("policy_digest", text(head, "digest"))
                addProperty("source_status", sourceStatus)
                addProperty("target_status", targetStatus)
                addProperty("bilateral_verified", head.get("bilateralVerified")?.asBoolean == true)
                addProperty("phone_ui_confirmation_observed", false)
                addProperty("native_confirmed_argument", true)
            }
        }
    }

    @Test fun rejectsWrongPinAndGenericRpcBypassWithoutConsumingSequence() {
        activeOwnerSession("negative-local-guards") { session, selectedScope, selected, _ ->
            val before = safeInteger(session.getStatus(), "nextSequence")
            val wrong = selected.sourcePin
            val wrongFingerprint = if (wrong.fingerprint.startsWith("0")) "1${wrong.fingerprint.drop(1)}"
                else "0${wrong.fingerprint.drop(1)}"
            try {
                session.confirmLinkOwnerPin(
                    wrong.ownerId, wrong.publicIdentityJson, wrongFingerprint, true, selectedScope.selectionGeneration,
                )
                error("Wrong independent Owner fingerprint was accepted")
            } catch (failure: HubSessionException) {
                assertTrue("Wrong pin refusal code changed", failure.errorCode == "OWNER_PIN_FINGERPRINT_MISMATCH")
            }
            listOf(
                "link.key_manifest" to "VERIFIED_LINK_CONSENT_FLOW_REQUIRED",
                "link.key_grants" to "VERIFIED_LINK_CONSENT_FLOW_REQUIRED",
                "link.key_grant" to "VERIFIED_LINK_CONSENT_FLOW_REQUIRED",
                "link.review_policy_preview" to "VERIFIED_LINK_CONSENT_FLOW_REQUIRED",
                "link.review_policy_grant" to "VERIFIED_LINK_CONSENT_FLOW_REQUIRED",
                "link.review_policy_status" to "VERIFIED_LINK_REVIEW_STATUS_FLOW_REQUIRED",
            ).forEach { (operation, code) ->
                try {
                    session.rpc(operation, JsonObject())
                    error("Generic RPC bypass reached a Link consent route")
                } catch (failure: HubSessionException) {
                    assertTrue("Generic Link RPC refusal code changed", failure.errorCode == code)
                }
            }
            val afterGeneric = session.getStatus()
            assertTrue("Generic Link RPC refusals must not consume a sequence",
                safeInteger(afterGeneric, "nextSequence") == before)
            assertFalse("Generic Link RPC refusals must not create pending work", afterGeneric.has("pendingOperationId"))
            writeReceipt(sideFile(selected, "negative-local-guards.redacted.json"), "${selected.ownerRole}-negative-local-guards", "PASS") {
                addProperty("wrong_pin_refused", true)
                addProperty("generic_rpc_bypass_refused", true)
                addProperty("sequence_unchanged", true)
                addProperty("pending_after_refusals", afterGeneric.has("pendingOperationId"))
            }
        }
    }

    @Test fun exportsFreshKeyReviewForTamperedProofNegativeCase() {
        activeOwnerSession("negative-proof-review-export") { session, selectedScope, selected, _ ->
            pinBothOwners(session, selected, selectedScope.selectionGeneration)
            val result = session.prepareLinkConsent(
                selected.linkId, selected.linkVersion, "KEY", null, selectedScope.selectionGeneration,
            )
            val parsed = review(result, selected, "KEY")
            saveReviewHandoff(sideFile(selected, "negative-key-review.private.json"), "KEY", parsed)
            writeReceipt(sideFile(selected, "negative-proof-review-export.redacted.json"),
                "${selected.ownerRole}-negative-proof-review-export", "PASS") {
                addProperty("link_id_sha256", hash(parsed.linkId))
                addProperty("link_version", parsed.linkVersion)
                addProperty("review_id_sha256", hash(parsed.reviewId))
                addProperty("consent_digest", parsed.consentDigest)
                addProperty("signing_request_sha256", hash(parsed.signingRequestJson))
                addProperty("fresh_review_for_tampered_proof", true)
            }
        }
    }

    @Test fun rejectsTamperedFreshOwnerProofBeforeLinkGrantWrite() {
        activeOwnerSession("negative-proof-submit") { session, selectedScope, selected, _ ->
            val keyReview = readReviewHandoff(sideFile(selected, "negative-key-review.private.json"), selected, "KEY")
                ?: notRun("${selected.ownerRole}-negative-proof-submit", "fresh negative KEY review is missing")
            val keyProof = readSignedProof(sideFile(selected, "negative-key-proof.private.json"), keyReview)
                ?: notRun("${selected.ownerRole}-negative-proof-submit", "host signature over the fresh negative review is missing")
            val bytes = Base64.getDecoder().decode(keyProof.encoded)
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            val tampered = Base64.getEncoder().encodeToString(bytes)
            val beforeSubmit = safeInteger(session.getStatus(), "nextSequence")
            expectCode("LINK_OWNER_PROOF_INVALID") {
                session.submitLinkConsent(
                    keyReview.reviewId, keyReview.consentDigest, tampered, true,
                    selectedScope.selectionGeneration,
                )
            }
            val afterTamper = session.getStatus()
            assertFalse("Tampered Owner proof must not create a pending Link write packet",
                afterTamper.has("pendingOperationId"))
            assertTrue("Tampered Owner proof must not set the uncertain-outcome fence",
                afterTamper.get("uncertainNeedsReconciliation")?.asBoolean != true)
            val recovery = session.recoverLinkConsent(selectedScope.selectionGeneration)
            assertFalse("Tampered Owner proof must not leave a Link consent write fence",
                recovery.get("reconciliationRequired")?.asBoolean == true)
            val readDelta = safeInteger(afterTamper, "nextSequence") - beforeSubmit
            assertTrue("Tampered proof verification must use fresh authority reads within its bound", readDelta in 1L..64L)
            writeReceipt(sideFile(selected, "negative-proof-submit.redacted.json"),
                "${selected.ownerRole}-negative-proof-submit", "PASS") {
                addProperty("review_id_sha256", hash(keyReview.reviewId))
                addProperty("original_proof_sha256", keyProof.proofSha256)
                addProperty("tampered_proof_sha256", hash(bytes))
                addProperty("refusal_code", "LINK_OWNER_PROOF_INVALID")
                addProperty("write_packet_created", false)
                addProperty("response_read_sequence_delta", readDelta)
                addProperty("pending_after_refusal", afterTamper.has("pendingOperationId"))
                addProperty("link_write_sent", false)
            }
        }
    }

    @Test fun recoversOnlyAnExplicitlySelectedOriginalConsentOperation() {
        val selected = selection()
        val scenario = readJson(sideFile(selected, "recovery-scenario.json"), 8 * 1024)
            ?: notRun("${selected.ownerRole}-exact-recovery", "bounded response-loss scenario is not configured")
        require(scenario.keySet() == setOf("schema", "run_id", "expected_operation") &&
            text(scenario, "schema") == RECOVERY_SCHEMA && text(scenario, "run_id") == runId) {
            "Bounded Link recovery scenario is invalid"
        }
        val expectedOperation = text(scenario, "expected_operation")
        require(expectedOperation in setOf("link.key_grant", "link.review_policy_grant")) {
            "Recovery scenario does not name a dedicated consent operation"
        }
        val selectedScope = scope()
        require(selectedScope.profileId == selected.profileId &&
            selectedScope.selectionGeneration == selected.profileGeneration) {
            "Recovery profile does not match the public v1.6.4 selection generation"
        }
        val before = profiles.getStatus(selectedScope)
        require(text(before, "hubId") == selected.hubId && text(before, "ownerId") == selected.ownerId &&
            text(before, "deviceId") == selected.deviceId) {
            "Recovery profile does not match the bounded consent selection"
        }
        if (!before.has("pendingOperationId")) {
            notRun("${selected.ownerRole}-exact-recovery", "no original response-loss packet is pending")
        }
        require(text(before, "pendingOperation") == expectedOperation) {
            "Pending packet is not the operation named by the recovery scenario"
        }
        val originalOperationId = text(before, "pendingOperationId")
        profiles.withActiveScope(selectedScope) { session ->
            val recovery = try {
                session.recoverLinkConsent(selectedScope.selectionGeneration)
            } catch (failure: HubSessionException) {
                writeReceipt(sideFile(selected, "exact-recovery.redacted.json"),
                    "${selected.ownerRole}-exact-recovery", "NOT_RUN") {
                    addProperty("original_operation", expectedOperation)
                    addProperty("original_operation_id_sha256", hash(originalOperationId))
                    addProperty("recovery_error_code", failure.errorCode)
                    addProperty("recovery_packet_resend_by_test", false)
                }
                assumeTrue("Exact recovery is NOT_RUN: recovery did not return an authenticated result", false)
                return@withActiveScope
            }
            val after = session.getStatus()
            val remainsPending = after.has("pendingOperationId")
            if (remainsPending) {
                require(text(after, "pendingOperationId") == originalOperationId &&
                    text(after, "pendingOperation") == expectedOperation) {
                    "Recovery changed the original pending operation"
                }
            }
            recovery?.get("operationId")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString?.let {
                require(it == originalOperationId) { "Recovery receipt does not correlate to the original operation" }
            }
            val reconciliationRequired = recovery?.get("reconciliationRequired")?.asBoolean
                ?: after.get("uncertainNeedsReconciliation")?.asBoolean == true
            val correlatedOperationId = recovery?.get("operationId")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            if (remainsPending || reconciliationRequired || correlatedOperationId != originalOperationId) {
                writeReceipt(sideFile(selected, "exact-recovery.redacted.json"),
                    "${selected.ownerRole}-exact-recovery", "NOT_RUN") {
                    addProperty("original_operation", expectedOperation)
                    addProperty("original_operation_id_sha256", hash(originalOperationId))
                    addProperty("recovery_state", recovery?.get("state")?.asString ?: "UNKNOWN")
                    addProperty("reconciliation_required", reconciliationRequired)
                    addProperty("pending_after_recovery", remainsPending)
                    addProperty("recovery_packet_resend_by_test", false)
                }
                assumeTrue("Exact recovery is NOT_RUN: the original operation remains unresolved", false)
                return@withActiveScope
            }
            writeReceipt(sideFile(selected, "exact-recovery.redacted.json"), "${selected.ownerRole}-exact-recovery", "PASS") {
                addProperty("original_operation", expectedOperation)
                addProperty("original_operation_id_sha256", hash(originalOperationId))
                addProperty("reconciliation_required", reconciliationRequired)
                addProperty("pending_after_recovery", remainsPending)
                addProperty("pending_operation_unchanged", !remainsPending || text(after, "pendingOperation") == expectedOperation)
                addProperty("recovery_state", recovery?.get("state")?.asString ?: "RECONCILED")
                addProperty("recovery_packet_resend_by_test", false)
            }
        }
    }

    private fun nonePolicy() = JsonObject().apply {
        addProperty("mode", "NONE")
        add("reviewers", com.google.gson.JsonArray())
        addProperty("max_failovers", 0)
        addProperty("reviewer_lease_seconds", 0)
        addProperty("max_review_age_seconds", 0)
    }

    private fun validatePolicy(policy: JsonObject) {
        require(policy.keySet() == setOf(
            "mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds",
        )) { "Review policy DTO has missing or extra fields" }
        val mode = text(policy, "mode")
        require(mode in setOf("NONE", "METADATA")) { "Review policy mode is invalid" }
        val reviewers = policy.get("reviewers")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: error("Review policy reviewers are invalid")
        require(reviewers.size() <= 8) { "Review policy has too many reviewers" }
        reviewers.forEach { item ->
            require(item.isJsonObject && item.asJsonObject.keySet() == setOf("endpoint_id", "group_id")) {
                "Review policy reviewer DTO is invalid"
            }
            listOf("endpoint_id", "group_id").forEach { field ->
                val id = text(item.asJsonObject, field)
                require(id.isNotBlank() && id.length <= 256 && id == id.trim()) {
                    "Review policy reviewer identifier is invalid"
                }
            }
        }
        val failovers = safeInteger(policy, "max_failovers")
        val lease = safeInteger(policy, "reviewer_lease_seconds")
        val age = safeInteger(policy, "max_review_age_seconds")
        if (mode == "NONE") require(reviewers.size() == 0 && failovers == 0L && lease == 0L && age == 0L) {
            "NONE review policy must have no reviewer configuration"
        }
        if (mode == "METADATA") require(reviewers.size() > 0 && failovers <= reviewers.size() - 1 &&
            lease in 30L..3600L && age in 60L..86400L) {
            "METADATA review policy exceeds its bounded review configuration"
        }
    }

    private fun validateCandidatePolicyGrantStatus(value: JsonObject, signer: JsonObject, ownerRole: String) {
        require(value.keySet() == setOf(
            "policyVersion", "digest", "current", "sourceStatus", "targetStatus", "bilateralVerified",
        )) { "Native policy-grant status receipt has an invalid schema" }
        val version = text(value, "policyVersion")
        val digest = text(value, "digest")
        require(version == safeLongNumber(signer, "policy_version", minimum = 1L).toString() &&
            digest == text(signer, "policy_digest") &&
            version.matches(Regex("[1-9][0-9]*")) && digest.matches(HEX_64)) {
            "Policy-grant status does not match the submitted candidate tuple"
        }
        val source = text(value, "sourceStatus")
        val target = text(value, "targetStatus")
        require(source in POLICY_STATUS_VALUES && target in POLICY_STATUS_VALUES) {
            "Policy-grant status has an unknown Owner status"
        }
        val bilateral = value.get("bilateralVerified")?.asBoolean == true
        val current = value.get("current")?.asBoolean == true
        if (ownerRole == "source") {
            require(!current && !bilateral && source == "VERIFIED" && target == "MISSING") {
                "SOURCE-first grant must remain a noncurrent one-sided candidate receipt"
            }
        } else {
            require(current && bilateral && source == "VERIFIED" && target == "VERIFIED") {
                "TARGET grant must activate the candidate only after both Owner proofs verify"
            }
        }
    }

    private fun validateCurrentPolicyHead(value: JsonObject, signer: JsonObject, ownerRole: String) {
        require(value.keySet() == setOf(
            "policyVersion", "digest", "current", "sourceStatus", "targetStatus", "bilateralVerified",
        )) { "Native current policy-head receipt has an invalid schema" }
        val version = text(value, "policyVersion")
        val digest = text(value, "digest")
        val source = text(value, "sourceStatus")
        val target = text(value, "targetStatus")
        val bilateral = value.get("bilateralVerified")?.asBoolean == true
        require(value.get("current")?.asBoolean == true && source in POLICY_STATUS_VALUES &&
            target in POLICY_STATUS_VALUES) { "Fresh v1.6.4 policy-head receipt is malformed" }
        if (ownerRole == "source") {
            require(version == "0" && digest.isEmpty() && source == "MISSING" && target == "MISSING" && !bilateral) {
                "A one-sided SOURCE proof must leave the unconfigured NONE policy head current"
            }
        } else {
            require(version == safeLongNumber(signer, "policy_version", minimum = 1L).toString() &&
                digest == text(signer, "policy_digest") &&
                version.matches(Regex("[1-9][0-9]*")) && digest.matches(HEX_64) &&
                source == "VERIFIED" && target == "VERIFIED" && bilateral) {
                "TARGET completion did not activate the exact bilateral signed policy tuple"
            }
        }
    }

    /** Report fixed transport outcomes without exposing response content or identifiers. */
    private fun safePolicySubmitFailure(result: JsonObject): String {
        val code = result.get("errorCode")?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isString
        }?.asString?.takeIf {
            it == "LINK_POLICY_RESULT_RECONCILIATION_REQUIRED" || it == "OUTCOME_UNCERTAIN"
        } ?: "UNKNOWN"
        fun flag(name: String): String = result.get(name)?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isBoolean
        }?.asBoolean?.toString() ?: "unknown"
        return "LOCAL_LINK_POLICY_SUBMIT:$code;" +
            "originalOperationCompleted=${flag("originalOperationCompleted")};" +
            "reconciliationRequired=${flag("reconciliationRequired")}"
    }

    private fun expectCode(expected: String, block: () -> Unit) {
        try {
            block()
            error("Expected bounded Link consent refusal")
        } catch (failure: HubSessionException) {
            assertTrue("Link consent refusal code changed", failure.errorCode == expected)
        }
    }

    companion object {
        private const val CATALOG_SHA256 = "953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d"
        private const val ONBOARDING_SCHEMA = "cicada.client-v164-onboarding-public.v1"
        private const val DEVICE_HANDOFF_SCHEMA = "cicada.client-v164-device-public-handoff.v1"
        private const val OWNER_DEVICE_GRANT_SCHEMA = "cicada.client-v164-owner-device-grant-handoff.v1"
        private const val SELECTION_SCHEMA = "cicada.client-v164-link-consent-selection.v2"
        private const val SIGNING_SCHEMA = "cicada.client.link-consent-signing-request.v1"
        private const val REVIEW_HANDOFF_SCHEMA = "cicada.client-v164-link-consent-review-handoff.v1"
        private const val SIGNED_PROOF_SCHEMA = "cicada.client-v164-owner-signed-proof.v1"
        private const val POLICY_FIXTURE_SCHEMA = "cicada.client-v164-review-policy-fixture.v1"
        private const val RECOVERY_SCHEMA = "cicada.client-v164-link-consent-recovery-scenario.v1"
        private val HEX_64 = Regex("[0-9a-f]{64}")
        private val REQUIRED_OPERATIONS = setOf(
            "link.key_manifest", "link.key_grants", "link.key_grant",
            "link.review_policy_status", "link.review_policy_preview", "link.review_policy_grant",
        )
        private val OWNER_STATUS_VALUES = setOf(
            "MISSING", "ACCEPTED", "KEY_BINDING_STALE", "OWNER_KEY_REVOKED",
            "PROOF_EXPIRED", "INVALID", "LEGACY_KEY_UNBOUND",
        )
        private val POLICY_STATUS_VALUES = setOf(
            "MISSING", "VERIFIED", "OWNER_KEY_REVOKED", "PROOF_EXPIRED", "SCOPE_STALE", "INVALID",
        )
        private val OWNER_ROLES = setOf("source", "target")
        private val FORBIDDEN_SIGNER_FIELDS = setOf(
            "private_key", "privatekey", "secret", "seed", "bearer", "token", "password", "credential",
        )
        private val REVIEW_HANDOFF_FIELDS = setOf(
            "schema", "run_id", "kind", "review_id", "consent_digest", "link_id", "link_version",
            "side", "owner_id", "owner_key_id", "signing_request_json", "native_review_json",
        )
        private val SIGNED_PROOF_FIELDS = setOf(
            "schema", "run_id", "review_id", "consent_digest", "link_id", "link_version", "side",
            "owner_id", "owner_key_id", "signed_proof_base64", "proof_sha256",
        )
        private val OWNER_DEVICE_GRANT_FIELDS = setOf(
            "schema", "run_id", "profile_id", "profile_generation", "hub_id", "owner_id",
            "owner_key_id", "device_id", "catalog_sha256", "device_public_identity_sha256",
            "owner_device_grant_base64", "grant_sha256",
        )
    }
}
