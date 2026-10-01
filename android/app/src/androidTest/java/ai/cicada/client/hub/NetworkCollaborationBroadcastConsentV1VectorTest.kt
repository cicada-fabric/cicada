package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/** Independent Kotlin checks for the pinned v1.6 BROADCAST public vector; TASK is separate. */
@RunWith(AndroidJUnit4::class)
class NetworkCollaborationBroadcastConsentV1VectorTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val validAt = Instant.parse("2026-10-01T13:00:00Z")
    private val vectorBytes by lazy {
        instrumentation.context.assets.open("network-collaboration-broadcast-consent-v1.json")
            .use { it.readBytes() }
    }
    private val vector by lazy {
        assertEquals(
            "c18b237047a6963b95844a1a32307794e6b353150313b77ab2ce84393b0ab8ea",
            sha256(vectorBytes),
        )
        JsonParser.parseString(String(vectorBytes, StandardCharsets.UTF_8)).asJsonObject.also {
            assertEquals(1, it.get("fixture_version").asInt)
            assertTrue(it.get("synthetic_only").asBoolean)
            assertEquals("PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT",
                it.get("warning").asString)
            assertEquals("BROADCAST", it.get("purpose").asString)
        }
    }
    private val manifestRaw by lazy {
        vector.get("manifest_canonical_json").asString.toByteArray(StandardCharsets.UTF_8)
    }
    private val grantRaw by lazy {
        vector.get("owner_grant_json").asString.toByteArray(StandardCharsets.UTF_8)
    }
    private val manifest by lazy {
        JsonParser.parseString(String(manifestRaw, StandardCharsets.UTF_8)).asJsonObject
    }
    private val grant by lazy {
        JsonParser.parseString(String(grantRaw, StandardCharsets.UTF_8)).asJsonObject
    }
    private val owner by lazy {
        ClientWireCrypto.PublicIdentity.parse(vector.getAsJsonObject("owner_public_identity"))
    }
    private val candidate by lazy {
        ClientWireCrypto.PublicIdentity.parse(
            manifest.getAsJsonObject("candidate").getAsJsonObject("public_identity"),
        )
    }

    private fun authority(
        source: JsonObject = manifest,
        ownerIdentity: ClientWireCrypto.PublicIdentity = owner,
        candidateIdentity: ClientWireCrypto.PublicIdentity = candidate,
    ): NetworkCollaborationBroadcastConsentV1Verifier.CurrentAuthority {
        val row = source.getAsJsonObject("candidate")
        return NetworkCollaborationBroadcastConsentV1Verifier.CurrentAuthority(
            isCurrent = true,
            hubId = source.get("hub_id").asString,
            networkId = source.get("network_id").asString,
            endpointId = source.get("endpoint_id").asString,
            principalId = source.get("principal_id").asString,
            ownerId = source.get("owner_id").asString,
            nodeId = source.get("node_id").asString,
            nativeSessionDigest = source.get("native_session_digest").asString,
            bindingId = source.get("binding_id").asString,
            bindingEpoch = source.get("binding_epoch").asLong,
            membershipRevision = source.get("membership_revision").asLong,
            endpointEnrollmentRevision = source.get("endpoint_enrollment_revision").asLong,
            candidateVersion = row.get("version").asLong,
            candidateFingerprint = row.get("fingerprint").asString,
            candidatePublicIdentity = candidateIdentity,
            ownerPublicIdentity = ownerIdentity,
            currentManifestDigest = vector.get("collaboration_manifest_digest").asString,
        )
    }

    private fun authorityForVector(
        sourceVector: JsonObject,
    ): NetworkCollaborationBroadcastConsentV1Verifier.CurrentAuthority {
        val sourceManifestRaw = sourceVector.get("manifest_canonical_json").asString
            .toByteArray(StandardCharsets.UTF_8)
        val sourceManifest = JsonParser.parseString(
            String(sourceManifestRaw, StandardCharsets.UTF_8),
        ).asJsonObject
        val sourceCandidate = sourceManifest.getAsJsonObject("candidate")
        val sourceIdentity = ClientWireCrypto.PublicIdentity.parse(
            sourceCandidate.getAsJsonObject("public_identity"),
        )
        val sourceOwner = ClientWireCrypto.PublicIdentity.parse(
            sourceVector.getAsJsonObject("owner_public_identity"),
        )
        val broadcastDigest = sha256(
            "cicada/network/collaboration-key-manifest/v1\u0000BROADCAST\u0000"
                .toByteArray(StandardCharsets.UTF_8) + sourceManifestRaw,
        )
        return NetworkCollaborationBroadcastConsentV1Verifier.CurrentAuthority(
            isCurrent = true,
            hubId = sourceManifest.get("hub_id").asString,
            networkId = sourceManifest.get("network_id").asString,
            endpointId = sourceManifest.get("endpoint_id").asString,
            principalId = sourceManifest.get("principal_id").asString,
            ownerId = sourceManifest.get("owner_id").asString,
            nodeId = sourceManifest.get("node_id").asString,
            nativeSessionDigest = sourceManifest.get("native_session_digest").asString,
            bindingId = sourceManifest.get("binding_id").asString,
            bindingEpoch = sourceManifest.get("binding_epoch").asLong,
            membershipRevision = sourceManifest.get("membership_revision").asLong,
            endpointEnrollmentRevision = sourceManifest.get("endpoint_enrollment_revision").asLong,
            candidateVersion = sourceCandidate.get("version").asLong,
            candidateFingerprint = sourceCandidate.get("fingerprint").asString,
            candidatePublicIdentity = sourceIdentity,
            ownerPublicIdentity = sourceOwner,
            currentManifestDigest = broadcastDigest,
        )
    }

    @Test fun publishedVectorReproducesTwelveClaimsWithFinalNullAndVerifiesOwnerGrant() {
        val grantFields = listOf(
            "version", "purpose", "hub_id", "network_id", "endpoint_id", "owner_id",
            "owner_key_id", "manifest_digest", "issued_at", "expires_at", "nonce", "signature",
        )
        assertEquals(grantFields, vector.getAsJsonArray("claims_field_order").map { it.asString })
        assertEquals(grantFields, grant.keySet().toList())
        assertEquals(String(grantRaw, StandardCharsets.UTF_8), grant.toString())
        assertEquals(String(manifestRaw, StandardCharsets.UTF_8), manifest.toString())

        // Build the BROADCAST wire claims independently. The final signature:null is signed.
        val claims = JsonObject().apply {
            addProperty("version", grant.get("version").asInt)
            addProperty("purpose", grant.get("purpose").asString)
            addProperty("hub_id", grant.get("hub_id").asString)
            addProperty("network_id", grant.get("network_id").asString)
            addProperty("endpoint_id", grant.get("endpoint_id").asString)
            addProperty("owner_id", grant.get("owner_id").asString)
            addProperty("owner_key_id", grant.get("owner_key_id").asString)
            addProperty("manifest_digest", grant.get("manifest_digest").asString)
            addProperty("issued_at", grant.get("issued_at").asString)
            addProperty("expires_at", grant.get("expires_at").asString)
            addProperty("nonce", grant.get("nonce").asString)
            add("signature", JsonNull.INSTANCE)
        }
        assertEquals(grantFields, claims.keySet().toList())
        assertTrue(claims.get("signature").isJsonNull)
        val unsignedJson = claims.toString()
        assertEquals(vector.get("canonical_unsigned_json").asString, unsignedJson)
        assertFalse(unsignedJson.contains("\"signature\":\""))

        val domain = "cicada/network/collaboration-key-grant/v1\u0000"
        val signed = domain.toByteArray(StandardCharsets.UTF_8) + unsignedJson.toByteArray(StandardCharsets.UTF_8)
        assertEquals("cicada/network/collaboration-key-grant/v1\\x00",
            vector.get("signing_domain").asString)
        assertArrayEquals(Base64.getDecoder().decode(vector.get("signed_input_base64").asString), signed)
        assertArrayEquals(hexBytes(vector.get("signed_input_hex").asString), signed)
        assertEquals(vector.get("signed_input_sha256").asString, sha256(signed))

        val signature = Base64.getDecoder().decode(grant.get("signature").asString)
        assertEquals(3309, signature.size)
        assertArrayEquals(Base64.getDecoder().decode(vector.get("signature_base64").asString), signature)
        assertEquals(Base64.getEncoder().encodeToString(owner.signingPublic),
            vector.getAsJsonObject("owner_public_identity").get("signing_public").asString)
        assertEquals(owner.id, grant.get("owner_key_id").asString)
        owner.validate()
        assertEquals(1184, owner.kemPublic.size)
        assertEquals(1952, owner.signingPublic.size)
        assertTrue(ClientWireCrypto.verify(owner, signed, signature))

        val manifestFields = listOf(
            "version", "hub_id", "network_id", "endpoint_id", "principal_id", "owner_id",
            "node_id", "native_session_digest", "binding_id", "binding_epoch",
            "membership_revision", "endpoint_enrollment_revision", "candidate", "digest",
        )
        assertEquals(manifestFields, manifest.keySet().toList())
        val candidateObject = manifest.getAsJsonObject("candidate")
        assertEquals(listOf("network_id", "endpoint_id", "principal_id", "owner_id", "node_id",
            "binding_id", "binding_epoch", "public_identity", "fingerprint", "attestation", "version"),
            candidateObject.keySet().toList())
        assertEquals(listOf("id", "kem_public", "signing_public"),
            candidateObject.getAsJsonObject("public_identity").keySet().toList())
        assertEquals("", manifest.get("digest").asString)
        val manifestDigest = sha256(
            "cicada/network/collaboration-key-manifest/v1\u0000BROADCAST\u0000"
                .toByteArray(StandardCharsets.UTF_8) + manifestRaw,
        )
        assertEquals(vector.get("collaboration_manifest_digest").asString, manifestDigest)
        assertEquals(manifestDigest, grant.get("manifest_digest").asString)
        candidate.validate()

        val checked = NetworkCollaborationBroadcastConsentV1Verifier.verify(
            manifestRaw, grantRaw, authority(), validAt,
        )
        assertEquals("BROADCAST", checked.purpose)
        assertEquals("hub_synthetic_collaboration", checked.hubId)
        assertEquals("net_synthetic_collaboration", checked.networkId)
        assertEquals("ep_synthetic_collaboration", checked.endpointId)
        assertEquals(owner.id, checked.ownerKeyId)
        assertEquals(manifestDigest, checked.manifestDigest)
        assertEquals(Instant.parse("2026-10-01T14:00:00Z"), checked.expiresAt)
    }

    @Test fun broadcastGrantRejectsOtherPurposeKeyAndExpiredConsent() {
        val purposeChanged = grant.deepCopy().apply { addProperty("purpose", "TASK") }
        assertRejected("TASK purpose was accepted by BROADCAST verifier", authority(), validAt,
            grant = bytes(purposeChanged))

        val policyVector = instrumentation.context.assets
            .open("owner-link-review-policy-proof-v1.json").use {
                JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject
            }
        val otherOwner = ClientWireCrypto.PublicIdentity.parse(policyVector.getAsJsonObject("owner_public_identity"))
        assertRejected("Grant verified under another Owner key", authority(ownerIdentity = otherOwner), validAt)

        // The separate TASK asset is independently covered by its own vector test. Feed its
        // actual signed proof into this fixed BROADCAST-only verifier to guard purpose separation.
        val taskVector = instrumentation.context.assets
            .open("network-collaboration-key-consent-v1.json").use {
                JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject
            }
        assertEquals("TASK", taskVector.get("purpose").asString)
        assertRejected("Actual TASK signed proof was accepted as BROADCAST",
            authorityForVector(taskVector), validAt,
            manifestBytes = taskVector.get("manifest_canonical_json").asString
                .toByteArray(StandardCharsets.UTF_8),
            grant = taskVector.get("owner_grant_json").asString.toByteArray(StandardCharsets.UTF_8))

        assertRejected("Grant issued in the future was accepted", authority(),
            Instant.parse("2026-10-01T11:59:59Z"))
        assertRejected("Grant accepted at expiry was accepted", authority(),
            Instant.parse("2026-10-01T14:00:00Z"))
    }

    @Test fun broadcastGrantRejectsStaleOwnerScopeBindingRevisionAndManifestMutations() {
        val current = authority()
        val changed = listOf(
            current.copy(isCurrent = false),
            current.copy(hubId = "hub_synthetic_other"),
            current.copy(networkId = "net_synthetic_other"),
            current.copy(endpointId = "ep_synthetic_other"),
            current.copy(principalId = "pr_synthetic_other"),
            current.copy(ownerId = "owner_synthetic_other"),
            current.copy(nodeId = "node_synthetic_other"),
            current.copy(nativeSessionDigest = "0".repeat(64)),
            current.copy(bindingId = "binding_synthetic_other"),
            current.copy(bindingEpoch = current.bindingEpoch + 1),
            current.copy(membershipRevision = current.membershipRevision + 1),
            current.copy(endpointEnrollmentRevision = current.endpointEnrollmentRevision + 1),
            current.copy(candidateVersion = current.candidateVersion + 1),
            current.copy(candidateFingerprint = "synthetic-fingerprint-other"),
            current.copy(candidatePublicIdentity = owner),
            current.copy(currentManifestDigest = "0".repeat(64)),
        )
        changed.forEachIndexed { index, other ->
            assertRejected("Current BROADCAST authority mutation $index was accepted", other, validAt)
        }

        val badSignature = grant.deepCopy()
        val signature = Base64.getDecoder().decode(badSignature.get("signature").asString)
        signature[signature.lastIndex] = (signature.last().toInt() xor 1).toByte()
        badSignature.addProperty("signature", Base64.getEncoder().encodeToString(signature))
        assertRejected("Changed BROADCAST ML-DSA signature was accepted", current, validAt,
            grant = bytes(badSignature))

        val changedManifest = manifest.deepCopy()
        changedManifest.addProperty("binding_id", "binding_synthetic_changed")
        assertRejected("Manifest with changed binding was accepted", current, validAt,
            manifestBytes = bytes(changedManifest))

        val changedCandidateRevision = manifest.deepCopy()
        changedCandidateRevision.getAsJsonObject("candidate")
            .addProperty("version", candidateVersion() + 1)
        assertRejected("Manifest with changed candidate revision was accepted", current, validAt,
            manifestBytes = bytes(changedCandidateRevision))

        val reversedGrant = JsonObject()
        grant.keySet().toList().reversed().forEach { reversedGrant.add(it, grant.get(it).deepCopy()) }
        assertRejected("Reordered BROADCAST grant JSON was accepted", current, validAt,
            grant = bytes(reversedGrant))
    }

    private fun candidateVersion(): Long = manifest.getAsJsonObject("candidate").get("version").asLong

    private fun assertRejected(
        message: String,
        context: NetworkCollaborationBroadcastConsentV1Verifier.CurrentAuthority,
        now: Instant,
        manifestBytes: ByteArray = manifestRaw,
        grant: ByteArray = grantRaw,
    ) {
        try {
            NetworkCollaborationBroadcastConsentV1Verifier.verify(manifestBytes, grant, context, now)
            fail(message)
        } catch (_: Exception) {
            // Rejection is expected; keep synthetic public proof material out of logs.
        }
    }

    private fun bytes(value: JsonObject): ByteArray = value.toString().toByteArray(StandardCharsets.UTF_8)

    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun hexBytes(value: String): ByteArray = value.chunked(2)
        .map { it.toInt(16).toByte() }.toByteArray()
}
