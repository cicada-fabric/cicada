package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonArray
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/** Pure JVM tests using only the published public synthetic Link proof vector. */
class LinkConsentAuthorityFactoryTest {
    private data class Fixture(
        val vector: JsonObject,
        val manifest: JsonObject,
        val statuses: List<JsonObject>,
        val statusResult: JsonArray,
        val sourcePin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
        val targetPin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
        val provenance: FreshLinkManifestRead,
        val statusProvenance: FreshLinkOwnerGrantStatusRead,
        val now: Instant,
    )

    private fun fixture(): Fixture {
        val loader = javaClass.classLoader
        val input = loader?.getResourceAsStream("link-client-proof-v2.json")
            ?: throw AssertionError("Missing public Link proof vector resource")
        val raw = input.use { it.readBytes() }
        assertEquals(
            "aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d",
            sha256(raw),
        )
        val vector = JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
        assertTrue("The published vector must remain synthetic", vector.get("synthetic").asBoolean)
        val manifest = vector.getAsJsonObject("manifest")
        val statuses = vector.getAsJsonArray("statuses").map { it.asJsonObject }
        val statusResult = statusArray(statuses)
        val sourcePin = pinFromStatus(statuses.single { it.get("side").asString == "SOURCE" })
        val targetPin = pinFromStatus(statuses.single { it.get("side").asString == "TARGET" })
        val contract = JsonParser.parseString(
            String(Base64.getDecoder().decode(manifest.get("contract_canonical").asString), StandardCharsets.UTF_8),
        ).asJsonObject
        val now = Instant.parse(vector.get("verification_time").asString)
        val provenance = FreshLinkManifestRead(
            profileId = "profile_vector",
            profileGeneration = 1,
            hubId = contract.get("transport_hub_id").asString,
            ownerId = contract.get("source_owner_id").asString,
            deviceId = "device_vector",
            sessionEpoch = 1,
            operation = "link.key_manifest",
            operationId = "operation_vector",
            requestSequence = 1,
            responseSequence = 1,
            authenticatedResultSha256 = LinkConsentAuthorityFactory.manifestResultSha256(manifest),
            selectedLinkId = manifest.get("link_id").asString,
            selectedLinkVersion = manifest.get("link_version").asLong,
            localSide = "SOURCE",
        )
        val statusProvenance = freshStatusRead(provenance, manifest, statusResult)
        return Fixture(
            vector, manifest, statuses, statusResult, sourcePin, targetPin,
            provenance, statusProvenance, now,
        )
    }

    @Test fun signerExpiryUsesCanonicalGoRfc3339NanoAndRoundTripsExactly() {
        val cases = listOf(
            "2026-10-02T15:27:50Z" to "2026-10-02T15:27:50Z",
            "2026-10-02T15:27:50.050630Z" to "2026-10-02T15:27:50.05063Z",
            "2026-10-02T15:27:50.120000Z" to "2026-10-02T15:27:50.12Z",
            "2026-10-02T15:27:50.123400Z" to "2026-10-02T15:27:50.1234Z",
            "2026-10-02T15:27:50.123456780Z" to "2026-10-02T15:27:50.12345678Z",
            "2026-10-02T15:27:50.123456789Z" to "2026-10-02T15:27:50.123456789Z",
            "2026-10-02T15:27:50.000000001Z" to "2026-10-02T15:27:50.000000001Z",
        )

        cases.forEach { (instantText, canonicalText) ->
            val instant = Instant.parse(instantText)
            if (instantText == "2026-10-02T15:27:50.050630Z") {
                assertEquals("2026-10-02T15:27:50.050630Z", instant.toString())
            }
            assertEquals(canonicalText, GroupKeyManifestVerifier.formatCanonicalUtc(instant))
            assertEquals(instant, GroupKeyManifestVerifier.parseCanonicalUtc(canonicalText))
        }
    }

    private fun pinFromStatus(status: JsonObject): LinkKeyManifestVerifier.OwnerPublicKeyPin {
        val evidence = status.getAsJsonObject("evidence")
        val identity = ClientWireCrypto.PublicIdentity.parse(evidence.getAsJsonObject("owner_public_identity"))
        return LinkKeyManifestVerifier.OwnerPublicKeyPin(
            ownerId = status.get("owner_id").asString,
            keyId = evidence.get("owner_key_id").asString,
            publicIdentity = identity,
        )
    }

    @Test fun currentManifestAndBothRetainedOwnerProofsBindToOneFreshNativeRead() {
        val f = fixture()
        val verified = LinkConsentAuthorityFactory.verifyFreshManifest(
            provenance = f.provenance,
            manifestJson = f.manifest,
            sourceOwnerPin = f.sourcePin,
            targetOwnerPin = f.targetPin,
            now = f.now,
        )

        assertEquals(f.provenance.selectedLinkId, verified.currentLink.linkId)
        assertEquals(f.provenance.selectedLinkVersion, verified.manifest.linkVersion)
        assertEquals(f.sourcePin.ownerId, verified.currentLink.source.ownerId)
        assertEquals(f.targetPin.ownerId, verified.currentLink.target.ownerId)
        assertEquals(1L, verified.currentLink.source.membershipRevision)
        assertEquals(1L, verified.currentLink.target.joinRevision)

        val policyLink = verified.asPolicyCurrentLink()
        assertEquals(verified.manifest.contractDigest, policyLink.contractDigest)
        assertEquals(f.provenance.localSide, policyLink.localSide)
        assertEquals(f.sourcePin.keyId, policyLink.sourceOwnerPin.keyId)
        assertEquals(f.targetPin.keyId, policyLink.targetOwnerPin.keyId)

        val grants = verified.verifyOwnerGrants(f.statusProvenance, f.statusResult, f.now)
        assertEquals(verified.manifest.digest, grants.manifestDigest)
        assertEquals("SOURCE", grants.source.side)
        assertEquals("TARGET", grants.target.side)
        assertEquals("ACTIVE", grants.sourceOwnerKey.state)
        assertTrue(grants.sourceOwnerKey.version > 0)
        assertEquals("ACTIVE", grants.targetOwnerKey.state)
        assertTrue(grants.targetOwnerKey.version > 0)

        val sourceProof = Base64.getDecoder().decode(
            f.statuses.single { it.get("side").asString == "SOURCE" }
                .getAsJsonObject("evidence").get("signed_proof").asString,
        )
        assertEquals("SOURCE", verified.verifyOwnerGrant("SOURCE", sourceProof, f.now).side)

        val oneSideResult = statusArray(f.statuses.map { status ->
            status.deepCopy().apply {
                if (get("side").asString == "TARGET") {
                    addProperty("accepted", false)
                    addProperty("current_status", "MISSING")
                    remove("evidence")
                    remove("key_id")
                    remove("manifest_digest")
                }
            }
        })
        val oneSideRead = freshStatusRead(f.provenance, f.manifest, oneSideResult)
        val sourceStatus = verified.verifyOwnerGrantStatusForSide(
            oneSideRead, oneSideResult, "SOURCE", f.now,
        )
        assertEquals("SOURCE", sourceStatus?.ownerGrant?.side)
        assertEquals("ACTIVE", sourceStatus?.currentOwnerKey?.state)
        assertTrue(requireNotNull(sourceStatus).currentOwnerKey.version > 0)
        assertEquals(null, verified.verifyOwnerGrantStatusForSide(
            oneSideRead, oneSideResult, "TARGET", f.now,
        ))
    }

    @Test fun nativeReadScopeAndOwnerPinsAreRequiredAndDistinctlyBound() {
        val f = fixture()
        val wrongOperation = freshRead(f.provenance, operation = "link.list")
        assertRejected("A non-manifest RPC result was accepted as fresh manifest provenance") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                wrongOperation, f.manifest, f.sourcePin, f.targetPin, f.now,
            )
        }

        val wrongSelection = freshRead(f.provenance, selectedLinkVersion = f.provenance.selectedLinkVersion + 1)
        assertRejected("A manifest for a different selected Link version was accepted") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                wrongSelection, f.manifest, f.sourcePin, f.targetPin, f.now,
            )
        }

        val wrongLocalOwner = freshRead(f.provenance, localSide = "TARGET")
        assertRejected("A fresh read for another Owner side was accepted") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                wrongLocalOwner, f.manifest, f.sourcePin, f.targetPin, f.now,
            )
        }

        assertRejected("A target-side key was accepted as the source Owner pin") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                f.provenance, f.manifest, f.targetPin, f.sourcePin, f.now,
            )
        }

        val wrongKeyId = LinkKeyManifestVerifier.OwnerPublicKeyPin(
            ownerId = f.sourcePin.ownerId,
            keyId = "pq1-" + "0".repeat(32),
            publicIdentity = f.sourcePin.publicIdentity,
        )
        assertRejected("A mismatched full-key pin ID was accepted") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                f.provenance, f.manifest, wrongKeyId, f.targetPin, f.now,
            )
        }
    }

    @Test fun fullManifestMutationAndIncompleteOrStaleGrantsFailClosed() {
        val f = fixture()
        val tamperedDigest = f.manifest.deepCopy().apply {
            addProperty("digest", "0".repeat(64))
        }
        assertRejected("A tampered Link manifest digest was accepted") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                f.provenance, tamperedDigest, f.sourcePin, f.targetPin, f.now,
            )
        }

        val tamperedEndpointProof = f.manifest.deepCopy().apply {
            val source = getAsJsonObject("source")
            val proof = Base64.getDecoder().decode(source.get("attestation").asString)
            proof[proof.lastIndex] = (proof.last().toInt() xor 1).toByte()
            source.addProperty("attestation", Base64.getEncoder().encodeToString(proof))
        }
        assertRejected("A mutated complete Endpoint attestation was accepted") {
            LinkConsentAuthorityFactory.verifyFreshManifest(
                f.provenance, tamperedEndpointProof, f.sourcePin, f.targetPin, f.now,
            )
        }

        val verified = LinkConsentAuthorityFactory.verifyFreshManifest(
            f.provenance, f.manifest, f.sourcePin, f.targetPin, f.now,
        )
        assertRejected("One Owner status was enough for bilateral verification") {
            val shortResult = statusArray(f.statuses.take(1))
            verified.verifyOwnerGrants(
                freshStatusRead(f.provenance, f.manifest, shortResult), shortResult, f.now,
            )
        }

        val alteredResult = statusArray(f.statuses.map { it.deepCopy() }.also {
            it[0].addProperty("current_status", "MISSING")
        })
        assertRejected("A status result differing from authenticated provenance was accepted") {
            verified.verifyOwnerGrants(f.statusProvenance, alteredResult, f.now)
        }

        val acceptedFlagOnly = f.statuses.mapIndexed { index, status ->
            if (index == 0) status.deepCopy().apply { remove("evidence") } else status.deepCopy()
        }
        assertRejected("accepted=true without retained proof evidence was accepted") {
            val result = statusArray(acceptedFlagOnly)
            verified.verifyOwnerGrants(freshStatusRead(f.provenance, f.manifest, result), result, f.now)
        }

        val mismatchedTargetKey = f.statuses.map { status ->
            status.deepCopy().apply {
                if (get("side").asString == "TARGET") {
                    val evidence = getAsJsonObject("evidence")
                    evidence.addProperty("owner_key_id", f.sourcePin.keyId)
                }
            }
        }
        assertRejected("A retained proof with a different current key ID was accepted") {
            val result = statusArray(mismatchedTargetKey)
            verified.verifyOwnerGrants(freshStatusRead(f.provenance, f.manifest, result), result, f.now)
        }

        val changedStatus = f.statuses.map { status ->
            status.deepCopy().apply {
                if (get("side").asString == "TARGET") addProperty("current_status", "PROOF_EXPIRED")
            }
        }
        assertRejected("An expired current status was accepted as bilateral consent") {
            val result = statusArray(changedStatus)
            verified.verifyOwnerGrants(freshStatusRead(f.provenance, f.manifest, result), result, f.now)
        }
    }

    @Test fun identityOnlyProofVerificationDoesNotInventOwnerLifecycle() {
        val f = fixture()
        val verified = LinkConsentAuthorityFactory.verifyFreshManifest(
            f.provenance, f.manifest, f.sourcePin, f.targetPin, f.now,
        )
        val targetStatus = f.statuses.single { it.get("side").asString == "TARGET" }
        val targetProof = Base64.getDecoder().decode(
            targetStatus.getAsJsonObject("evidence").get("signed_proof").asString,
        )
        assertEquals("TARGET", verified.verifyOwnerGrant("TARGET", targetProof, f.now).side)

        val sourceIdentityAsTarget = LinkKeyManifestVerifier.OwnerPublicKeyPin(
            ownerId = f.targetPin.ownerId,
            keyId = f.sourcePin.keyId,
            publicIdentity = f.sourcePin.publicIdentity,
        )
        assertRejected("A proof verified under a different peer full key") {
            LinkKeyManifestVerifier.verifyOwnerGrant(
                rawProof = targetProof,
                pinnedOwnerKey = sourceIdentityAsTarget,
                currentLink = verified.currentLink,
                manifestJson = f.manifest,
                side = "TARGET",
                now = f.now,
            )
        }
    }

    @Test fun v164PolicyVectorIsNotCrossBoundToThisDifferentLinkManifest() {
        val loader = javaClass.classLoader
        val input = loader?.getResourceAsStream("link-review-policy-client-evidence-v1.json")
            ?: throw AssertionError("Missing public Link review-policy vector resource")
        val raw = input.use { it.readBytes() }
        assertEquals(
            "aeb0985056e305a2ea06616e39bebd2bd58957efe61d5e2be9511f6a52039bcd",
            sha256(raw),
        )
        val policyVector = JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
        val f = fixture()
        val otherLinkId = policyVector.get("preview").asJsonObject.get("link_id").asString
        assertNotEquals(f.manifest.get("link_id").asString, otherLinkId)
    }

    private fun freshRead(
        source: FreshLinkManifestRead,
        operation: String = source.operation,
        selectedLinkVersion: Long = source.selectedLinkVersion,
        localSide: String = source.localSide,
    ) = FreshLinkManifestRead(
        profileId = source.profileId,
        profileGeneration = source.profileGeneration,
        hubId = source.hubId,
        ownerId = source.ownerId,
        deviceId = source.deviceId,
        sessionEpoch = source.sessionEpoch,
        operation = operation,
        operationId = source.operationId,
        requestSequence = source.requestSequence,
        responseSequence = source.responseSequence,
        authenticatedResultSha256 = source.authenticatedResultSha256,
        selectedLinkId = source.selectedLinkId,
        selectedLinkVersion = selectedLinkVersion,
        localSide = localSide,
    )

    private fun statusArray(statuses: List<JsonObject>) = JsonArray().apply {
        statuses.forEach { add(it.deepCopy()) }
    }

    private fun freshStatusRead(
        manifestRead: FreshLinkManifestRead,
        manifest: JsonObject,
        result: JsonArray,
    ) = FreshLinkOwnerGrantStatusRead(
        profileId = manifestRead.profileId,
        profileGeneration = manifestRead.profileGeneration,
        hubId = manifestRead.hubId,
        ownerId = manifestRead.ownerId,
        deviceId = manifestRead.deviceId,
        sessionEpoch = manifestRead.sessionEpoch,
        operation = "link.key_grants",
        operationId = "operation_status_vector",
        requestSequence = manifestRead.requestSequence + 1,
        responseSequence = manifestRead.responseSequence + 1,
        authenticatedResultSha256 = LinkConsentAuthorityFactory.ownerGrantStatusResultSha256(result),
        selectedLinkId = manifestRead.selectedLinkId,
        selectedLinkVersion = manifestRead.selectedLinkVersion,
        localSide = manifestRead.localSide,
        manifestDigest = manifest.get("digest").asString,
    )

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun assertRejected(message: String, block: () -> Unit) {
        try {
            block()
            fail(message)
        } catch (_: Exception) {
            // Expected invalid, stale, incomplete, or cross-scope evidence.
        }
    }
}
