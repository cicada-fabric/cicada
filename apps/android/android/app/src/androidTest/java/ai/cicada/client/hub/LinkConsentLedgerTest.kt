package ai.cicada.client.hub

import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

/** Pure ledger transition tests; the only fixture material is the published synthetic public vector. */
class LinkConsentLedgerTest {
    private data class Fixture(
        val staged: LinkConsentLedger,
        val fence: LinkConsentLedger.WriteFence,
        val tuple: LinkConsentLedger.AuthorityTuple,
    )

    private fun fixture(): Fixture {
        val stream = (javaClass.classLoader)
            ?.getResourceAsStream("link-client-proof-v2.json")
            ?: throw AssertionError("Missing published synthetic Link vector")
        val vector = stream.use { JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject }
        assertEquals("PUBLIC TEST FIXTURE ONLY; NEVER INITIALIZE A DEPLOYMENT", vector.get("warning").asString)
        val manifest = vector.getAsJsonObject("manifest")
        val contractBytes = Base64.getDecoder().decode(manifest.get("contract_canonical").asString)
        val contract = JsonParser.parseString(String(contractBytes, StandardCharsets.UTF_8)).asJsonObject
        val statuses = vector.getAsJsonArray("statuses").map { it.asJsonObject }
        val statusBySide = statuses.associateBy { it.get("side").asString }
        val pinBySide = mutableMapOf<String, LinkConsentLedger.OwnerPin>()
        var ledger = LinkConsentLedger.empty()
        val now = Instant.parse(vector.get("verification_time").asString)
        for (side in listOf("SOURCE", "TARGET")) {
            val status = requireNotNull(statusBySide[side])
            val evidence = status.getAsJsonObject("evidence")
            val identity = ClientWireCrypto.PublicIdentity.parse(evidence.getAsJsonObject("owner_public_identity"))
            val ownerId = status.get("owner_id").asString
            val (updated, pin) = ledger.pinOwner(identity, ownerId, identity.fingerprint(), true, now)
            ledger = updated
            pinBySide[side] = pin
        }
        fun sideScope(side: String): LinkConsentLedger.SideScope {
            val key = side.lowercase()
            val endpoint = manifest.getAsJsonObject(key)
            val status = requireNotNull(statusBySide[side])
            val evidence = status.getAsJsonObject("evidence")
            val pin = requireNotNull(pinBySide[side])
            return LinkConsentLedger.SideScope(
                endpointId = endpoint.get("endpoint_id").asString,
                groupId = endpoint.get("group_id").asString,
                principalId = endpoint.get("principal_id").asString,
                ownerId = endpoint.get("owner_id").asString,
                nodeId = endpoint.get("node_id").asString,
                bindingId = endpoint.get("binding_id").asString,
                bindingEpoch = endpoint.get("binding_epoch").asLong,
                candidateVersion = endpoint.get("candidate_version").asLong,
                keyId = endpoint.get("key_id").asString,
                keyFingerprint = endpoint.get("key_fingerprint").asString,
                proofDigest = endpoint.get("proof_digest").asString,
                membershipRevision = contract.getAsJsonObject("scope_snapshot").get("${key}_membership_revision").asLong,
                joinRevision = contract.getAsJsonObject("scope_snapshot").get("${key}_join_revision").asLong,
                groupVersion = contract.getAsJsonObject("scope_snapshot").get("${key}_group_version").asLong,
                ownerKeyId = evidence.get("owner_key_id").asString,
                ownerFingerprint = pin.fingerprint,
                ownerKeyState = null,
                ownerKeyVersion = null,
                ownerPinRevision = pin.pinRevision,
            )
        }
        val source = sideScope("SOURCE")
        val target = sideScope("TARGET")
        val tuple = LinkConsentLedger.AuthorityTuple(
            profileId = "profile_synthetic_vector",
            profileGeneration = 1,
            hubId = contract.get("transport_hub_id").asString,
            ownerId = source.ownerId,
            deviceId = "device_synthetic_vector",
            sessionEpoch = 1,
            linkId = manifest.get("link_id").asString,
            linkVersion = manifest.get("link_version").asLong,
            contractDigest = manifest.get("contract_digest").asString,
            manifestDigest = manifest.get("digest").asString,
            localSide = "SOURCE",
            kind = "KEY",
            direction = contract.get("direction").asString,
            actions = contract.getAsJsonArray("actions").map { it.asString }.sorted(),
            dataScopes = contract.getAsJsonArray("data_scopes").map { it.asString }.sorted(),
            expiresAt = contract.get("expires_at").asString,
            source = source,
            target = target,
        )
        val review = LinkConsentLedger.Review(
            reviewId = "review_synthetic_vector",
            consentDigest = LinkConsentLedger.digestTuple(tuple),
            tuple = tuple,
            manifestRead = LinkConsentLedger.ReadCorrelation("link.key_manifest", "read_manifest", 1, 2),
            statusRead = LinkConsentLedger.ReadCorrelation("link.key_grants", "read_grants", 3, 4),
            previewRead = null,
            policyJson = null,
            signingRequestJson = "{\"synthetic\":true}",
            createdAt = now.toString(),
        )
        ledger = ledger.prepare(review)
        val proof = "{\"synthetic_public_test_record\":true}"
        val packet = "{\"synthetic_opaque_packet\":true}"
        val fence = LinkConsentLedger.WriteFence(
            operation = "link.key_grant",
            operationId = "write_synthetic_vector",
            requestSequence = 5,
            expectedResponseSequence = 6,
            signedProofJson = proof,
            signedProofSha256 = LinkConsentLedger.digest(proof.toByteArray(StandardCharsets.UTF_8)),
            packetJson = packet,
            packetSha256 = LinkConsentLedger.digest(packet.toByteArray(StandardCharsets.UTF_8)),
            reviewId = review.reviewId,
            consentDigest = review.consentDigest,
            tupleDigest = LinkConsentLedger.digestTuple(tuple),
            state = LinkConsentLedger.FenceState.PENDING,
        )
        val staged = ledger.stage(fence)
        return Fixture(staged, fence, tuple)
    }

    @Test fun processingAndRecoveryStatesNeverDropOriginalPacketOrProof() {
        val f = fixture()
        for (next in LinkConsentLedger.FenceState.values().filter { it != LinkConsentLedger.FenceState.PENDING }) {
            val changed = f.staged.markFenceState(f.fence.operationId, f.fence.requestSequence, next)
            assertEquals(next, changed.writeFence?.state)
            assertEquals(f.fence.packetJson, changed.writeFence?.packetJson)
            assertEquals(f.fence.packetSha256, changed.writeFence?.packetSha256)
            assertEquals(f.fence.signedProofJson, changed.writeFence?.signedProofJson)
            assertEquals(f.fence.signedProofSha256, changed.writeFence?.signedProofSha256)
            assertEquals(changed, LinkConsentLedger.decode(changed.encode()))
        }
        assertEquals(f.staged, f.staged.observeGenericSnapshot())
        assertEquals(f.staged, f.staged.invalidateReviewForProfileGeneration(2))
        expectRejected("A pin change must not discard an unresolved original packet") {
            f.staged.pinOwner(
                ClientWireCrypto.PublicIdentity.parse(
                    JsonParser.parseString(f.staged.ownerPins.first().publicIdentityJson).asJsonObject,
                ),
                f.staged.ownerPins.first().ownerId,
                f.staged.ownerPins.first().fingerprint,
                true,
                Instant.parse("2026-10-02T00:00:00Z"),
            )
        }
    }

    @Test fun onlyExactAuthenticatedOriginalCorrelationCanCompleteFence() {
        val f = fixture()
        val expected = LinkConsentLedger.VerifiedOriginalCompletion(
            f.fence.operationId,
            f.fence.requestSequence,
            f.fence.expectedResponseSequence,
            f.fence.packetSha256,
            f.fence.signedProofSha256,
            f.fence.tupleDigest,
        )
        val invalid = listOf(
            expected.copy(operationId = "another-operation"),
            expected.copy(requestSequence = expected.requestSequence + 1),
            expected.copy(responseSequence = expected.responseSequence + 1),
            expected.copy(packetSha256 = "0".repeat(64)),
            expected.copy(signedProofSha256 = "0".repeat(64)),
            expected.copy(tupleDigest = "0".repeat(64)),
        )
        invalid.forEach { completion ->
            expectRejected("Mismatched terminal response correlation cleared the fence") {
                f.staged.completeOriginal(completion)
            }
        }
        val completed = f.staged.completeOriginal(expected)
        assertNull(completed.writeFence)
        assertNull(completed.review)
    }

    @Test fun activatedPairMustContainOriginalProofAndMatchEverySavedTupleDigest() {
        val f = fixture()
        val valid = LinkConsentLedger.VerifiedActivatedPair(
            linkId = f.tuple.linkId,
            linkVersion = f.tuple.linkVersion,
            contractDigest = f.tuple.contractDigest,
            manifestDigest = f.tuple.manifestDigest,
            policyDigest = null,
            policyVersion = null,
            tupleDigest = f.fence.tupleDigest,
            includedSignedProofSha256 = setOf(f.fence.signedProofSha256),
            freshResponseSequence = f.fence.expectedResponseSequence + 1,
        )
        val invalid = listOf(
            valid.copy(linkVersion = valid.linkVersion + 1),
            valid.copy(contractDigest = "0".repeat(64)),
            valid.copy(manifestDigest = "0".repeat(64)),
            valid.copy(tupleDigest = "0".repeat(64)),
            valid.copy(includedSignedProofSha256 = emptySet()),
            valid.copy(freshResponseSequence = f.fence.expectedResponseSequence),
        )
        invalid.forEach { pair ->
            expectRejected("A pair detached from the stored proof or tuple cleared the fence") {
                f.staged.resolveActivatedPair(pair)
            }
        }
        val resolved = f.staged.resolveActivatedPair(valid)
        assertNull(resolved.writeFence)
        assertNull(resolved.review)
    }

    @Test fun ledgerDecodeEnforcesTheBoundAndRejectsUnknownTopLevelFields() {
        val f = fixture()
        val baseLedger = f.staged.copy(review = null, writeFence = null)
        val nonePolicy = LinkReviewPolicyConsentPolicy("NONE", emptyList(), 0, 0, 0)
        val noneJson = LinkReviewPolicyConsentValidation.canonicalPolicyJson(nonePolicy)
        val noneTuple = f.tuple.copy(
            kind = "REVIEW_POLICY",
            source = f.tuple.source.copy(ownerKeyState = "ACTIVE", ownerKeyVersion = 2),
            expectedPolicyVersion = 0,
            policyVersion = 1,
            policyDigest = LinkReviewPolicyConsentValidation.policyDigest(nonePolicy),
            maximumProofExpiresAt = f.tuple.expiresAt,
            reviewers = emptyList(),
        )
        val baseReview = requireNotNull(f.staged.review)
        val noneReview = baseReview.copy(
            reviewId = "review_none_policy",
            consentDigest = LinkConsentLedger.digestTuple(noneTuple),
            tuple = noneTuple,
            previewRead = LinkConsentLedger.ReadCorrelation("link.review_policy_preview", "preview_none", 5, 6),
            policyJson = noneJson,
        )
        val nonePrepared = baseLedger.prepare(noneReview)
        assertEquals(nonePrepared, LinkConsentLedger.decode(nonePrepared.encode()))

        val metadataPolicy = LinkReviewPolicyConsentPolicy(
            "METADATA",
            listOf(LinkReviewPolicyConsentReviewer("reviewer_synthetic", f.tuple.source.groupId)),
            0,
            60,
            60,
        )
        val metadataTupleWithoutQualifications = noneTuple.copy(
            policyDigest = LinkReviewPolicyConsentValidation.policyDigest(metadataPolicy),
            reviewers = emptyList(),
        )
        expectRejected("METADATA policy without reviewer qualifications was accepted") {
            baseLedger.prepare(noneReview.copy(
                reviewId = "review_metadata_missing_qualifications",
                consentDigest = LinkConsentLedger.digestTuple(metadataTupleWithoutQualifications),
                tuple = metadataTupleWithoutQualifications,
                policyJson = LinkReviewPolicyConsentValidation.canonicalPolicyJson(metadataPolicy),
            ))
        }

        val roundTrip = LinkConsentLedger.decode(f.staged.encode())
        assertEquals(f.staged, roundTrip)
        expectRejected("Oversized persisted ledger was accepted") {
            LinkConsentLedger.decode(ByteArray(LinkConsentLedger.MAX_LEDGER_BYTES + 1))
        }
        val withUnknown = String(f.staged.encode(), StandardCharsets.UTF_8)
            .replaceFirst("{\"schema\":1,", "{\"unexpected\":true,\"schema\":1,")
        assertFalse(withUnknown == String(f.staged.encode(), StandardCharsets.UTF_8))
        expectRejected("Unknown persisted ledger field was accepted") {
            LinkConsentLedger.decode(withUnknown.toByteArray(StandardCharsets.UTF_8))
        }
    }

    @Test fun canonicalGoTimestampsAndLegacyJavaPendingLedgerPreserveOriginalEvidence() {
        val f = fixture()
        val sourceReview = requireNotNull(f.staged.review)
        val exactInstant = Instant.parse("2026-10-02T15:27:50.050630Z")
        val javaTimestamp = exactInstant.toString()
        val goTimestamp = GroupKeyManifestVerifier.formatCanonicalUtc(exactInstant)
        assertEquals("2026-10-02T15:27:50.050630Z", javaTimestamp)
        assertEquals("2026-10-02T15:27:50.05063Z", goTimestamp)

        val legacyPending = f.staged.copy(review = sourceReview.copy(createdAt = javaTimestamp))
        val legacyBytes = legacyPending.encode()
        val legacyRoundTrip = LinkConsentLedger.decode(legacyBytes)
        assertEquals(legacyPending, legacyRoundTrip)
        assertTrue(legacyBytes.contentEquals(legacyRoundTrip.encode()))
        val oldFence = requireNotNull(legacyRoundTrip.writeFence)
        assertEquals(f.fence.operationId, oldFence.operationId)
        assertEquals(f.fence.requestSequence, oldFence.requestSequence)
        assertEquals(f.fence.expectedResponseSequence, oldFence.expectedResponseSequence)
        assertEquals(f.fence.packetJson, oldFence.packetJson)
        assertEquals(f.fence.packetSha256, oldFence.packetSha256)
        assertEquals(f.fence.signedProofJson, oldFence.signedProofJson)
        assertEquals(f.fence.signedProofSha256, oldFence.signedProofSha256)

        val metadataPolicy = LinkReviewPolicyConsentPolicy(
            "METADATA",
            listOf(LinkReviewPolicyConsentReviewer("reviewer_synthetic", f.tuple.source.groupId)),
            0,
            60,
            60,
        )
        val metadataJson = LinkReviewPolicyConsentValidation.canonicalPolicyJson(metadataPolicy)
        val reviewer = LinkConsentLedger.ReviewerQualification(
            endpointId = "reviewer_synthetic",
            groupId = f.tuple.source.groupId,
            membershipRevision = 1,
            joinRevision = 1,
            groupVersion = 1,
            bindingId = "binding_synthetic",
            bindingEpoch = 1,
            action = "link.review",
            leaseExpiresAt = goTimestamp,
        )
        val goTuple = f.tuple.copy(
            kind = "REVIEW_POLICY",
            expiresAt = goTimestamp,
            source = f.tuple.source.copy(ownerKeyState = "ACTIVE", ownerKeyVersion = 2),
            expectedPolicyVersion = 0,
            policyVersion = 1,
            policyDigest = LinkReviewPolicyConsentValidation.policyDigest(metadataPolicy),
            maximumProofExpiresAt = goTimestamp,
            reviewers = listOf(reviewer),
        )
        val goReview = sourceReview.copy(
            reviewId = "review_go_timestamp",
            consentDigest = LinkConsentLedger.digestTuple(goTuple),
            tuple = goTuple,
            previewRead = LinkConsentLedger.ReadCorrelation("link.review_policy_preview", "preview_go_timestamp", 5, 6),
            policyJson = metadataJson,
            createdAt = goTimestamp,
        )
        val newLedger = f.staged.copy(review = null, writeFence = null).prepare(goReview)
        val newRoundTrip = LinkConsentLedger.decode(newLedger.encode())
        assertEquals(newLedger, newRoundTrip)
        assertEquals(goTimestamp, newRoundTrip.review?.createdAt)
        assertEquals(goTimestamp, newRoundTrip.review?.tuple?.expiresAt)
        assertEquals(goTimestamp, newRoundTrip.review?.tuple?.maximumProofExpiresAt)
        assertEquals(goTimestamp, newRoundTrip.review?.tuple?.reviewers?.single()?.leaseExpiresAt)

        val publicIdentity = ClientWireCrypto.PublicIdentity.parse(
            JsonParser.parseString(f.staged.ownerPins.first().publicIdentityJson).asJsonObject,
        )
        val confirmed = LinkConsentLedger.empty().pinOwner(
            publicIdentity,
            f.staged.ownerPins.first().ownerId,
            publicIdentity.fingerprint(),
            true,
            exactInstant,
        ).first
        assertEquals(goTimestamp, confirmed.ownerPins.single().confirmedAt)
        assertEquals(confirmed, LinkConsentLedger.decode(confirmed.encode()))
    }

    private fun expectRejected(message: String, block: () -> Unit) {
        var rejected = false
        try {
            block()
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(message, rejected)
    }
}
