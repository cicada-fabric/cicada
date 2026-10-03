package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/** Pure JVM tests: no Android context, native bridge, Hub, or signing operation. */
class LinkKeyManifestVerifierTest {
    private val validNow = Instant.parse("2026-10-02T00:00:00Z")

    private fun fixture(name: String): JsonObject {
        val loader = javaClass.classLoader
        val input = loader?.getResourceAsStream(name)
            ?: throw AssertionError("Missing public contract vector resource: $name")
        val raw = input.use { it.readBytes() }
        if (name == "endpoint-key-attestation-v1.json") {
            assertEquals(
                "735072be3d4b68fc54d50f7feb705a5adb5928214fa00348e6607c6a708d3b51",
                sha256(raw),
            )
        }
        if (name == "link-client-proof-v2.json") {
            assertEquals(
                "aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d",
                sha256(raw),
            )
        }
        return JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
    }

    private fun endpointCandidate(): Pair<JsonObject, LinkKeyManifestVerifier.CurrentEndpointAuthority> {
        val vector = fixture("endpoint-key-attestation-v1.json")
        val rawProof = vector.get("attestation_utf8").asString.toByteArray(StandardCharsets.UTF_8)
        val proof = JsonParser.parseString(String(rawProof, StandardCharsets.UTF_8)).asJsonObject
        val publicJson = vector.getAsJsonObject("public_identity")
        val kem = Base64.getDecoder().decode(publicJson.get("kem_public").asString)
        val signing = Base64.getDecoder().decode(publicJson.get("signing_public").asString)
        val fingerprint = "sha256:" + sha256(
            "cicada/nodekeys/peer-key-fingerprint/v1\u0000".toByteArray(StandardCharsets.UTF_8) +
                kem + signing,
        )
        val scope = LinkKeyManifestVerifier.CurrentEndpointAuthority(
            endpointId = proof.get("endpoint_id").asString,
            groupId = "grp_vector_source",
            principalId = proof.get("principal_id").asString,
            ownerId = "owner_vector",
            nodeId = proof.get("node_id").asString,
            bindingId = proof.get("binding_id").asString,
            bindingEpoch = proof.get("binding_epoch").asLong,
            candidateVersion = 5,
            membershipRevision = 3,
            joinRevision = 4,
            groupVersion = 2,
        )
        val side = JsonObject().apply {
            addProperty("endpoint_id", scope.endpointId)
            addProperty("group_id", scope.groupId)
            addProperty("principal_id", scope.principalId)
            addProperty("owner_id", scope.ownerId)
            addProperty("node_id", scope.nodeId)
            addProperty("binding_id", scope.bindingId)
            addProperty("binding_epoch", scope.bindingEpoch)
            addProperty("candidate_version", scope.candidateVersion)
            addProperty("key_id", publicJson.get("id").asString)
            addProperty("key_fingerprint", fingerprint)
            addProperty("proof_digest", vector.get("proof_sha256").asString)
            add("public_identity", publicJson.deepCopy())
            addProperty("attestation", Base64.getEncoder().encodeToString(rawProof))
        }
        return side to scope
    }

    @Test fun completePublishedEndpointVectorIsReusedForSideCandidateVerification() {
        val (candidate, expected) = endpointCandidate()
        val verified = LinkKeyManifestVerifier.verifyEndpointCandidate(candidate, expected)
        assertEquals(expected.endpointId, verified.endpointId)
        assertEquals(expected.groupId, verified.groupId)
        assertEquals("pq1-f75d1b3a30a2c8c04939056893dd4c8b", verified.publicIdentity.id)
        val expectedPeerFingerprint = "sha256:" + sha256(
            "cicada/nodekeys/peer-key-fingerprint/v1\u0000".toByteArray(StandardCharsets.UTF_8) +
                verified.publicIdentity.kemPublic + verified.publicIdentity.signingPublic,
        )
        assertEquals(expectedPeerFingerprint, verified.keyFingerprint)
        assertNotEquals("sha256:${verified.publicIdentity.fingerprint()}", verified.keyFingerprint)

        val staleEpoch = candidate.deepCopy().apply {
            addProperty("binding_epoch", expected.bindingEpoch + 1)
        }
        assertRejected("A candidate with a stale binding epoch was accepted") {
            LinkKeyManifestVerifier.verifyEndpointCandidate(staleEpoch, expected)
        }

        val staleVersion = candidate.deepCopy().apply {
            addProperty("candidate_version", expected.candidateVersion + 1)
        }
        assertRejected("A candidate version outside fresh authority was accepted") {
            LinkKeyManifestVerifier.verifyEndpointCandidate(staleVersion, expected)
        }

        val changedProofDigest = candidate.deepCopy().apply {
            addProperty("proof_digest", "0".repeat(64))
        }
        assertRejected("A changed Endpoint proof digest was accepted") {
            LinkKeyManifestVerifier.verifyEndpointCandidate(changedProofDigest, expected)
        }

        val changedFingerprint = candidate.deepCopy().apply {
            addProperty("key_fingerprint", "sha256:" + "0".repeat(64))
        }
        assertRejected("A changed Endpoint public-key fingerprint was accepted") {
            LinkKeyManifestVerifier.verifyEndpointCandidate(changedFingerprint, expected)
        }

        val changedAttestation = candidate.deepCopy().apply {
            val raw = Base64.getDecoder().decode(get("attestation").asString)
            raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte()
            addProperty("attestation", Base64.getEncoder().encodeToString(raw))
        }
        assertRejected("A changed full Endpoint attestation was accepted") {
            LinkKeyManifestVerifier.verifyEndpointCandidate(changedAttestation, expected)
        }

        val reordered = JsonObject().apply {
            add("group_id", candidate.get("group_id").deepCopy())
            candidate.entrySet().filter { it.key != "group_id" }.forEach {
                add(it.key, it.value.deepCopy())
            }
        }
        assertRejected("A reordered Link candidate DTO was accepted") {
            LinkKeyManifestVerifier.verifyEndpointCandidate(reordered, expected)
        }
    }

    @Test fun contractDigestUsesGoHtmlAndUnicodeLineSeparatorEscapes() {
        val authority = currentLink(dataScopes = listOf("scope<&>\"\\\u2028\u2029"))
        val actual = LinkKeyManifestVerifier.contractDigestForAuthority(authority, validNow)
        val canonical = """{"link_id":"link_test","source_endpoint_id":"ep_source","source_principal_id":"pr_source","source_group_id":"grp_source","source_owner_id":"owner_test","source_node_id":"node_source","target_endpoint_id":"ep_target","target_principal_id":"pr_target","target_group_id":"grp_target","target_owner_id":"owner_test","target_node_id":"node_target","direction":"forward","actions":["ask","reply"],"data_scopes":["scope\u003c\u0026\u003e\"\\\u2028\u2029"],"transport_hub_id":"","expires_at":"2026-10-10T00:00:00Z","scope_snapshot":{"source_membership_revision":2,"source_join_revision":3,"source_group_version":4,"target_membership_revision":5,"target_join_revision":6,"target_group_version":7}}"""
        val expected = sha256(
            "cicada/communication-link/proposal/v1\u0000".toByteArray(StandardCharsets.UTF_8) +
                canonical.toByteArray(StandardCharsets.UTF_8),
        )
        assertEquals(expected, actual)

        val unescaped = canonical
            .replace("\\u003c", "<")
            .replace("\\u0026", "&")
            .replace("\\u003e", ">")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
            .replace("\\u2028", "\u2028")
            .replace("\\u2029", "\u2029")
        assertNotEquals(
            sha256(
                "cicada/communication-link/proposal/v1\u0000".toByteArray(StandardCharsets.UTF_8) +
                    unescaped.toByteArray(StandardCharsets.UTF_8),
            ),
            actual,
        )
    }

    @Test fun manifestLinkVersionAndContractAreCheckedAgainstIndependentAuthority() {
        val current = currentLink()
        val staleVersion = manifestShell(current).apply {
            addProperty("link_version", current.linkVersion + 1)
        }
        assertRejected("A Link manifest for another version was accepted") {
            LinkKeyManifestVerifier.verifyManifest(staleVersion, current, validNow)
        }

        val noContractBytes = manifestShell(current)
        assertRejected("A candidate supplied its own missing contract authority") {
            LinkKeyManifestVerifier.verifyManifest(noContractBytes, current, validNow)
        }

        val reordered = JsonObject().apply {
            add("link_version", noContractBytes.get("link_version").deepCopy())
            noContractBytes.entrySet().filter { it.key != "link_version" }.forEach {
                add(it.key, it.value.deepCopy())
            }
        }
        assertRejected("A reordered Link manifest DTO was accepted") {
            LinkKeyManifestVerifier.verifyManifest(reordered, current, validNow)
        }
    }

    @Test fun completeSyntheticBilateralVectorVerifiesManifestAndRetainedOwnerProofs() {
        val vector = fixture("link-client-proof-v2.json")
        assertEquals(true, vector.get("synthetic").asBoolean)
        val manifestJson = vector.getAsJsonObject("manifest")
        val current = currentLinkFromVector(manifestJson)
        val statuses = vector.getAsJsonArray("statuses").map { it.asJsonObject }
        val sourceKey = trustedOwnerKey(statuses.single { it.get("side").asString == "SOURCE" })
        val targetKey = trustedOwnerKey(statuses.single { it.get("side").asString == "TARGET" })
        val now = Instant.parse(vector.get("verification_time").asString)

        val manifest = LinkKeyManifestVerifier.verifyManifest(manifestJson, current, now)
        assertEquals("link_0c6c419b83c1f01e", manifest.linkId)
        assertEquals("fa4c7eb08449f983303bec0c568da20b6b490805b2526d9576827de1dfcf63de", manifest.digest)
        assertEquals(current.source.ownerId, sourceKey.ownerId)
        assertEquals(current.target.ownerId, targetKey.ownerId)

        val verified = LinkKeyManifestVerifier.verifyRetainedOwnerConsentsCandidateV163(
            manifestJson = manifestJson,
            statuses = statuses,
            currentLink = current,
            trustedSourceOwnerKey = sourceKey,
            trustedTargetOwnerKey = targetKey,
            now = now,
        )
        assertEquals("link_0c6c419b83c1f01e", verified.linkId)
        assertEquals(manifest.digest, verified.manifestDigest)
        assertEquals("SOURCE", verified.source.side)
        assertEquals("TARGET", verified.target.side)
        assertEquals(sourceKey.keyId, verified.source.ownerKeyId)
        assertEquals(targetKey.keyId, verified.target.ownerKeyId)
        assertEquals(false, LinkKeyManifestVerifier.RETAINED_LINK_PROOF_CANDIDATE_READY)
    }

    @Test fun retainedProofEvidenceFailsClosedOnRaceTrustAndStatusMutations() {
        val vector = fixture("link-client-proof-v2.json")
        val manifestJson = vector.getAsJsonObject("manifest")
        val current = currentLinkFromVector(manifestJson)
        val statuses = vector.getAsJsonArray("statuses").map { it.asJsonObject }
        val sourceKey = trustedOwnerKey(statuses.single { it.get("side").asString == "SOURCE" })
        val targetKey = trustedOwnerKey(statuses.single { it.get("side").asString == "TARGET" })
        val now = Instant.parse(vector.get("verification_time").asString)

        val statusWithoutEvidence = statuses.mapIndexed { index, status ->
            status.deepCopy().apply { if (index == 1) remove("evidence") }
        }
        assertRetainedRejected("A historical accepted status without current proof was accepted") {
            verifyRetainedCandidate(manifestJson, statusWithoutEvidence, current, sourceKey, targetKey, now)
        }

        val invalidCurrentState = statuses.map { it.deepCopy() }.toMutableList().apply {
            this[0].addProperty("current_status", "KEY_BINDING_STALE")
        }
        assertRetainedRejected("accepted=true overrode a stale current status") {
            verifyRetainedCandidate(manifestJson, invalidCurrentState, current, sourceKey, targetKey, now)
        }

        val changedManifestDigest = statuses.map { it.deepCopy() }.toMutableList().apply {
            this[0].getAsJsonObject("evidence").addProperty("manifest_digest", "0".repeat(64))
        }
        assertRetainedRejected("Evidence for a different manifest was accepted") {
            verifyRetainedCandidate(manifestJson, changedManifestDigest, current, sourceKey, targetKey, now)
        }

        val changedLinkVersion = statuses.mapIndexed { index, status ->
            status.deepCopy().apply {
                if (index == 1) getAsJsonObject("evidence").addProperty("link_version", 2)
            }
        }
        assertRetainedRejected("Evidence for another Link version was accepted") {
            verifyRetainedCandidate(manifestJson, changedLinkVersion, current, sourceKey, targetKey, now)
        }

        val raceBetweenStatusSnapshots = statuses.map { it.deepCopy() }.toMutableList().apply {
            this[1].getAsJsonObject("evidence").addProperty("verified_at", "2026-10-02T04:39:19.524412943Z")
        }
        assertRetainedRejected("Statuses from different current snapshots were combined") {
            verifyRetainedCandidate(manifestJson, raceBetweenStatusSnapshots, current, sourceKey, targetKey, now)
        }

        val hubKeyIsNotTrust = statuses.map { it.deepCopy() }.toMutableList().apply {
            this[1].getAsJsonObject("evidence")
                .add("owner_public_identity", this[0].getAsJsonObject("evidence")
                    .get("owner_public_identity").deepCopy())
        }
        assertRetainedRejected("The Hub-provided Owner key bypassed the independent pin") {
            verifyRetainedCandidate(manifestJson, hubKeyIsNotTrust, current, sourceKey, targetKey, now)
        }

        assertRetainedRejected("A stale independent Owner key version was accepted") {
            verifyRetainedCandidate(
                manifestJson, statuses, current, sourceKey,
                targetKey.copy(version = targetKey.version + 1), now,
            )
        }

        val tamperedGrant = statuses.map { it.deepCopy() }.toMutableList().apply {
            val evidence = this[0].getAsJsonObject("evidence")
            val raw = Base64.getDecoder().decode(evidence.get("signed_proof").asString)
            raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte()
            evidence.addProperty("signed_proof", Base64.getEncoder().encodeToString(raw))
        }
        assertRetainedRejected("A tampered retained OwnerLinkKeyGrant was accepted") {
            verifyRetainedCandidate(manifestJson, tamperedGrant, current, sourceKey, targetKey, now)
        }
    }

    @Test fun publishedOwnerGrantStatusVectorHasStableSanitizedVerificationFailures() {
        val vector = fixture("link-client-proof-v2.json")
        val manifestJson = vector.getAsJsonObject("manifest")
        val current = currentLinkFromVector(manifestJson)
        val statuses = vector.getAsJsonArray("statuses").map { it.asJsonObject }
        val sourceStatus = statuses.single { it.get("side").asString == "SOURCE" }
        val targetStatus = statuses.single { it.get("side").asString == "TARGET" }
        val sourceKey = trustedOwnerKey(sourceStatus)
        val targetKey = trustedOwnerKey(targetStatus)
        val sourcePin = LinkKeyManifestVerifier.OwnerPublicKeyPin(
            ownerId = sourceKey.ownerId,
            keyId = sourceKey.keyId,
            publicIdentity = sourceKey.publicIdentity,
        )
        val now = Instant.parse(vector.get("verification_time").asString)

        fun verify(
            status: JsonObject = sourceStatus.deepCopy(),
            pin: LinkKeyManifestVerifier.OwnerPublicKeyPin = sourcePin,
            at: Instant = now,
        ) = LinkKeyManifestVerifier.verifyRetainedOwnerGrantStatusCandidateV164(
            manifestJson = manifestJson.deepCopy(),
            status = status,
            currentLink = current,
            trustedOwnerPin = pin,
            side = "SOURCE",
            now = at,
        )

        val accepted = verify()
        assertEquals("SOURCE", accepted?.ownerGrant?.side)
        assertEquals(sourceKey.keyId, accepted?.currentOwnerKey?.keyId)

        val futureAcceptance = sourceStatus.deepCopy().apply {
            addProperty("accepted_at", now.plusNanos(1).toString())
        }
        assertOwnerGrantFailure(LinkOwnerGrantVerificationReason.ACCEPTED_AT_IN_FUTURE) {
            verify(futureAcceptance)
        }

        val futureEvidence = sourceStatus.deepCopy().apply {
            getAsJsonObject("evidence").addProperty("verified_at", now.plusNanos(1).toString())
        }
        assertOwnerGrantFailure(LinkOwnerGrantVerificationReason.VERIFIED_AT_IN_FUTURE) {
            verify(futureEvidence)
        }

        val wrongPin = LinkKeyManifestVerifier.OwnerPublicKeyPin(
            ownerId = sourceKey.ownerId,
            keyId = sourceKey.keyId,
            publicIdentity = targetKey.publicIdentity,
        )
        assertOwnerGrantFailure(LinkOwnerGrantVerificationReason.OWNER_PIN_MISMATCH) {
            verify(pin = wrongPin)
        }

        val tamperedProof = sourceStatus.deepCopy().apply {
            val evidence = getAsJsonObject("evidence")
            val proof = Base64.getDecoder().decode(evidence.get("signed_proof").asString)
            proof[proof.lastIndex] = (proof.last().toInt() xor 1).toByte()
            evidence.addProperty("signed_proof", Base64.getEncoder().encodeToString(proof))
        }
        assertSafeOwnerGrantFailure { verify(tamperedProof) }

        val proofJson = JsonParser.parseString(
            String(
                Base64.getDecoder().decode(
                    sourceStatus.getAsJsonObject("evidence").get("signed_proof").asString,
                ),
                StandardCharsets.UTF_8,
            ),
        ).asJsonObject
        val afterExpiry = Instant.parse(proofJson.get("expires_at").asString).plusNanos(1)
        assertSafeOwnerGrantFailure { verify(at = afterExpiry) }

        val secretMarker = "synthetic-private-error-marker"
        val unknown = LinkOwnerGrantVerificationFailure.from(IllegalStateException(secretMarker))
        assertEquals(LinkOwnerGrantVerificationReason.UNKNOWN, unknown.reason)
        assertEquals("LOCAL_LINK_OWNER_GRANT_VERIFICATION:UNKNOWN", unknown.message)
        assertEquals(null, unknown.cause)
        assertEquals(false, unknown.message.orEmpty().contains(secretMarker))
    }

    @Test fun ownerGrantVerifierRejectsOversizedInputBeforeAnyAuthorityCanBeTrusted() {
        val (candidate, _) = endpointCandidate()
        val publicIdentity = ClientWireCrypto.PublicIdentity.parse(
            candidate.getAsJsonObject("public_identity"),
        )
        val owner = LinkKeyManifestVerifier.CurrentOwnerKeyAuthority(
            ownerId = "owner_test",
            keyId = publicIdentity.id,
            publicIdentity = publicIdentity,
            state = "ACTIVE",
            version = 1,
        )
        assertRejected("An oversized OwnerLinkKeyGrant was accepted") {
            LinkKeyManifestVerifier.verifyOwnerGrant(
                rawProof = ByteArray(16 * 1024 + 1),
                currentOwnerKey = owner,
                currentLink = currentLink(),
                manifestJson = JsonObject(),
                side = "SOURCE",
                now = validNow,
            )
        }
    }

    @Test fun ownerReviewSignatureCannotBeReusedAsAnOwnerLinkKeyGrant() {
        val ownerVector = fixture("owner-link-review-policy-proof-v1.json")
        val ownerProof = JsonParser.parseString(ownerVector.get("proof_json").asString).asJsonObject
        val publicIdentity = ClientWireCrypto.PublicIdentity.parse(
            ownerVector.getAsJsonObject("owner_public_identity"),
        )
        val ownerKey = LinkKeyManifestVerifier.CurrentOwnerKeyAuthority(
            ownerId = ownerProof.get("owner_id").asString,
            keyId = publicIdentity.id,
            publicIdentity = publicIdentity,
            state = "ACTIVE",
            version = 1,
        )
        val grantAuthority = LinkKeyManifestVerifier.CurrentOwnerGrantAuthority(
            currentOwnerKey = ownerKey,
            ownerId = ownerProof.get("owner_id").asString,
            linkId = ownerProof.get("link_id").asString,
            contractDigest = ownerProof.get("contract_digest").asString,
            manifestDigest = "a".repeat(64),
            linkVersion = ownerProof.get("expected_link_version").asLong,
            side = ownerProof.get("side").asString,
            linkExpiresAt = Instant.parse("2026-10-01T15:00:00Z"),
        )
        val proof = ownerLinkKeyGrant(
            authority = grantAuthority,
            issuedAt = ownerProof.get("issued_at").asString,
            expiresAt = ownerProof.get("expires_at").asString,
            nonce = ownerProof.get("nonce").asString,
            signature = ownerVector.get("signature_base64").asString,
        )
        val now = Instant.parse("2026-10-01T13:00:00Z")
        assertRejected("A review-policy signature was reused across Owner grant purposes") {
            LinkKeyManifestVerifier.verifyOwnerGrantEvidence(proof, grantAuthority, now)
        }

        val wrongSide = JsonParser.parseString(String(proof, StandardCharsets.UTF_8)).asJsonObject.apply {
            addProperty("side", "TARGET")
        }.toString().toByteArray(StandardCharsets.UTF_8)
        assertRejected("A proof for the other Link side was accepted") {
            LinkKeyManifestVerifier.verifyOwnerGrantEvidence(wrongSide, grantAuthority, now)
        }

        val wrongManifest = JsonParser.parseString(String(proof, StandardCharsets.UTF_8)).asJsonObject.apply {
            addProperty("key_binding_digest", "b".repeat(64))
        }.toString().toByteArray(StandardCharsets.UTF_8)
        assertRejected("A proof for another Link key manifest was accepted") {
            LinkKeyManifestVerifier.verifyOwnerGrantEvidence(wrongManifest, grantAuthority, now)
        }

        val noncanonicalTime = JsonParser.parseString(String(proof, StandardCharsets.UTF_8)).asJsonObject.apply {
            addProperty("issued_at", "2026-10-01T12:00:00.000Z")
        }.toString().toByteArray(StandardCharsets.UTF_8)
        assertRejected("A noncanonical OwnerLinkKeyGrant timestamp was accepted") {
            LinkKeyManifestVerifier.verifyOwnerGrantEvidence(noncanonicalTime, grantAuthority, now)
        }
    }

    private fun currentLink(
        dataScopes: List<String> = listOf("thread.message"),
    ) = LinkKeyManifestVerifier.CurrentLinkAuthority(
        linkId = "link_test",
        linkVersion = 4,
        state = "PROPOSED",
        direction = "forward",
        actions = listOf("ask", "reply"),
        dataScopes = dataScopes,
        transportHubId = "",
        expiresAt = "2026-10-10T00:00:00Z",
        source = endpointScope("ep_source", "grp_source", "pr_source", "node_source", 2, 3, 4),
        target = endpointScope("ep_target", "grp_target", "pr_target", "node_target", 5, 6, 7),
    )

    private fun currentLinkFromVector(
        manifest: JsonObject,
    ): LinkKeyManifestVerifier.CurrentLinkAuthority {
        val contractRaw = Base64.getDecoder().decode(manifest.get("contract_canonical").asString)
        val contract = JsonParser.parseString(String(contractRaw, StandardCharsets.UTF_8)).asJsonObject
        val snapshot = contract.getAsJsonObject("scope_snapshot")

        fun endpoint(prefix: String, side: JsonObject) =
            LinkKeyManifestVerifier.CurrentEndpointAuthority(
                endpointId = contract.get("${prefix}_endpoint_id").asString,
                groupId = contract.get("${prefix}_group_id").asString,
                principalId = contract.get("${prefix}_principal_id").asString,
                ownerId = contract.get("${prefix}_owner_id").asString,
                nodeId = contract.get("${prefix}_node_id").asString,
                bindingId = side.get("binding_id").asString,
                bindingEpoch = side.get("binding_epoch").asLong,
                candidateVersion = side.get("candidate_version").asLong,
                membershipRevision = snapshot.get("${prefix}_membership_revision").asLong,
                joinRevision = snapshot.get("${prefix}_join_revision").asLong,
                groupVersion = snapshot.get("${prefix}_group_version").asLong,
            )

        val source = manifest.getAsJsonObject("source")
        val target = manifest.getAsJsonObject("target")
        return LinkKeyManifestVerifier.CurrentLinkAuthority(
            linkId = contract.get("link_id").asString,
            linkVersion = manifest.get("link_version").asLong,
            state = "PROPOSED",
            direction = contract.get("direction").asString,
            actions = contract.getAsJsonArray("actions").map { it.asString },
            dataScopes = contract.getAsJsonArray("data_scopes").map { it.asString },
            transportHubId = contract.get("transport_hub_id").asString,
            expiresAt = contract.get("expires_at").asString,
            source = endpoint("source", source),
            target = endpoint("target", target),
        )
    }

    private fun trustedOwnerKey(
        status: JsonObject,
    ): LinkKeyManifestVerifier.CurrentOwnerKeyAuthority {
        val evidence = status.getAsJsonObject("evidence")
        val identity = ClientWireCrypto.PublicIdentity.parse(
            evidence.getAsJsonObject("owner_public_identity"),
        )
        return LinkKeyManifestVerifier.CurrentOwnerKeyAuthority(
            ownerId = status.get("owner_id").asString,
            keyId = evidence.get("owner_key_id").asString,
            publicIdentity = identity,
            state = evidence.get("owner_key_state").asString,
            version = evidence.get("owner_key_version").asLong,
        )
    }

    private fun verifyRetainedCandidate(
        manifest: JsonObject,
        statuses: List<JsonObject>,
        current: LinkKeyManifestVerifier.CurrentLinkAuthority,
        sourceKey: LinkKeyManifestVerifier.CurrentOwnerKeyAuthority,
        targetKey: LinkKeyManifestVerifier.CurrentOwnerKeyAuthority,
        now: Instant,
    ) = LinkKeyManifestVerifier.verifyRetainedOwnerConsentsCandidateV163(
        manifestJson = manifest,
        statuses = statuses,
        currentLink = current,
        trustedSourceOwnerKey = sourceKey,
        trustedTargetOwnerKey = targetKey,
        now = now,
    )

    private fun endpointScope(
        endpointId: String,
        groupId: String,
        principalId: String,
        nodeId: String,
        membershipRevision: Long,
        joinRevision: Long,
        groupVersion: Long,
    ) = LinkKeyManifestVerifier.CurrentEndpointAuthority(
        endpointId = endpointId,
        groupId = groupId,
        principalId = principalId,
        ownerId = "owner_test",
        nodeId = nodeId,
        bindingId = "bind_$endpointId",
        bindingEpoch = 1,
        candidateVersion = 2,
        membershipRevision = membershipRevision,
        joinRevision = joinRevision,
        groupVersion = groupVersion,
    )

    private fun manifestShell(current: LinkKeyManifestVerifier.CurrentLinkAuthority) = JsonObject().apply {
        addProperty("version", 2)
        addProperty("link_id", current.linkId)
        addProperty("link_version", current.linkVersion)
        addProperty("contract_digest", "0".repeat(64))
        addProperty("contract_canonical", "")
        add("source", JsonObject())
        add("target", JsonObject())
        addProperty("digest", "0".repeat(64))
    }

    private fun ownerLinkKeyGrant(
        authority: LinkKeyManifestVerifier.CurrentOwnerGrantAuthority,
        issuedAt: String,
        expiresAt: String,
        nonce: String,
        signature: String,
    ): ByteArray = JsonObject().apply {
        addProperty("version", 2)
        addProperty("owner_id", authority.ownerId)
        addProperty("link_id", authority.linkId)
        addProperty("contract_digest", authority.contractDigest)
        addProperty("key_binding_digest", authority.manifestDigest)
        addProperty("expected_link_version", authority.linkVersion)
        addProperty("side", authority.side)
        addProperty("issued_at", issuedAt)
        addProperty("expires_at", expiresAt)
        addProperty("nonce", nonce)
        addProperty("signature", signature)
    }.toString().toByteArray(StandardCharsets.UTF_8)

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun assertRejected(message: String, block: () -> Unit) {
        try {
            block()
            fail(message)
        } catch (_: Exception) {
            // Expected malformed, stale, noncanonical, or unauthenticated input.
        }
    }

    private fun assertRetainedRejected(message: String, block: () -> Unit) =
        assertRejected(message, block)

    private fun assertOwnerGrantFailure(
        expected: LinkOwnerGrantVerificationReason,
        block: () -> Unit,
    ) {
        try {
            block()
            fail("Owner grant verification unexpectedly succeeded: $expected")
        } catch (error: IllegalArgumentException) {
            val failure = LinkOwnerGrantVerificationFailure.from(error)
            assertEquals(expected, failure.reason)
            assertEquals("LOCAL_LINK_OWNER_GRANT_VERIFICATION:${expected.name}", failure.message)
            assertEquals(null, failure.cause)
        }
    }

    private fun assertSafeOwnerGrantFailure(block: () -> Unit) {
        try {
            block()
            fail("Owner grant verification unexpectedly succeeded")
        } catch (error: IllegalArgumentException) {
            val failure = LinkOwnerGrantVerificationFailure.from(error)
            assertEquals("LOCAL_LINK_OWNER_GRANT_VERIFICATION:${failure.reason.name}", failure.message)
            assertEquals(null, failure.cause)
        }
    }
}
