package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonParser
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/** Independent verification of the published synthetic Endpoint proof. */
@RunWith(AndroidJUnit4::class)
class EndpointAttestationVectorTest {
    private val manifestClaims = listOf("version", "operation", "hub_id", "owner_id",
        "principal_id", "group_id", "group_revision", "endpoint_id", "node_id", "binding_id",
        "binding_epoch", "membership_revision", "endpoint_join_revision", "candidate_version",
        "candidate_key_id", "candidate_fingerprint", "candidate_proof_digest",
        "candidate_binding_digest", "candidate_public_identity", "owner_key_id", "issued_at",
        "expires_at")

    private val fixture by lazy {
        val bytes = InstrumentationRegistry.getInstrumentation().context.assets
            .open("endpoint-key-attestation-v1.json").use { it.readBytes() }
        assertEquals("735072be3d4b68fc54d50f7feb705a5adb5928214fa00348e6607c6a708d3b51",
            sha256(bytes))
        JsonParser.parseString(String(bytes, StandardCharsets.UTF_8)).asJsonObject
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it) }

    private fun manifestDigest(manifest: com.google.gson.JsonObject): String {
        val claims = com.google.gson.JsonObject().apply {
            for (field in manifestClaims) add(field, manifest.get(field).deepCopy())
        }
        val input = "cicada/group/endpoint-key-grant-manifest/v1\u0000" + claims
        return sha256(input.toByteArray(StandardCharsets.UTF_8))
    }

    private fun ownerProof(
        claims: com.google.gson.JsonObject,
        owner: ClientWireCrypto.Identity,
    ): ByteArray {
        val signed = ("cicada/communication-link/owner-key-grant/v2\u0000" + claims)
            .toByteArray(StandardCharsets.UTF_8)
        return claims.deepCopy().apply {
            addProperty("signature", Base64.getEncoder().encodeToString(owner.sign(signed)))
        }.toString().toByteArray(StandardCharsets.UTF_8)
    }

    private fun assertRejected(message: String, block: () -> Unit) {
        try {
            block()
            fail(message)
        } catch (_: IllegalArgumentException) { }
    }

    private fun verify(publicKey: ByteArray, input: ByteArray, signature: ByteArray): Boolean {
        val verifier = MLDSASigner()
        verifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, publicKey))
        verifier.update(input, 0, input.size)
        return verifier.verifySignature(signature)
    }

    @Test fun completePublishedProofUsesNullSignatureInV1SignedBytes() {
        val proof = fixture.get("attestation_utf8").asString
            .toByteArray(StandardCharsets.UTF_8)
        assertEquals(fixture.get("proof_sha256").asString, sha256(proof))
        val claim = JsonParser.parseString(String(proof, StandardCharsets.UTF_8)).asJsonObject
        assertEquals(1, claim.get("version").asInt)
        assertEquals("ep_synthetic_vector", claim.get("endpoint_id").asString)
        assertEquals("pr_synthetic_vector", claim.get("principal_id").asString)
        assertEquals("node_synthetic_vector", claim.get("node_id").asString)
        assertEquals("bind_synthetic_vector", claim.get("binding_id").asString)
        assertEquals(7L, claim.get("binding_epoch").asLong)
        val public = claim.getAsJsonObject("public_identity")
        assertEquals(fixture.getAsJsonObject("public_identity"), public)
        val kem = Base64.getDecoder().decode(public.get("kem_public").asString)
        val signing = Base64.getDecoder().decode(public.get("signing_public").asString)
        val signature = Base64.getDecoder().decode(claim.get("signature").asString)
        assertEquals(1184, kem.size)
        assertEquals(1952, signing.size)
        assertEquals(3309, signature.size)
        val keyId = "pq1-" + sha256(kem + signing).take(32)
        assertEquals(public.get("id").asString, keyId)

        // Replace only the final, base64 signature value. This verifies the
        // published bytes independently of the production canonicalizer.
        val prefix = String(proof, StandardCharsets.UTF_8).substringBeforeLast(",\"signature\":\"")
        val unsigned = ("cicada/fabric/endpoint-key-attestation/v1\u0000" +
            prefix + ",\"signature\":null}").toByteArray(StandardCharsets.UTF_8)
        val expected = fixture.get("signed_input_hex").asString
        assertEquals(expected, unsigned.joinToString("") { "%02x".format(it) })
        assertTrue(verify(signing, unsigned, signature))
        val omitted = ("cicada/fabric/endpoint-key-attestation/v1\u0000" + prefix + "}")
            .toByteArray(StandardCharsets.UTF_8)
        assertFalse(verify(signing, omitted, signature))
        val changed = unsigned.clone().also { it[it.size - 2] = '1'.code.toByte() }
        assertFalse(verify(signing, changed, signature))
        val wrongSignature = signature.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(verify(signing, unsigned, wrongSignature))
    }

    @Test fun productionProofVerifierAcceptsVectorAndRejectsChangedBindings() {
        val raw = fixture.get("attestation_utf8").asString
            .toByteArray(StandardCharsets.UTF_8)
        val public = fixture.getAsJsonObject("public_identity")
        val digest = fixture.get("proof_sha256").asString
        val accepted = GroupKeyManifestVerifier.verifyProof(raw, "ep_synthetic_vector",
            "pr_synthetic_vector", "node_synthetic_vector", "bind_synthetic_vector", 7L,
            public, digest)
        assertEquals(public.get("id").asString, accepted.id)
        for (wrongEpoch in listOf(6L, 8L)) {
            try {
                GroupKeyManifestVerifier.verifyProof(raw, "ep_synthetic_vector",
                    "pr_synthetic_vector", "node_synthetic_vector", "bind_synthetic_vector",
                    wrongEpoch, public, digest)
                fail("A stale binding epoch was accepted")
            } catch (_: IllegalArgumentException) { }
        }
        try {
            GroupKeyManifestVerifier.verifyProof(raw, "ep_other", "pr_synthetic_vector",
                "node_synthetic_vector", "bind_synthetic_vector", 7L, public, digest)
            fail("A different Endpoint ID was accepted")
        } catch (_: IllegalArgumentException) { }
        val changedProof = raw.clone().also { it[it.size - 4] = 'A'.code.toByte() }
        try {
            GroupKeyManifestVerifier.verifyProof(changedProof, "ep_synthetic_vector",
                "pr_synthetic_vector", "node_synthetic_vector", "bind_synthetic_vector",
                7L, public, sha256(changedProof))
            fail("Tampered proof was accepted with an updated digest")
        } catch (_: Exception) { }

        val proofText = String(raw, StandardCharsets.UTF_8)
        val signatureText = JsonParser.parseString(proofText).asJsonObject
            .get("signature").asString
        val noncanonicalSignature = proofText.replace(
            "\"signature\":\"$signatureText\"",
            "\"signature\":\"${signatureText}=\"",
        ).toByteArray(StandardCharsets.UTF_8)
        assertRejected("Noncanonical Endpoint signature base64 was accepted") {
            GroupKeyManifestVerifier.verifyProof(noncanonicalSignature, "ep_synthetic_vector",
                "pr_synthetic_vector", "node_synthetic_vector", "bind_synthetic_vector",
                7L, public, sha256(noncanonicalSignature))
        }

        val ignoredBase64Suffix = proofText.replace(
            "\"signature\":\"$signatureText\"",
            "\"signature\":\"${signatureText}!\"",
        ).toByteArray(StandardCharsets.UTF_8)
        assertRejected("A noncanonical Endpoint signature base64 was accepted") {
            GroupKeyManifestVerifier.verifyProof(ignoredBase64Suffix, "ep_synthetic_vector",
                "pr_synthetic_vector", "node_synthetic_vector", "bind_synthetic_vector",
                7L, public, sha256(ignoredBase64Suffix))
        }
    }

    @Test fun syntheticGroupManifestChecksRevisionsBindingAndManifestDigests() {
        val bytes = InstrumentationRegistry.getInstrumentation().context.assets
            .open("group-key-manifest-v1.json").use { it.readBytes() }
        val manifest = JsonParser.parseString(String(bytes, StandardCharsets.UTF_8)).asJsonObject
        assertEquals("735a2a0019c5987687175931bcda6cdc9b763275a0ae036c47d85299891feacf",
            manifest.get("candidate_binding_digest").asString)
        assertEquals("62e1e54970b2dfc40cfc8a792858b0757d661c66474bf4fc043eb53570f11f20",
            manifest.get("digest").asString)
        fun check(value: com.google.gson.JsonObject) = GroupKeyManifestVerifier.verifyManifest(value,
            "hub_synthetic_vector", "owner_synthetic_vector", "grp_synthetic_vector",
            "ep_synthetic_vector", "owner_key_synthetic_vector",
            Instant.parse("2026-09-25T12:00:00Z"))
        assertEquals(manifest, check(manifest))
        for (field in listOf("group_revision", "membership_revision", "endpoint_join_revision",
            "binding_epoch", "candidate_version")) {
            val changed = manifest.deepCopy()
            changed.addProperty(field, changed.get(field).asLong + 1)
            try { check(changed); fail("Changed $field was accepted") }
            catch (_: IllegalArgumentException) { }
        }
        val expired = manifest.deepCopy()
        try {
            GroupKeyManifestVerifier.verifyManifest(expired, "hub_synthetic_vector",
                "owner_synthetic_vector", "grp_synthetic_vector", "ep_synthetic_vector",
                "owner_key_synthetic_vector", Instant.parse("2026-09-26T00:00:01Z"))
            fail("Expired manifest was accepted")
        } catch (_: IllegalArgumentException) { }

        val fractionalRevision = manifest.deepCopy().apply {
            addProperty("group_revision", 3.5)
            addProperty("digest", manifestDigest(this))
        }
        assertRejected("A fractional Group revision was accepted") { check(fractionalRevision) }

        val futureIssued = manifest.deepCopy().apply {
            addProperty("issued_at", "2026-09-25T12:00:01Z")
            addProperty("digest", manifestDigest(this))
        }
        assertRejected("A future-issued Group manifest was accepted") { check(futureIssued) }

        val noncanonicalDate = manifest.deepCopy().apply {
            addProperty("issued_at", "2026-09-25T00:00:00.123400Z")
            addProperty("digest", manifestDigest(this))
        }
        assertRejected("A Group manifest timestamp with redundant fractional zero was accepted") {
            check(noncanonicalDate)
        }

        val fractionalTimestamps = manifest.deepCopy().apply {
            addProperty("issued_at", "2026-09-25T00:00:00.1234Z")
            addProperty("expires_at", "2026-09-26T00:00:00.5678Z")
            addProperty("digest", manifestDigest(this))
        }
        assertEquals(fractionalTimestamps, check(fractionalTimestamps))

        val offsetTimestamp = manifest.deepCopy().apply {
            addProperty("issued_at", "2026-09-25T01:00:00+01:00")
            addProperty("digest", manifestDigest(this))
        }
        assertRejected("A non-UTC Group manifest timestamp was accepted") { check(offsetTimestamp) }

        val noncanonicalAttestationBase64 = manifest.deepCopy().apply {
            addProperty("candidate_attestation", get("candidate_attestation").asString + "=")
        }
        assertRejected("Noncanonical Endpoint proof base64 was accepted") {
            check(noncanonicalAttestationBase64)
        }
    }

    @Test fun separateOwnerProofMustBindExactReviewedManifest() {
        val bytes = InstrumentationRegistry.getInstrumentation().context.assets
            .open("group-key-manifest-v1.json").use { it.readBytes() }
        val manifest = JsonParser.parseString(String(bytes, StandardCharsets.UTF_8)).asJsonObject
        val owner = ClientWireCrypto.Identity.generate()
        try {
            manifest.addProperty("owner_key_id", owner.publicIdentity.id)
            val claims = com.google.gson.JsonObject().apply {
                addProperty("version", 2)
                addProperty("owner_id", manifest.get("owner_id").asString)
                addProperty("link_id", "group-endpoint-key-grant:v1")
                addProperty("contract_digest", manifest.get("digest").asString)
                addProperty("key_binding_digest", manifest.get("candidate_binding_digest").asString)
                addProperty("expected_link_version", manifest.get("candidate_version").asLong)
                addProperty("side", "SOURCE")
                addProperty("issued_at", manifest.get("issued_at").asString)
                addProperty("expires_at", manifest.get("expires_at").asString)
                addProperty("nonce", "a".repeat(64))
            }
            val signed = ("cicada/communication-link/owner-key-grant/v2\u0000" + claims)
                .toByteArray(StandardCharsets.UTF_8)
            val proof = claims.deepCopy().apply {
                addProperty("signature", Base64.getEncoder().encodeToString(owner.sign(signed)))
            }.toString().toByteArray(StandardCharsets.UTF_8)
            val validNow = Instant.parse("2026-09-25T12:00:00Z")
            GroupKeyOwnerProof.verify(proof, manifest, owner.publicIdentity, validNow)
            assertRejected("A future-issued owner proof was accepted") {
                GroupKeyOwnerProof.verify(proof, manifest, owner.publicIdentity,
                    Instant.parse("2026-09-24T23:59:59Z"))
            }
            assertRejected("An owner proof accepted at its expiry") {
                GroupKeyOwnerProof.verify(proof, manifest, owner.publicIdentity,
                    Instant.parse("2026-09-26T00:00:00Z"))
            }

            val whitespaceProof = String(proof, StandardCharsets.UTF_8)
                .replace("{\"version\":2", "{ \"version\":2")
                .toByteArray(StandardCharsets.UTF_8)
            assertRejected("Noncanonical owner proof JSON was accepted") {
                GroupKeyOwnerProof.verify(whitespaceProof, manifest, owner.publicIdentity, validNow)
            }

            val noncanonicalBase64Proof = JsonParser.parseString(
                String(proof, StandardCharsets.UTF_8)).asJsonObject.apply {
                addProperty("signature", get("signature").asString + "=")
            }.toString().toByteArray(StandardCharsets.UTF_8)
            assertRejected("Noncanonical owner signature base64 was accepted") {
                GroupKeyOwnerProof.verify(noncanonicalBase64Proof, manifest,
                    owner.publicIdentity, validNow)
            }

            val fractionalManifest = manifest.deepCopy().apply {
                addProperty("issued_at", "2026-09-25T00:00:00.1234Z")
                addProperty("expires_at", "2026-09-26T00:00:00.5678Z")
                addProperty("digest", manifestDigest(this))
            }
            val fractionalClaims = claims.deepCopy().apply {
                addProperty("contract_digest", fractionalManifest.get("digest").asString)
                addProperty("issued_at", fractionalManifest.get("issued_at").asString)
                addProperty("expires_at", fractionalManifest.get("expires_at").asString)
            }
            GroupKeyOwnerProof.verify(ownerProof(fractionalClaims, owner),
                fractionalManifest, owner.publicIdentity, validNow)

            fun assertOwnerIssueTimestampRejected(timestamp: String, message: String) {
                val changedManifest = manifest.deepCopy().apply {
                    addProperty("issued_at", timestamp)
                    addProperty("digest", manifestDigest(this))
                }
                val changedClaims = claims.deepCopy().apply {
                    addProperty("contract_digest", changedManifest.get("digest").asString)
                    addProperty("issued_at", timestamp)
                }
                assertRejected(message) {
                    GroupKeyOwnerProof.verify(ownerProof(changedClaims, owner),
                        changedManifest, owner.publicIdentity, validNow)
                }
            }
            assertOwnerIssueTimestampRejected("2026-09-25T00:00:00.123400Z",
                "An owner proof timestamp with a redundant fractional zero was accepted")
            assertOwnerIssueTimestampRejected("2026-09-25T01:00:00+01:00",
                "A non-UTC owner proof timestamp was accepted")

            val fractionalVersionClaims = claims.deepCopy().apply {
                addProperty("expected_link_version", 6.5)
            }
            assertRejected("A fractional owner link version was accepted") {
                GroupKeyOwnerProof.verify(ownerProof(fractionalVersionClaims, owner),
                    manifest, owner.publicIdentity, validNow)
            }

            val changed = manifest.deepCopy().apply { addProperty("candidate_version", 7) }
            assertRejected("Changed candidate version was accepted") {
                GroupKeyOwnerProof.verify(proof, changed, owner.publicIdentity, validNow)
            }
        } finally { owner.close() }
    }
}
