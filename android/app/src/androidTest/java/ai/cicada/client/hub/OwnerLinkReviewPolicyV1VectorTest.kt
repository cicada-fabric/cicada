package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
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

/** Independent Kotlin checks for the pinned clean v1.6.1 public Policy vector. */
@RunWith(AndroidJUnit4::class)
class OwnerLinkReviewPolicyV1VectorTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val validAt = Instant.parse("2026-10-01T13:00:00Z")
    private val vectorBytes by lazy {
        instrumentation.context.assets.open("owner-link-review-policy-proof-v1.json").use { it.readBytes() }
    }
    private val vector by lazy {
        assertEquals(
            "aab0a7074fb32523f75bb89f9a61f4725d9f462c2d83eec33d23f79609fc5907",
            sha256(vectorBytes),
        )
        JsonParser.parseString(String(vectorBytes, StandardCharsets.UTF_8)).asJsonObject.also {
            assertEquals(1, it.get("fixture_version").asInt)
            assertTrue(it.get("synthetic_only").asBoolean)
            assertEquals("ML-DSA-65", it.get("algorithm").asString)
            assertEquals("PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT",
                it.get("warning").asString)
        }
    }
    private val proofRaw by lazy { vector.get("proof_json").asString.toByteArray(StandardCharsets.UTF_8) }
    private val proof by lazy { JsonParser.parseString(String(proofRaw, StandardCharsets.UTF_8)).asJsonObject }
    private val owner by lazy {
        ClientWireCrypto.PublicIdentity.parse(vector.getAsJsonObject("owner_public_identity"))
    }

    private fun expected(proofJson: JsonObject = proof): OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority =
        OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority(
            ownerId = proofJson.get("owner_id").asString,
            linkId = proofJson.get("link_id").asString,
            contractDigest = proofJson.get("contract_digest").asString,
            policyDigest = proofJson.get("policy_digest").asString,
            expectedLinkVersion = proofJson.get("expected_link_version").asLong,
            policyVersion = proofJson.get("policy_version").asLong,
            side = proofJson.get("side").asString,
        )

    @Test fun publishedVectorReproducesElevenClaimsAndVerifiesCompleteOwnerKey() {
        val claimsOrder = listOf(
            "version", "owner_id", "link_id", "contract_digest", "policy_digest",
            "expected_link_version", "policy_version", "side", "issued_at", "expires_at", "nonce",
        )
        assertEquals(claimsOrder, vector.getAsJsonArray("claims_field_order").map { it.asString })
        assertEquals(listOf(
            "version", "owner_id", "link_id", "contract_digest", "policy_digest",
            "expected_link_version", "policy_version", "side", "issued_at", "expires_at",
            "nonce", "signature",
        ), proof.keySet().toList())
        assertEquals(String(proofRaw, StandardCharsets.UTF_8), proof.toString())

        val claims = JsonObject()
        for (field in claimsOrder) claims.add(field, proof.get(field).deepCopy())
        assertFalse("Policy's signed claims exclude signature", claims.has("signature"))
        val unsignedJson = claims.toString()
        assertEquals(vector.get("canonical_unsigned_json").asString, unsignedJson)
        assertEquals(claimsOrder, JsonParser.parseString(unsignedJson).asJsonObject.keySet().toList())

        val domain = "cicada/communication-link/review-policy-owner-approval/v1\u0000"
        val signed = domain.toByteArray(StandardCharsets.UTF_8) + unsignedJson.toByteArray(StandardCharsets.UTF_8)
        assertEquals("cicada/communication-link/review-policy-owner-approval/v1\\x00",
            vector.get("signing_domain").asString)
        assertEquals("6369636164612f636f6d6d756e69636174696f6e2d6c696e6b2f7265766965772d706f6c6963792d6f776e65722d617070726f76616c2f763100",
            vector.get("signing_domain_hex").asString)
        assertArrayEquals(Base64.getDecoder().decode(vector.get("signed_bytes_base64").asString), signed)
        assertArrayEquals(hexBytes(vector.get("signed_bytes_hex").asString), signed)
        assertEquals(vector.get("signed_bytes_sha256").asString, sha256(signed))

        val signature = Base64.getDecoder().decode(proof.get("signature").asString)
        assertArrayEquals(Base64.getDecoder().decode(vector.get("signature_base64").asString), signature)
        assertEquals(3309, signature.size)
        assertEquals(vector.get("proof_sha256").asString, sha256(proofRaw))

        val public = vector.getAsJsonObject("owner_public_identity")
        assertEquals("pq1-25b8988dba616337fd7c4d5edea0a356", owner.id)
        val kemPublic = Base64.getDecoder().decode(public.get("kem_public").asString)
        val signingPublic = Base64.getDecoder().decode(public.get("signing_public").asString)
        assertEquals(1184, kemPublic.size)
        assertEquals(1952, signingPublic.size)
        assertArrayEquals(signingPublic, Base64.getDecoder().decode(vector.get("mldsa_public_key_base64").asString))
        owner.validate()
        assertTrue(ClientWireCrypto.verify(owner, signed, signature))

        val checked = OwnerLinkReviewPolicyV1Verifier.verify(proofRaw, owner, expected(), validAt)
        assertEquals(expected().ownerId, checked.ownerId)
        assertEquals(expected().linkId, checked.linkId)
        assertEquals(7L, checked.expectedLinkVersion)
        assertEquals(3L, checked.policyVersion)
        assertEquals("SOURCE", checked.side)
        assertEquals(Instant.parse("2026-10-01T14:00:00Z"), checked.expiresAt)
    }

    @Test fun policyProofRejectsWrongOwnerLinkPolicyRevisionSideAndExpiry() {
        val authority = expected()
        val changed = listOf(
            authority.copy(ownerId = "owner_synthetic_other"),
            authority.copy(linkId = "link_synthetic_other"),
            authority.copy(contractDigest = "0".repeat(64)),
            authority.copy(policyDigest = "0".repeat(64)),
            authority.copy(expectedLinkVersion = authority.expectedLinkVersion + 1),
            authority.copy(policyVersion = authority.policyVersion + 1),
            authority.copy(side = "TARGET"),
        )
        changed.forEachIndexed { index, other ->
            assertRejected("Policy authority mutation $index was accepted", owner, other, validAt)
        }
        assertRejected("Proof issued in the future was accepted", owner, authority,
            Instant.parse("2026-10-01T11:59:59Z"))
        assertRejected("Proof accepted at expiry was accepted", owner, authority,
            Instant.parse("2026-10-01T14:00:00Z"))
    }

    @Test fun policyProofRejectsOtherKeyWrongPurposeAndTamperedOrReorderedBytes() {
        val otherVector = loadBroadcastVector()
        val otherOwner = ClientWireCrypto.PublicIdentity.parse(otherVector.getAsJsonObject("owner_public_identity"))
        assertRejected("Policy proof verified under a different Owner key", otherOwner, expected(), validAt)

        val signedClaims = JsonParser.parseString(vector.get("canonical_unsigned_json").asString).asJsonObject
        val wrongPurposeBytes = "cicada/communication-link/owner-key-grant/v2\u0000".toByteArray(
            StandardCharsets.UTF_8,
        ) + signedClaims.toString().toByteArray(StandardCharsets.UTF_8)
        assertFalse("Policy proof verified under another proof purpose",
            ClientWireCrypto.verify(owner, wrongPurposeBytes, Base64.getDecoder().decode(proof.get("signature").asString)))

        val changedClaim = proof.deepCopy().apply { addProperty("policy_digest", "0".repeat(64)) }
        assertRejected("Changed policy claim accepted", owner, expected(changedClaim), validAt, bytes(changedClaim))

        val changedSignature = proof.deepCopy()
        val badSignature = Base64.getDecoder().decode(changedSignature.get("signature").asString)
        badSignature[0] = (badSignature[0].toInt() xor 1).toByte()
        changedSignature.addProperty("signature", Base64.getEncoder().encodeToString(badSignature))
        assertRejected("Changed ML-DSA signature accepted", owner, expected(), validAt, bytes(changedSignature))

        val reversed = JsonObject()
        proof.keySet().toList().reversed().forEach { reversed.add(it, proof.get(it).deepCopy()) }
        assertRejected("Reordered proof wire JSON accepted", owner, expected(), validAt, bytes(reversed))
    }

    private fun loadBroadcastVector(): JsonObject = instrumentation.context.assets
        .open("network-collaboration-broadcast-consent-v1.json").use {
            JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject
        }

    private fun assertRejected(
        message: String,
        trusted: ClientWireCrypto.PublicIdentity,
        expected: OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority,
        now: Instant,
        raw: ByteArray = proofRaw,
    ) {
        try {
            OwnerLinkReviewPolicyV1Verifier.verify(raw, trusted, expected, now)
            fail(message)
        } catch (_: Exception) {
            // Rejection is expected; do not include public proof bytes in test output.
        }
    }

    private fun bytes(value: JsonObject): ByteArray = value.toString().toByteArray(StandardCharsets.UTF_8)

    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun hexBytes(value: String): ByteArray = value.chunked(2)
        .map { it.toInt(16).toByte() }.toByteArray()
}
