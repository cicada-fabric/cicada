package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/**
 * Independent Android checks for the public synthetic TASK collaboration vector.
 * Its candidate attestation is only an opaque abbreviated value, not a complete
 * EndpointKeyAttestation; these checks do not establish Endpoint or native authority.
 */
@RunWith(AndroidJUnit4::class)
class NetworkCollaborationTaskV1VectorTest {
    private val vectorBytes by lazy {
        InstrumentationRegistry.getInstrumentation().context.assets
            .open("network-collaboration-key-consent-v1.json").use { it.readBytes() }
    }
    private val vector by lazy {
        assertEquals(
            "ad073291703a01513c27fc729439a6bfa8502a8df8f8138a7ed1c3863a4d0c64",
            sha256(vectorBytes),
        )
        JsonParser.parseString(String(vectorBytes, StandardCharsets.UTF_8)).asJsonObject.also {
            assertEquals(1, it.get("fixture_version").asInt)
            assertTrue(it.get("synthetic_only").asBoolean)
            assertEquals("TASK", it.get("purpose").asString)
        }
    }
    private val proofRaw by lazy { vector.get("owner_grant_json").asString }
    private val proof by lazy { parse(proofRaw) }
    private val owner by lazy {
        ClientWireCrypto.PublicIdentity.parse(vector.getAsJsonObject("owner_public_identity"))
    }

    @Test
    fun taskManifestDigestBindsPurposeAndCanonicalManifest() {
        val manifestRaw = vector.get("manifest_canonical_json").asString
        val manifest = parse(manifestRaw)
        assertEquals(
            listOf(
                "version", "hub_id", "network_id", "endpoint_id", "principal_id", "owner_id", "node_id",
                "native_session_digest", "binding_id", "binding_epoch", "membership_revision",
                "endpoint_enrollment_revision", "candidate", "digest",
            ),
            manifest.keySet().toList(),
        )
        assertEquals("The manifest fixture must remain compact and ordered", manifestRaw, manifest.toString())
        val candidate = manifest.getAsJsonObject("candidate")
        assertEquals(
            listOf(
                "network_id", "endpoint_id", "principal_id", "owner_id", "node_id", "binding_id",
                "binding_epoch", "public_identity", "fingerprint", "attestation", "version",
            ),
            candidate.keySet().toList(),
        )
        assertEquals(
            listOf("id", "kem_public", "signing_public"),
            candidate.getAsJsonObject("public_identity").keySet().toList(),
        )

        val nativeSessionId = vector.get("synthetic_native_session_id").asString
        val nativeDigest = sha256(bytes("cicada/network/native-session/v1\u0000") + bytes(nativeSessionId))
        assertEquals(vector.get("native_session_digest").asString, nativeDigest)
        assertEquals(nativeDigest, manifest.get("native_session_digest").asString)

        val purpose = vector.get("purpose").asString
        val canonicalManifest = bytes(manifestRaw)
        val taskDigest = sha256(
            bytes("cicada/network/collaboration-key-manifest/v1\u0000${purpose}\u0000") + canonicalManifest,
        )
        assertEquals(vector.get("collaboration_manifest_digest").asString, taskDigest)
        assertEquals(taskDigest, proof.get("manifest_digest").asString)

        val broadcastDigest = sha256(
            bytes("cicada/network/collaboration-key-manifest/v1\u0000BROADCAST\u0000") + canonicalManifest,
        )
        assertNotEquals("TASK and BROADCAST must have distinct manifest digests", taskDigest, broadcastDigest)

        val abbreviatedAttestation = Base64.getDecoder().decode(
            manifest.getAsJsonObject("candidate").get("attestation").asString,
        )
        val parsedAttestation = runCatching {
            JsonParser.parseString(String(abbreviatedAttestation, StandardCharsets.UTF_8))
                .takeIf { it.isJsonObject }
        }.getOrNull()
        assertNull("The TASK vector does not include a complete Endpoint attestation", parsedAttestation)
    }

    @Test
    fun taskGrantReproducesCanonicalTwelveClaimsAndVerifiesOwnerSignature() {
        val claimOrder = listOf(
            "version", "purpose", "hub_id", "network_id", "endpoint_id", "owner_id", "owner_key_id",
            "manifest_digest", "issued_at", "expires_at", "nonce", "signature",
        )
        assertEquals(claimOrder, proof.keySet().toList())
        assertEquals("The submitted Owner grant must be compact canonical JSON", proofRaw, proof.toString())

        val canonicalClaims = canonicalGrantWithNullSignature(proof)
        val canonicalObject = parse(canonicalClaims)
        assertEquals(claimOrder, canonicalObject.keySet().toList())
        assertTrue(canonicalObject.get("signature") is JsonNull)
        assertEquals(vector.get("canonical_unsigned_json").asString, canonicalClaims)

        val signedInput = bytes("cicada/network/collaboration-key-grant/v1\u0000") + bytes(canonicalClaims)
        assertArrayEquals(Base64.getDecoder().decode(vector.get("signed_input_base64").asString), signedInput)
        assertArrayEquals(hexBytes(vector.get("signed_input_hex").asString), signedInput)
        assertEquals(vector.get("signed_input_sha256").asString, sha256(signedInput))

        assertEquals("TASK", proof.get("purpose").asString)
        assertEquals(vector.get("collaboration_manifest_digest").asString, proof.get("manifest_digest").asString)
        assertEquals(owner.id, proof.get("owner_key_id").asString)
        owner.validate()
        assertEquals(1184, owner.kemPublic.size)
        assertEquals(1952, owner.signingPublic.size)
        val signature = Base64.getDecoder().decode(proof.get("signature").asString)
        assertEquals(3309, signature.size)
        assertTrue(ClientWireCrypto.verify(owner, signedInput, signature))
    }

    @Test
    fun taskGrantRejectsWrongPurposeTamperedClaimsSignatureAndOwnerKey() {
        val signature = Base64.getDecoder().decode(proof.get("signature").asString)
        val originalInput = signedInput(proof)

        val broadcastProof = proof.deepCopy().apply { addProperty("purpose", "BROADCAST") }
        assertFalse(ClientWireCrypto.verify(owner, signedInput(broadcastProof), signature))

        val wrongManifest = proof.deepCopy().apply { addProperty("manifest_digest", "0".repeat(64)) }
        assertFalse(ClientWireCrypto.verify(owner, signedInput(wrongManifest), signature))

        val wrongHub = proof.deepCopy().apply { addProperty("hub_id", "hub_synthetic_other") }
        assertFalse(ClientWireCrypto.verify(owner, signedInput(wrongHub), signature))

        val changedSignature = signature.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(ClientWireCrypto.verify(owner, originalInput, changedSignature))

        val endpointPublic = ClientWireCrypto.PublicIdentity.parse(
            parse(vector.get("manifest_canonical_json").asString)
                .getAsJsonObject("candidate").getAsJsonObject("public_identity"),
        )
        assertFalse(ClientWireCrypto.verify(endpointPublic, originalInput, signature))

        val withoutNullSignature = JsonObject()
        OWNER_GRANT_FIELDS.dropLast(1).forEach { field ->
            withoutNullSignature.add(field, proof.get(field).deepCopy())
        }
        assertFalse(
            "The Owner signature must cover the final signature:null field",
            ClientWireCrypto.verify(
                owner,
                bytes("cicada/network/collaboration-key-grant/v1\u0000") + bytes(withoutNullSignature.toString()),
                signature,
            ),
        )
    }

    private fun signedInput(value: JsonObject): ByteArray =
        bytes("cicada/network/collaboration-key-grant/v1\u0000") +
            bytes(canonicalGrantWithNullSignature(value))

    /** Serialize the explicit Go claim order; signature is present as JSON null. */
    private fun canonicalGrantWithNullSignature(value: JsonObject): String = JsonObject().apply {
        OWNER_GRANT_FIELDS.forEach { field ->
            if (field == "signature") add(field, JsonNull.INSTANCE)
            else add(field, value.get(field).deepCopy())
        }
    }.toString()

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)
    private fun parse(value: String): JsonObject = JsonParser.parseString(value).asJsonObject
    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun hexBytes(value: String): ByteArray = value.chunked(2)
        .map { it.toInt(16).toByte() }.toByteArray()

    companion object {
        private val OWNER_GRANT_FIELDS = listOf(
            "version", "purpose", "hub_id", "network_id", "endpoint_id", "owner_id", "owner_key_id",
            "manifest_digest", "issued_at", "expires_at", "nonce", "signature",
        )
    }
}
