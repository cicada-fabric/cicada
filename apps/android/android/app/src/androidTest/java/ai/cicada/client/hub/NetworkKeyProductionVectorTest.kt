package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
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

/** Exact public Store vector; synthetic protocol evidence, not live Owner or Node acceptance. */
@RunWith(AndroidJUnit4::class)
class NetworkKeyProductionVectorTest {
    private val now = Instant.parse("2026-09-30T12:00:00Z")
    private val fixture by lazy {
        val raw = InstrumentationRegistry.getInstrumentation().context.assets
            .open("network-direct-key-production-v1.json").use { it.readBytes() }
        assertEquals("6f21a1184243a0781024598063113ccda92df98b9f3996b9d86dd3167efdda04", sha256(raw))
        parse(String(raw, StandardCharsets.UTF_8)).also { assertTrue(it.get("synthetic_only").asBoolean) }
    }

    @Test
    fun completeStoreManifestMatchesPublishedClaimsAndPrivateLocatorDigest() {
        val manifest = manifest()
        assertEquals(setOf("version", "hub_id", "network_id", "endpoint_id", "principal_id", "owner_id",
            "node_id", "native_session_id", "native_session_digest", "binding_id", "binding_epoch",
            "membership_revision", "endpoint_enrollment_revision", "candidate", "digest"), manifest.keySet())
        assertEquals(7L, manifest.get("binding_epoch").asLong)
        assertEquals(11L, manifest.get("membership_revision").asLong)
        assertEquals(13L, manifest.get("endpoint_enrollment_revision").asLong)
        assertEquals(5L, manifest.getAsJsonObject("candidate").get("version").asLong)
        val canonical = bytes(fixture.get("canonical_claims").asString)
        assertFalse(parse(String(canonical, StandardCharsets.UTF_8)).has("native_session_id"))
        assertEquals("", parse(String(canonical, StandardCharsets.UTF_8)).get("digest").asString)
        assertArrayEquals(canonical, NetworkKeyConsent.canonicalManifestClaims(manifest))
        val independentDigest = sha256(bytes("cicada/network/direct-key-manifest/v1\u0000") + canonical)
        assertEquals(fixture.get("manifest_digest").asString, independentDigest)
        assertEquals(independentDigest, manifest.get("digest").asString)
        assertEquals(NATIVE_DIGEST, sha256(bytes("cicada/network/native-session/v1\u0000" +
            manifest.get("native_session_id").asString)))
        assertEquals(NATIVE_DIGEST, manifest.get("native_session_digest").asString)
        val verified = check(manifest)
        assertEquals(manifest, verified)
        assertNotSame(manifest, verified)
    }

    @Test
    fun endpointAttestationChecksExactRawBytesFullKeysAndTrailingNull() {
        val manifest = manifest()
        val candidate = manifest.getAsJsonObject("candidate")
        val raw = decode(candidate.get("attestation").asString)
        assertEquals("5a7dcbba453316213a0701542b96c060e1c5bddcb53140c5b145de02ddc45c8b", sha256(raw))
        val proof = parse(String(raw, StandardCharsets.UTF_8))
        for (field in listOf("network_id", "endpoint_id", "principal_id", "node_id", "binding_id", "binding_epoch")) {
            assertEquals(manifest.get(field), candidate.get(field))
            assertEquals(manifest.get(field), proof.get(field))
        }
        assertEquals(manifest.get("hub_id"), proof.get("hub_id"))
        assertEquals(manifest.get("owner_id"), candidate.get("owner_id"))
        val public = proof.getAsJsonObject("public_identity")
        assertEquals(candidate.getAsJsonObject("public_identity"), public)
        val signed = unsignedBytes("cicada/network/direct-key-attestation/v1\u0000", String(raw, StandardCharsets.UTF_8))
        assertArrayEquals(decode(fixture.get("attestation_signed_input_base64").asString), signed)
        assertEquals(fixture.get("attestation_signed_sha256").asString, sha256(signed))
        val signature = decode(proof.get("signature").asString)
        assertTrue(independentVerify(public, signed, signature))
        assertFalse(independentVerify(public, bytes(String(signed, StandardCharsets.UTF_8)
            .replace(",\"signature\":null}", "}")), signature))
        assertFalse(independentVerify(public, bytes(String(signed, StandardCharsets.UTF_8)
            .replace("\u0000", "\\0")), signature))
        val fingerprint = "sha256:" + sha256(bytes("cicada/nodekeys/peer-key-fingerprint/v1\u0000") +
            decode(public.get("kem_public").asString) + decode(public.get("signing_public").asString))
        assertEquals(candidate.get("fingerprint").asString, fingerprint)
        assertEquals(public.get("id").asString, NetworkKeyConsent.verifyAttestation(raw, HUB, NETWORK, ENDPOINT,
            PRINCIPAL, NODE, BINDING, 7, public, sha256(raw)).id)
        rejected { NetworkKeyConsent.verifyAttestation(raw, HUB, NETWORK, ENDPOINT, PRINCIPAL, NODE,
            BINDING, 7, public, "0".repeat(64)) }
    }

    @Test
    fun publishedExternalOwnerProofRequiresPinnedOwnerExactScopeAndLiveTime() {
        val manifest = check(manifest())
        val raw = fixture.get("owner_proof").asString
        val proof = parse(raw)
        val public = fixture.getAsJsonObject("owner_public_identity")
        for (field in listOf("hub_id", "network_id", "endpoint_id", "owner_id")) {
            assertEquals(manifest.get(field), proof.get(field))
        }
        assertEquals(public.get("id").asString, proof.get("owner_key_id").asString)
        assertEquals(manifest.get("digest"), proof.get("manifest_digest"))
        val signed = unsignedBytes("cicada/network/direct-key-grant/v1\u0000", raw)
        assertArrayEquals(decode(fixture.get("owner_grant_signed_input_base64").asString), signed)
        assertEquals(fixture.get("owner_grant_signed_sha256").asString, sha256(signed))
        val signature = decode(proof.get("signature").asString)
        assertTrue(independentVerify(public, signed, signature))
        assertFalse(independentVerify(public, bytes(String(signed, StandardCharsets.UTF_8)
            .replace(",\"signature\":null}", "}")), signature))
        val pinnedOwner = ClientWireCrypto.PublicIdentity.parse(public)
        NetworkKeyConsent.verifyOwnerProof(bytes(raw), manifest, pinnedOwner, now)
        rejected { NetworkKeyConsent.verifyOwnerProof(bytes(raw), manifest,
            ClientWireCrypto.PublicIdentity.parse(manifest.getAsJsonObject("candidate").getAsJsonObject("public_identity")), now) }
        rejected { NetworkKeyConsent.verifyOwnerProof(bytes(raw), manifest, pinnedOwner,
            Instant.parse(proof.get("issued_at").asString).minusNanos(1)) }
        rejected { NetworkKeyConsent.verifyOwnerProof(bytes(raw), manifest, pinnedOwner,
            Instant.parse(proof.get("expires_at").asString)) }
        val changed = proof.deepCopy().apply { addProperty("manifest_digest", "0".repeat(64)) }
        rejected { NetworkKeyConsent.verifyOwnerProof(bytes(changed.toString()), manifest, pinnedOwner, now) }
    }

    @Test
    fun independentlyFixedCurrentBindingRejectsChangedAuthorityAfterRehashing() {
        val manifest = manifest()
        for (field in listOf("binding_epoch", "membership_revision", "endpoint_enrollment_revision")) {
            val changed = manifest.deepCopy().apply {
                addProperty(field, get(field).asLong + 1)
                if (field == "binding_epoch") getAsJsonObject("candidate").addProperty(field, get(field).asLong)
                addProperty("digest", NetworkKeyConsent.manifestDigest(this))
            }
            rejected { check(changed) }
        }
        val candidateVersion = manifest.deepCopy().apply {
            getAsJsonObject("candidate").addProperty("version", 6)
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        rejected { check(candidateVersion) }
        val otherNative = manifest.deepCopy().apply {
            addProperty("native_session_id", "another_synthetic_private_locator")
            addProperty("native_session_digest", sha256(bytes("cicada/network/native-session/v1\u0000" + get("native_session_id").asString)))
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        rejected { check(otherNative) }
        for (field in listOf("hub_id", "network_id", "endpoint_id", "owner_id", "principal_id", "node_id", "binding_id")) {
            val changed = manifest.deepCopy().apply {
                addProperty(field, "wrong_synthetic_scope")
                if (getAsJsonObject("candidate").has(field)) getAsJsonObject("candidate").addProperty(field, "wrong_synthetic_scope")
                addProperty("digest", NetworkKeyConsent.manifestDigest(this))
            }
            rejected { check(changed) }
        }
    }

    @Test
    fun tamperedCompleteKeysAttestationSignatureEncodingAndShapesAreRejected() {
        val manifest = manifest()
        val raw = decode(manifest.getAsJsonObject("candidate").get("attestation").asString)
        val proof = parse(String(raw, StandardCharsets.UTF_8))
        val signature = decode(proof.get("signature").asString).also { it[0] = (it[0].toInt() xor 1).toByte() }
        proof.addProperty("signature", Base64.getEncoder().encodeToString(signature))
        val corruptSignature = withAttestation(manifest, bytes(proof.toString()))
        rejected { check(corruptSignature) }
        val noncanonical = withAttestation(manifest, bytes(String(raw, StandardCharsets.UTF_8).replace("{\"version\":1", "{ \"version\":1")))
        rejected { check(noncanonical) }
        val wrongKey = manifest.deepCopy().apply {
            getAsJsonObject("candidate").add("public_identity", fixture.getAsJsonObject("owner_public_identity").deepCopy())
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        rejected { check(wrongKey) }
        val fingerprint = manifest.deepCopy().apply {
            getAsJsonObject("candidate").addProperty("fingerprint", "sha256:" + "0".repeat(64))
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        rejected { check(fingerprint) }
        rejected { check(manifest.deepCopy().apply { addProperty("unexpected", true) }) }
        rejected { check(manifest.deepCopy().apply { remove("native_session_id") }) }
        rejected { check(manifest.deepCopy().apply { getAsJsonObject("candidate").addProperty("unexpected", true) }) }
        val ownerProof = parse(fixture.get("owner_proof").asString)
        val ownerSignature = decode(ownerProof.get("signature").asString).also { it[0] = (it[0].toInt() xor 1).toByte() }
        ownerProof.addProperty("signature", Base64.getEncoder().encodeToString(ownerSignature))
        rejected { NetworkKeyConsent.verifyOwnerProof(bytes(ownerProof.toString()), manifest,
            ClientWireCrypto.PublicIdentity.parse(fixture.getAsJsonObject("owner_public_identity")), now) }
    }

    private fun manifest(): JsonObject = fixture.getAsJsonObject("manifest").deepCopy()

    private fun check(manifest: JsonObject): JsonObject = NetworkKeyConsent.verifyManifest(manifest,
        HUB, OWNER, NETWORK, ENDPOINT, NetworkKeyConsent.ExpectedBinding(PRINCIPAL, NODE, NATIVE_DIGEST,
            BINDING, 7, 11, 13, 5))

    private fun withAttestation(manifest: JsonObject, raw: ByteArray): JsonObject = manifest.deepCopy().apply {
        getAsJsonObject("candidate").addProperty("attestation", Base64.getEncoder().encodeToString(raw))
        addProperty("digest", NetworkKeyConsent.manifestDigest(this))
    }

    private fun unsignedBytes(domain: String, proof: String): ByteArray = bytes(domain +
        proof.substringBeforeLast(",\"signature\":\"") + ",\"signature\":null}")

    private fun independentVerify(public: JsonObject, signed: ByteArray, signature: ByteArray): Boolean {
        val kem = decode(public.get("kem_public").asString)
        val signing = decode(public.get("signing_public").asString)
        assertEquals(1184, kem.size)
        assertEquals(1952, signing.size)
        assertEquals(3309, signature.size)
        assertEquals("pq1-" + sha256(kem + signing).take(32), public.get("id").asString)
        val verifier = MLDSASigner()
        verifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, signing))
        verifier.update(signed, 0, signed.size)
        return verifier.verifySignature(signature)
    }

    private fun bytes(text: String): ByteArray = text.toByteArray(StandardCharsets.UTF_8)
    private fun decode(value: String): ByteArray = Base64.getDecoder().decode(value)
    private fun parse(value: String): JsonObject = JsonParser.parseString(value).asJsonObject
    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(raw)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun rejected(action: () -> Unit) {
        try { action(); fail("Tampered or expired production-shape evidence was accepted") }
        catch (_: IllegalArgumentException) { }
    }

    companion object {
        private const val HUB = "hub_synthetic_production_shape"
        private const val OWNER = "owner_synthetic_production_shape"
        private const val NETWORK = "net_synthetic_production_shape"
        private const val ENDPOINT = "ep_synthetic_production_shape"
        private const val PRINCIPAL = "pr_synthetic_production_shape"
        private const val NODE = "node_synthetic_production_shape"
        private const val BINDING = "binding_synthetic_production_shape"
        private const val NATIVE_DIGEST = "3686bb45dbc4af1a3e14260f2b3a67748821c05782c5e4b4c723b4566a4085aa"
    }
}
