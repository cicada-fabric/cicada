package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonNull
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

/** Public-vector checks do not use the production canonicalizer to create expected bytes. */
@RunWith(AndroidJUnit4::class)
class NetworkKeyConsentVectorTest {
    private val now = Instant.parse("2026-09-30T12:00:00Z")
    private val fixture by lazy {
        val raw = InstrumentationRegistry.getInstrumentation().context.assets
            .open("network-direct-key-consent-v1.json").use { it.readBytes() }
        assertEquals("198bc89dc6508acfc587f1c8dab21cf650c16d816e448857c00deb6d4fdb112a", sha256(raw))
        JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject.also {
            assertTrue(it.get("synthetic_only").asBoolean)
        }
    }

    private fun bytes(text: String): ByteArray = text.toByteArray(StandardCharsets.UTF_8)
    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun decode(value: String): ByteArray = Base64.getDecoder().decode(value)
    private fun parse(value: String): JsonObject = JsonParser.parseString(value).asJsonObject
    private fun assertRejected(message: String, action: () -> Unit) {
        try { action(); fail(message) } catch (_: IllegalArgumentException) { }
    }

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

    /** Replace the final signature alone, independently of production JSON serialization. */
    private fun publishedSignedBytes(domain: String, proof: String): ByteArray = bytes(domain +
        proof.substringBeforeLast(",\"signature\":\"") + ",\"signature\":null}")

    private fun vectorManifest(): JsonObject = parse(fixture.get("manifest_canonical_json").asString)

    private fun ownerPreview(): JsonObject = vectorManifest().apply {
        // The frozen public vector intentionally omits the Owner-only locator and
        // leaves candidate fingerprint blank. Real Store candidates compute it.
        addProperty("native_session_id", fixture.get("synthetic_native_session_id").asString)
        getAsJsonObject("candidate").addProperty("fingerprint", NetworkKeyConsent.fingerprint(
            ClientWireCrypto.PublicIdentity.parse(getAsJsonObject("candidate").getAsJsonObject("public_identity"))))
        addProperty("digest", NetworkKeyConsent.manifestDigest(this))
    }

    private fun check(manifest: JsonObject, expected: NetworkKeyConsent.ExpectedBinding? = null): JsonObject =
        NetworkKeyConsent.verifyManifest(manifest, "hub_synthetic_vector", "owner_synthetic_sender",
            "net_synthetic_vector", "ep_synthetic_sender", expected)

    private fun binding(manifest: JsonObject) = NetworkKeyConsent.ExpectedBinding(
        manifest.get("principal_id").asString, manifest.get("node_id").asString,
        manifest.get("native_session_digest").asString, manifest.get("binding_id").asString,
        manifest.get("binding_epoch").asLong, manifest.get("membership_revision").asLong,
        manifest.get("endpoint_enrollment_revision").asLong,
        manifest.getAsJsonObject("candidate").get("version").asLong,
    )

    /** Ephemeral synthetic key material is never serialized or stored in an asset. */
    private fun ownerProof(manifest: JsonObject, owner: ClientWireCrypto.Identity,
        change: (JsonObject) -> Unit = {}): ByteArray {
        val proof = parse(fixture.get("owner_grant").asString).apply {
            addProperty("owner_key_id", owner.publicIdentity.id)
            addProperty("manifest_digest", manifest.get("digest").asString)
            add("signature", JsonNull.INSTANCE)
            change(this)
        }
        val signature = owner.sign(bytes("cicada/network/direct-key-grant/v1\u0000" + proof.toString()))
        proof.addProperty("signature", Base64.getEncoder().encodeToString(signature))
        return bytes(proof.toString())
    }

    @Test fun publishedAttestationChecksRawHashCompleteKeysNullSignatureAndRealNul() {
        val rawText = fixture.get("attestation").asString
        val raw = bytes(rawText)
        assertEquals("3f278549ebc1ecee05d02e1682b1fc6e3972393bfe60e4007c07c3c82a954497", sha256(raw))
        val proof = parse(rawText)
        val signed = publishedSignedBytes("cicada/network/direct-key-attestation/v1\u0000", rawText)
        assertArrayEquals(decode(fixture.get("attestation_signed_input_base64").asString), signed)
        assertEquals(fixture.get("attestation_signed_sha256").asString, sha256(signed))
        val public = proof.getAsJsonObject("public_identity")
        assertEquals(fixture.getAsJsonObject("sender_public_identity"), public)
        val signature = decode(proof.get("signature").asString)
        assertTrue(independentVerify(public, signed, signature))
        val omitted = bytes(String(signed, StandardCharsets.UTF_8).replace(",\"signature\":null}", "}"))
        assertFalse(independentVerify(public, omitted, signature))
        val literalNul = bytes(String(signed, StandardCharsets.UTF_8).replace("\u0000", "\\0"))
        assertFalse(independentVerify(public, literalNul, signature))
        val changed = signature.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(independentVerify(public, signed, changed))
        val verified = NetworkKeyConsent.verifyAttestation(raw, "hub_synthetic_vector", "net_synthetic_vector",
            "ep_synthetic_sender", "pr_synthetic_sender", "node_synthetic_sender", "native_binding_synthetic",
            1L, public, sha256(raw))
        assertEquals(public.get("id").asString, verified.id)
    }

    @Test fun publishedManifestAndOwnerSignatureAreIndependentlyReproduced() {
        val canonical = bytes(fixture.get("manifest_canonical_json").asString)
        val manifest = vectorManifest()
        assertFalse(manifest.has("native_session_id"))
        assertEquals("", manifest.get("digest").asString)
        assertEquals("", manifest.getAsJsonObject("candidate").get("fingerprint").asString)
        assertArrayEquals(canonical, NetworkKeyConsent.canonicalManifestClaims(manifest))
        assertEquals(fixture.get("manifest_digest").asString,
            sha256(bytes("cicada/network/direct-key-manifest/v1\u0000") + canonical))
        val rawLocator = fixture.get("synthetic_native_session_id").asString
        assertEquals(fixture.get("native_session_digest").asString,
            sha256(bytes("cicada/network/native-session/v1\u0000" + rawLocator)))
        assertEquals(fixture.get("native_session_digest").asString, NetworkKeyConsent.nativeSessionDigest(rawLocator))
        val rawProof = fixture.get("owner_grant").asString
        val proof = parse(rawProof)
        val signed = publishedSignedBytes("cicada/network/direct-key-grant/v1\u0000", rawProof)
        assertArrayEquals(decode(fixture.get("owner_grant_signed_input_base64").asString), signed)
        assertEquals(fixture.get("owner_grant_signed_sha256").asString, sha256(signed))
        assertEquals(fixture.get("manifest_digest").asString, proof.get("manifest_digest").asString)
        assertEquals("hub_synthetic_vector", proof.get("hub_id").asString)
        assertEquals("net_synthetic_vector", proof.get("network_id").asString)
        assertEquals("ep_synthetic_sender", proof.get("endpoint_id").asString)
        assertEquals("owner_synthetic_sender", proof.get("owner_id").asString)
        val public = fixture.getAsJsonObject("owner_public_identity")
        assertEquals(public.get("id").asString, proof.get("owner_key_id").asString)
        val signature = decode(proof.get("signature").asString)
        assertTrue(independentVerify(public, signed, signature))
        assertFalse(independentVerify(public, bytes(String(signed, StandardCharsets.UTF_8)
            .replace(",\"signature\":null}", "}")), signature))
        assertRejected("Incomplete vector was accepted as an Owner preview") { check(manifest) }
    }

    @Test fun productionOwnerPreviewRequiresFullFingerprintAndNativeDigest() {
        val manifest = ownerPreview()
        assertEquals(manifest, check(manifest, binding(manifest)))
        for (field in listOf("hub_id", "network_id", "endpoint_id", "owner_id", "principal_id", "node_id", "binding_id")) {
            val changed = manifest.deepCopy().apply { addProperty(field, "wrong_scope") }
            assertRejected("Changed $field accepted") { check(changed) }
        }
        for (field in listOf("native_session_id", "native_session_digest", "digest")) {
            val changed = manifest.deepCopy().apply { addProperty(field, "a".repeat(64)) }
            assertRejected("Changed $field accepted") { check(changed) }
        }
        for (fingerprint in listOf("", "sha256:" + "0".repeat(64))) {
            val changed = manifest.deepCopy().apply {
                getAsJsonObject("candidate").addProperty("fingerprint", fingerprint)
                addProperty("digest", NetworkKeyConsent.manifestDigest(this))
            }
            assertRejected("Hub-supplied incorrect fingerprint accepted with updated digest") { check(changed) }
        }
    }

    @Test fun currentAuthorityRejectsStaleBindingAndRevisionsEvenWithUpdatedManifestDigest() {
        val manifest = ownerPreview()
        val expected = binding(manifest)
        for (field in listOf("binding_epoch", "membership_revision", "endpoint_enrollment_revision")) {
            val changed = manifest.deepCopy().apply {
                addProperty(field, get(field).asLong + 1)
                if (field == "binding_epoch") getAsJsonObject("candidate").addProperty(field, get(field).asLong)
                addProperty("digest", NetworkKeyConsent.manifestDigest(this))
            }
            assertRejected("Stale $field accepted") { check(changed, expected) }
        }
        val changedCandidate = manifest.deepCopy().apply {
            getAsJsonObject("candidate").addProperty("version", 2)
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        assertRejected("Stale candidate version accepted") { check(changedCandidate, expected) }
        for (number in listOf(0, -1, 1.5)) {
            val changed = manifest.deepCopy().apply {
                addProperty("membership_revision", number)
                addProperty("digest", NetworkKeyConsent.manifestDigest(this))
            }
            assertRejected("Invalid revision accepted") { check(changed) }
        }
    }

    @Test fun proofTamperingAndAlternatePublicKeysAreRejectedBeforeOwnerConsent() {
        val manifest = ownerPreview()
        val wrongPublic = manifest.deepCopy().apply {
            getAsJsonObject("candidate").add("public_identity", fixture.getAsJsonObject("receiver_public_identity").deepCopy())
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        assertRejected("Different complete candidate public key accepted") { check(wrongPublic) }
        val proof = parse(fixture.get("attestation").asString)
        val signature = decode(proof.get("signature").asString).also { it[0] = (it[0].toInt() xor 1).toByte() }
        proof.addProperty("signature", Base64.getEncoder().encodeToString(signature))
        val changed = manifest.deepCopy().apply {
            getAsJsonObject("candidate").addProperty("attestation", Base64.getEncoder().encodeToString(bytes(proof.toString())))
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        assertRejected("Tampered signature accepted with rehashed candidate and manifest") { check(changed) }
        val whitespace = manifest.deepCopy().apply {
            val raw = fixture.get("attestation").asString.replace("{\"version\":1", "{ \"version\":1")
            getAsJsonObject("candidate").addProperty("attestation", Base64.getEncoder().encodeToString(bytes(raw)))
            addProperty("digest", NetworkKeyConsent.manifestDigest(this))
        }
        assertRejected("Noncanonical attestation accepted") { check(whitespace) }
        val noncanonicalBase64 = manifest.deepCopy().apply {
            getAsJsonObject("candidate").addProperty("attestation", getAsJsonObject("candidate").get("attestation").asString + "=")
        }
        assertRejected("Noncanonical candidate base64 accepted") { check(noncanonicalBase64) }
    }

    @Test fun externalOwnerProofRequiresPinnedOwnerExactScopeAndLiveCanonicalTime() {
        val manifest = check(ownerPreview())
        val owner = ClientWireCrypto.Identity.generate()
        val other = ClientWireCrypto.Identity.generate()
        try {
            val raw = ownerProof(manifest, owner)
            NetworkKeyConsent.verifyOwnerProof(raw, manifest, owner.publicIdentity, now)
            assertRejected("Other pinned Owner accepted") {
                NetworkKeyConsent.verifyOwnerProof(raw, manifest, other.publicIdentity, now)
            }
            for (field in listOf("hub_id", "network_id", "endpoint_id", "owner_id", "owner_key_id", "manifest_digest", "nonce")) {
                val changed = ownerProof(manifest, owner) { it.addProperty(field, "wrong_scope") }
                assertRejected("Signed proof for other $field accepted") {
                    NetworkKeyConsent.verifyOwnerProof(changed, manifest, owner.publicIdentity, now)
                }
            }
            for (timestamp in listOf("2026-10-01T00:00:00Z", "2026-01-01T00:00:00.1200Z", "2026-01-01T01:00:00+01:00")) {
                val changed = ownerProof(manifest, owner) { it.addProperty("issued_at", timestamp) }
                assertRejected("Invalid issue time accepted") {
                    NetworkKeyConsent.verifyOwnerProof(changed, manifest, owner.publicIdentity, now)
                }
            }
            assertRejected("Expired proof accepted at boundary") {
                NetworkKeyConsent.verifyOwnerProof(raw, manifest, owner.publicIdentity, Instant.parse("2027-01-01T00:00:00Z"))
            }
            val changedRevision = manifest.deepCopy().apply {
                addProperty("membership_revision", 2)
                addProperty("digest", NetworkKeyConsent.manifestDigest(this))
            }
            assertRejected("Old Owner approval accepted after authority revision changed") {
                NetworkKeyConsent.verifyOwnerProof(raw, changedRevision, owner.publicIdentity, now)
            }
            val changedSignature = parse(String(raw, StandardCharsets.UTF_8)).apply {
                val sig = decode(get("signature").asString).also { it[0] = (it[0].toInt() xor 1).toByte() }
                addProperty("signature", Base64.getEncoder().encodeToString(sig))
            }
            assertRejected("Tampered Owner signature accepted") {
                NetworkKeyConsent.verifyOwnerProof(bytes(changedSignature.toString()), manifest, owner.publicIdentity, now)
            }
            val whitespace = bytes(String(raw, StandardCharsets.UTF_8).replace("{\"version\":1", "{ \"version\":1"))
            assertRejected("Noncanonical Owner proof accepted") {
                NetworkKeyConsent.verifyOwnerProof(whitespace, manifest, owner.publicIdentity, now)
            }
        } finally { owner.close(); other.close() }
    }
}
