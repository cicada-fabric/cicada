package ai.cicada.client.hub

import android.util.Base64
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/** Independent verification of a Network candidate and separately signed Owner consent. */
internal object NetworkKeyConsent {
    private const val ATTESTATION_DOMAIN = "cicada/network/direct-key-attestation/v1\u0000"
    private const val GRANT_DOMAIN = "cicada/network/direct-key-grant/v1\u0000"
    private const val MANIFEST_DOMAIN = "cicada/network/direct-key-manifest/v1\u0000"
    private const val NATIVE_DOMAIN = "cicada/network/native-session/v1\u0000"
    private const val FINGERPRINT_DOMAIN = "cicada/nodekeys/peer-key-fingerprint/v1\u0000"
    private val attestationFields = listOf("version", "hub_id", "network_id", "endpoint_id",
        "principal_id", "node_id", "binding_id", "binding_epoch", "public_identity", "signature")
    private val candidateFields = listOf("network_id", "endpoint_id", "principal_id", "owner_id",
        "node_id", "binding_id", "binding_epoch", "public_identity", "fingerprint", "attestation",
        "version")
    private val manifestFields = listOf("version", "hub_id", "network_id", "endpoint_id",
        "principal_id", "owner_id", "node_id", "native_session_digest", "binding_id",
        "binding_epoch", "membership_revision", "endpoint_enrollment_revision", "candidate", "digest")
    private val grantFields = listOf("version", "hub_id", "network_id", "endpoint_id", "owner_id",
        "owner_key_id", "manifest_digest", "issued_at", "expires_at", "nonce", "signature")
    private val hexDigest = Regex("[0-9a-f]{64}")

    /** Optional current authority obtained independently from an authenticated topology/binding view. */
    data class ExpectedBinding(
        val principalId: String,
        val nodeId: String,
        val nativeSessionDigest: String,
        val bindingId: String,
        val bindingEpoch: Long,
        val membershipRevision: Long,
        val endpointEnrollmentRevision: Long,
        val candidateVersion: Long,
    )

    private fun bytes(text: String): ByteArray = text.toByteArray(StandardCharsets.UTF_8)

    internal fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun text(source: JsonObject, name: String): String = source.get(name)?.takeIf {
        it.isJsonPrimitive && it.asJsonPrimitive.isString
    }?.asString ?: throw IllegalArgumentException("Invalid Network key field: $name")

    private fun positive(source: JsonObject, name: String): Long {
        val token = source.get(name)?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isNumber
        }?.asString
        require(token != null && token.matches(Regex("[1-9][0-9]*"))) {
            "Invalid Network key revision: $name"
        }
        return token.toLongOrNull()?.takeIf { it > 0 }
            ?: throw IllegalArgumentException("Invalid Network key revision: $name")
    }

    private fun validUtf8(value: String): Boolean = try {
        StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
        true
    } catch (_: java.nio.charset.CharacterCodingException) { false }

    private fun token(value: String): Boolean = value.isNotEmpty() && value == value.trim() &&
        bytes(value).size <= 256 && validUtf8(value) &&
        value.none { it.isWhitespace() || it.isISOControl() || it == '/' || it == '\\' }

    private fun shape(source: JsonObject, names: List<String>) {
        require(source.size() == names.size && source.keySet() == names.toSet()) {
            "Invalid Network key object shape"
        }
    }

    private fun fields(source: JsonObject, names: List<String>): JsonObject = JsonObject().apply {
        for (name in names) add(name, source.get(name)?.deepCopy()
            ?: throw IllegalArgumentException("Missing Network key field: $name"))
    }

    // Go encoding/json escapes these Unicode characters even with compact JSON.
    private fun canonicalJson(source: JsonObject): String = source.toString()
        .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    private fun base64(source: JsonObject, name: String): ByteArray {
        val encoded = text(source, name)
        val decoded = try { Base64.decode(encoded, Base64.NO_WRAP) }
        catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Network key base64: $name", error)
        }
        require(Base64.encodeToString(decoded, Base64.NO_WRAP) == encoded) {
            "Noncanonical Network key base64: $name"
        }
        return decoded
    }

    private fun identity(source: JsonObject): ClientWireCrypto.PublicIdentity {
        shape(source, listOf("id", "kem_public", "signing_public"))
        val public = ClientWireCrypto.PublicIdentity(text(source, "id"),
            base64(source, "kem_public"), base64(source, "signing_public"))
        public.validate()
        return public
    }

    private fun publicJson(public: ClientWireCrypto.PublicIdentity): JsonObject =
        JsonParser.parseString(public.toJson()).asJsonObject

    private fun parseCanonicalProof(raw: ByteArray, names: List<String>): JsonObject {
        require(raw.isNotEmpty() && raw.size <= 32 * 1024) { "Invalid Network proof size" }
        val decoded = try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
        } catch (error: java.nio.charset.CharacterCodingException) {
            throw IllegalArgumentException("Invalid Network proof UTF-8", error)
        }
        val proof = try { JsonParser.parseString(decoded).asJsonObject }
        catch (error: RuntimeException) { throw IllegalArgumentException("Invalid Network proof JSON", error) }
        shape(proof, names)
        return proof
    }

    internal fun nativeSessionDigest(nativeSessionId: String): String =
        sha256(bytes(NATIVE_DOMAIN) + bytes(nativeSessionId))

    internal fun fingerprint(public: ClientWireCrypto.PublicIdentity): String =
        "sha256:" + sha256(bytes(FINGERPRINT_DOMAIN) + public.kemPublic + public.signingPublic)

    /** Public digest encoding: raw native locator is omitted; digest remains as an empty string. */
    internal fun canonicalManifestClaims(manifest: JsonObject): ByteArray {
        val canonical = fields(manifest, manifestFields)
        val candidate = fields(manifest.getAsJsonObject("candidate"), candidateFields)
        candidate.add("public_identity", publicJson(identity(candidate.getAsJsonObject("public_identity"))))
        canonical.add("candidate", candidate)
        canonical.addProperty("digest", "")
        return bytes(canonicalJson(canonical))
    }

    internal fun manifestDigest(manifest: JsonObject): String =
        sha256(bytes(MANIFEST_DOMAIN) + canonicalManifestClaims(manifest))

    fun verifyAttestation(
        raw: ByteArray,
        hubId: String,
        networkId: String,
        endpointId: String,
        principalId: String,
        nodeId: String,
        bindingId: String,
        bindingEpoch: Long,
        expectedPublic: JsonObject,
        expectedRawSha256: String,
    ): ClientWireCrypto.PublicIdentity {
        require(listOf(hubId, networkId, endpointId, principalId, nodeId, bindingId).all(::token) &&
            bindingEpoch > 0 && expectedRawSha256.matches(hexDigest)) { "Invalid expected Network binding" }
        require(sha256(raw) == expectedRawSha256) { "Network attestation raw digest mismatch" }
        val proof = parseCanonicalProof(raw, attestationFields)
        val expected = mapOf("hub_id" to hubId, "network_id" to networkId, "endpoint_id" to endpointId,
            "principal_id" to principalId, "node_id" to nodeId, "binding_id" to bindingId)
        require(positive(proof, "version") == 1L && positive(proof, "binding_epoch") == bindingEpoch &&
            expected.all { (name, value) -> text(proof, name) == value }) {
            "Network attestation binding mismatch"
        }
        val public = identity(proof.getAsJsonObject("public_identity"))
        require(public.sameAs(identity(expectedPublic))) { "Network attestation public key mismatch" }
        val canonical = fields(proof, attestationFields).apply { add("public_identity", publicJson(public)) }
        require(MessageDigest.isEqual(raw, bytes(canonicalJson(canonical)))) {
            "Network attestation is not canonical v1 JSON"
        }
        val signature = base64(proof, "signature")
        canonical.add("signature", JsonNull.INSTANCE)
        require(ClientWireCrypto.verify(public, bytes(ATTESTATION_DOMAIN) + bytes(canonicalJson(canonical)),
            signature)) { "Network attestation signature failed" }
        return public
    }

    /** This is an Owner preview; peer evidence without the raw native locator is insufficient here. */
    fun verifyManifest(
        manifest: JsonObject,
        hubId: String,
        ownerId: String,
        networkId: String,
        endpointId: String,
        expectedBinding: ExpectedBinding? = null,
    ): JsonObject {
        require(listOf(hubId, ownerId, networkId, endpointId).all(::token)) {
            "Invalid selected Network key scope"
        }
        shape(manifest, manifestFields + "native_session_id")
        val expected = mapOf("hub_id" to hubId, "owner_id" to ownerId, "network_id" to networkId,
            "endpoint_id" to endpointId)
        require(positive(manifest, "version") == 1L && expected.all {
            (name, value) -> text(manifest, name) == value
        }) { "Network key manifest scope mismatch" }
        for (name in listOf("principal_id", "node_id", "binding_id")) {
            require(token(text(manifest, name))) { "Invalid Network key identity: $name" }
        }
        val nativeId = text(manifest, "native_session_id")
        require(nativeId.isNotEmpty() && validUtf8(nativeId) &&
            nativeSessionDigest(nativeId) == text(manifest, "native_session_digest")) {
            "Network native Thread digest mismatch"
        }
        for (name in listOf("binding_epoch", "membership_revision", "endpoint_enrollment_revision")) {
            positive(manifest, name)
        }
        val candidate = manifest.getAsJsonObject("candidate")
        shape(candidate, candidateFields)
        for (name in listOf("network_id", "endpoint_id", "principal_id", "owner_id", "node_id", "binding_id")) {
            require(text(candidate, name) == text(manifest, name)) { "Network candidate scope mismatch: $name" }
        }
        require(positive(candidate, "binding_epoch") == positive(manifest, "binding_epoch")) {
            "Network candidate binding epoch mismatch"
        }
        val candidateVersion = positive(candidate, "version")
        if (expectedBinding != null) {
            require(text(manifest, "principal_id") == expectedBinding.principalId &&
                text(manifest, "node_id") == expectedBinding.nodeId &&
                text(manifest, "native_session_digest") == expectedBinding.nativeSessionDigest &&
                text(manifest, "binding_id") == expectedBinding.bindingId &&
                positive(manifest, "binding_epoch") == expectedBinding.bindingEpoch &&
                positive(manifest, "membership_revision") == expectedBinding.membershipRevision &&
                positive(manifest, "endpoint_enrollment_revision") == expectedBinding.endpointEnrollmentRevision &&
                candidateVersion == expectedBinding.candidateVersion) { "Network key authority changed" }
        }
        val raw = base64(candidate, "attestation")
        val public = verifyAttestation(raw, hubId, networkId, endpointId, text(manifest, "principal_id"),
            text(manifest, "node_id"), text(manifest, "binding_id"), positive(manifest, "binding_epoch"),
            candidate.getAsJsonObject("public_identity"), sha256(raw))
        require(fingerprint(public) == text(candidate, "fingerprint")) {
            "Network candidate fingerprint mismatch"
        }
        val digest = text(manifest, "digest")
        require(digest.matches(hexDigest) && manifestDigest(manifest) == digest) {
            "Network key manifest digest mismatch"
        }
        return manifest.deepCopy()
    }

    /** Owner private material stays in the external signer. This checks only its public proof. */
    fun verifyOwnerProof(
        raw: ByteArray,
        verifiedManifest: JsonObject,
        pinnedOwner: ClientWireCrypto.PublicIdentity,
        now: Instant = Instant.now(),
    ) {
        pinnedOwner.validate()
        val manifest = verifyManifest(verifiedManifest, text(verifiedManifest, "hub_id"),
            text(verifiedManifest, "owner_id"), text(verifiedManifest, "network_id"),
            text(verifiedManifest, "endpoint_id"))
        val proof = parseCanonicalProof(raw, grantFields)
        require(positive(proof, "version") == 1L &&
            listOf("hub_id", "network_id", "endpoint_id", "owner_id").all {
                text(proof, it) == text(manifest, it)
            } && text(proof, "owner_key_id") == pinnedOwner.id &&
            text(proof, "manifest_digest") == text(manifest, "digest") &&
            text(proof, "nonce").matches(hexDigest)) { "Owner proof is not bound to this Network manifest" }
        val issued = GroupKeyManifestVerifier.parseCanonicalUtc(text(proof, "issued_at"))
        val expires = GroupKeyManifestVerifier.parseCanonicalUtc(text(proof, "expires_at"))
        require(issued <= now && expires > now && expires > issued) { "Network Owner proof expired or future-issued" }
        val canonical = fields(proof, grantFields)
        require(MessageDigest.isEqual(raw, bytes(canonicalJson(canonical)))) {
            "Network Owner proof is not canonical v1 JSON"
        }
        val signature = base64(proof, "signature")
        canonical.add("signature", JsonNull.INSTANCE)
        require(ClientWireCrypto.verify(pinnedOwner, bytes(GRANT_DOMAIN) + bytes(canonicalJson(canonical)),
            signature)) { "Network Owner proof signature failed" }
    }
}
