package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Base64
import java.util.Locale

/** Independently checks the complete Endpoint proof and both v1 Group digests. */
internal object GroupKeyManifestVerifier {
    private const val OPERATION = "group-endpoint-key-grant:v1"
    private const val PROOF_DOMAIN = "cicada/fabric/endpoint-key-attestation/v1\u0000"
    private const val FINGERPRINT_DOMAIN = "cicada/nodekeys/peer-key-fingerprint/v1\u0000"
    private const val BINDING_DOMAIN = "cicada/group/endpoint-key-binding/v1\u0000"
    private const val MANIFEST_DOMAIN = "cicada/group/endpoint-key-grant-manifest/v1\u0000"
    private val utcSecondsFormatter = DateTimeFormatter
        .ofPattern("uuuu-MM-dd'T'HH:mm:ss", Locale.ROOT)
        .withZone(ZoneOffset.UTC)
    private val proofFields = listOf("version", "endpoint_id", "principal_id", "node_id",
        "binding_id", "binding_epoch", "public_identity", "signature")
    private val bindingFields = listOf("operation", "owner_id", "principal_id", "group_id",
        "endpoint_id", "node_id", "binding_id", "binding_epoch", "membership_revision",
        "endpoint_join_revision", "candidate_version", "candidate_key_id",
        "candidate_fingerprint", "candidate_proof_digest", "candidate_public_identity")
    private val manifestFields = listOf("version", "operation", "hub_id", "owner_id",
        "principal_id", "group_id", "group_revision", "endpoint_id", "node_id", "binding_id",
        "binding_epoch", "membership_revision", "endpoint_join_revision", "candidate_version",
        "candidate_key_id", "candidate_fingerprint", "candidate_proof_digest",
        "candidate_binding_digest", "candidate_public_identity", "owner_key_id", "issued_at",
        "expires_at")

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)
    private fun digest(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun value(source: JsonObject, field: String): String = source.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: throw IllegalArgumentException("Missing Group key field: $field")
    private fun positive(source: JsonObject, field: String): Long {
        val element = source.get(field)
        val token = element?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
        require(token != null && token.matches(Regex("[1-9][0-9]*"))) {
            "Invalid Group key revision: $field"
        }
        return token.toLongOrNull()?.takeIf { it > 0 }
            ?: throw IllegalArgumentException("Invalid Group key revision: $field")
    }
    private fun canonicalBase64(source: JsonObject, field: String): ByteArray {
        val encoded = value(source, field)
        val decoded = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Group key base64: $field", error)
        }
        require(Base64.getEncoder().encodeToString(decoded) == encoded) {
            "Noncanonical Group key base64: $field"
        }
        return decoded
    }
    private fun canonicalToken(value: String): Boolean = value.isNotEmpty() &&
        value.toByteArray(StandardCharsets.UTF_8).size <= 256 && value == value.trim() &&
        value.none { it.isWhitespace() || it.isISOControl() || it == '/' || it == '\\' }
    private fun fields(source: JsonObject, names: List<String>): JsonObject = JsonObject().apply {
        for (name in names) add(name, source.get(name)?.deepCopy()
            ?: throw IllegalArgumentException("Missing Group key field: $name"))
    }
    private fun hashClaims(domain: String, source: JsonObject, names: List<String>): String =
        digest(bytes(domain) + bytes(fields(source, names).toString()))
    private fun identity(source: JsonObject): ClientWireCrypto.PublicIdentity {
        require(source.size() == 3 && source.has("id") && source.has("kem_public") &&
            source.has("signing_public")) { "Invalid Endpoint public identity shape" }
        val public = ClientWireCrypto.PublicIdentity.parse(source)
        require(source.toString() == public.toJson()) { "Noncanonical Endpoint public identity" }
        return public
    }
    private fun canonicalPublic(public: ClientWireCrypto.PublicIdentity): JsonObject =
        JsonParser.parseString(public.toJson()).asJsonObject

    private fun formatCanonicalUtc(instant: Instant): String {
        val seconds = utcSecondsFormatter.format(instant)
        if (instant.nano == 0) return "${seconds}Z"
        val fraction = instant.nano.toString().padStart(9, '0').trimEnd('0')
        return "$seconds.$fraction" + "Z"
    }

    /** Matches Go's time.Parse(RFC3339Nano).UTC().Format(RFC3339Nano) round trip. */
    internal fun parseCanonicalUtc(value: String): Instant {
        val parsed = try { Instant.parse(value) }
        catch (error: DateTimeParseException) {
            throw IllegalArgumentException("Invalid Group key UTC timestamp", error)
        }
        require(formatCanonicalUtc(parsed) == value) { "Noncanonical Group key UTC timestamp" }
        return parsed
    }

    fun verifyProof(
        rawProof: ByteArray,
        expectedEndpoint: String,
        expectedPrincipal: String,
        expectedNode: String,
        expectedBinding: String,
        expectedEpoch: Long,
        expectedPublic: JsonObject,
        expectedDigest: String,
    ): ClientWireCrypto.PublicIdentity {
        require(rawProof.isNotEmpty() && rawProof.size <= 32 * 1024) { "Invalid Endpoint proof size" }
        require(listOf(expectedEndpoint, expectedPrincipal, expectedNode, expectedBinding)
            .all(::canonicalToken) && expectedEpoch > 0) { "Invalid expected Endpoint binding" }
        require(digest(rawProof) == expectedDigest) { "Endpoint proof digest mismatch" }
        val proof = JsonParser.parseString(String(rawProof, StandardCharsets.UTF_8)).asJsonObject
        require(proof.size() == proofFields.size && proof.keySet() == proofFields.toSet()) {
            "Invalid Endpoint proof shape"
        }
        require(positive(proof, "version") == 1L &&
            value(proof, "endpoint_id") == expectedEndpoint &&
            value(proof, "principal_id") == expectedPrincipal &&
            value(proof, "node_id") == expectedNode &&
            value(proof, "binding_id") == expectedBinding &&
            positive(proof, "binding_epoch") == expectedEpoch) { "Endpoint proof binding mismatch" }
        val public = identity(proof.getAsJsonObject("public_identity"))
        require(public.sameAs(identity(expectedPublic))) { "Endpoint proof public key mismatch" }
        val signed = fields(proof, proofFields).apply { add("signature", com.google.gson.JsonNull.INSTANCE) }
        val canonicalProof = fields(proof, proofFields).apply {
            add("public_identity", canonicalPublic(public))
        }.toString()
        require(MessageDigest.isEqual(rawProof, bytes(canonicalProof))) {
            "Endpoint proof is not canonical v1 JSON"
        }
        signed.add("public_identity", canonicalPublic(public))
        val signature = canonicalBase64(proof, "signature")
        require(signature.size == 3309) { "Invalid Endpoint signature size" }
        val message = bytes(PROOF_DOMAIN) + bytes(signed.toString())
        val verifier = MLDSASigner()
        verifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65,
            public.signingPublic))
        verifier.update(message, 0, message.size)
        require(verifier.verifySignature(signature)) { "Endpoint proof signature failed" }
        return public
    }

    fun verifyManifest(
        manifest: JsonObject,
        hubId: String,
        ownerId: String,
        groupId: String,
        endpointId: String,
        ownerKeyId: String,
        now: Instant = Instant.now(),
    ): JsonObject {
        require(listOf(hubId, ownerId, groupId, endpointId, ownerKeyId).all(::canonicalToken)) {
            "Invalid Group key manifest scope"
        }
        require(manifest.size() == manifestFields.size + 2 &&
            manifest.keySet() == (manifestFields + "candidate_attestation" + "digest").toSet()) {
            "Invalid Group key manifest shape"
        }
        require(positive(manifest, "version") == 1L && value(manifest, "operation") == OPERATION &&
            value(manifest, "hub_id") == hubId && value(manifest, "owner_id") == ownerId &&
            value(manifest, "group_id") == groupId && value(manifest, "endpoint_id") == endpointId &&
            value(manifest, "owner_key_id") == ownerKeyId) { "Group key manifest scope mismatch" }
        for (field in listOf("group_revision", "binding_epoch", "membership_revision",
            "endpoint_join_revision", "candidate_version")) positive(manifest, field)
        val issued = parseCanonicalUtc(value(manifest, "issued_at"))
        val expires = parseCanonicalUtc(value(manifest, "expires_at"))
        require(issued <= now && expires > now && expires > issued) {
            "Group key manifest expired or noncanonical"
        }
        val publicJson = manifest.getAsJsonObject("candidate_public_identity")
        val raw = canonicalBase64(manifest, "candidate_attestation")
        val public = verifyProof(raw, endpointId, value(manifest, "principal_id"),
            value(manifest, "node_id"), value(manifest, "binding_id"),
            positive(manifest, "binding_epoch"), publicJson,
            value(manifest, "candidate_proof_digest"))
        require(public.id == value(manifest, "candidate_key_id")) { "Endpoint key ID mismatch" }
        val fingerprint = "sha256:" + digest(bytes(FINGERPRINT_DOMAIN) +
            public.kemPublic + public.signingPublic)
        require(fingerprint == value(manifest, "candidate_fingerprint")) {
            "Endpoint key fingerprint mismatch"
        }
        val canonical = fields(manifest, manifestFields).apply {
            add("candidate_public_identity", canonicalPublic(public))
        }
        require(hashClaims(BINDING_DOMAIN, canonical, bindingFields) ==
            value(manifest, "candidate_binding_digest")) { "Endpoint binding digest mismatch" }
        require(hashClaims(MANIFEST_DOMAIN, canonical, manifestFields) ==
            value(manifest, "digest")) { "Group key manifest digest mismatch" }
        return manifest.deepCopy()
    }
}
