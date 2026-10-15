package ai.cicada.client.hub

import android.util.Base64
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import java.nio.charset.StandardCharsets
import java.time.Instant

/** Checks a separately signed owner consent before sending a Group key grant. */
internal object GroupKeyOwnerProof {
    private const val DOMAIN = "cicada/communication-link/owner-key-grant/v2\u0000"
    private const val PURPOSE = "group-endpoint-key-grant:v1"
    private val claims = listOf("version", "owner_id", "link_id", "contract_digest",
        "key_binding_digest", "expected_link_version", "side", "issued_at", "expires_at", "nonce")

    fun verify(
        raw: ByteArray,
        manifest: JsonObject,
        owner: ClientWireCrypto.PublicIdentity,
        now: Instant = Instant.now(),
    ) {
        require(raw.isNotEmpty() && raw.size <= 32 * 1024) { "Invalid owner proof size" }
        val proof = JsonParser.parseString(String(raw, StandardCharsets.UTF_8)).asJsonObject
        require(proof.size() == claims.size + 1 && proof.keySet() == (claims + "signature").toSet()) {
            "Invalid owner proof shape"
        }
        fun text(field: String): String = proof.get(field)?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isString
        }?.asString ?: throw IllegalArgumentException("Invalid owner proof field: $field")
        fun positiveLong(source: JsonObject, field: String): Long {
            val element = source.get(field)
            val token = element?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
            require(token != null && token.matches(Regex("[1-9][0-9]*"))) {
                "Invalid owner proof integer: $field"
            }
            return token.toLongOrNull()?.takeIf { it > 0 }
                ?: throw IllegalArgumentException("Invalid owner proof integer: $field")
        }
        require(positiveLong(proof, "version") == 2L &&
            text("owner_id") == manifest.get("owner_id").asString &&
            text("link_id") == PURPOSE && text("contract_digest") == manifest.get("digest").asString &&
            text("key_binding_digest") == manifest.get("candidate_binding_digest").asString &&
            positiveLong(proof, "expected_link_version") ==
                positiveLong(manifest, "candidate_version") &&
            text("side") == "SOURCE" &&
            text("issued_at") == manifest.get("issued_at").asString &&
            text("expires_at") == manifest.get("expires_at").asString &&
            text("nonce").matches(Regex("[0-9a-f]{64}")) &&
            owner.id == manifest.get("owner_key_id").asString) { "Owner proof is not bound to this manifest" }
        val issuedAt = GroupKeyManifestVerifier.parseCanonicalUtc(text("issued_at"))
        val expiresAt = GroupKeyManifestVerifier.parseCanonicalUtc(text("expires_at"))
        require(!issuedAt.isAfter(now) && expiresAt.isAfter(now) && expiresAt.isAfter(issuedAt)) {
            "Owner proof is outside its validity period"
        }
        val canonicalClaims = JsonObject().apply {
            for (field in claims) add(field, proof.get(field).deepCopy())
        }
        val encodedSignature = text("signature")
        val signature = try { Base64.decode(encodedSignature, Base64.NO_WRAP) }
        catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid owner signature base64", error)
        }
        require(Base64.encodeToString(signature, Base64.NO_WRAP) == encodedSignature) {
            "Owner signature must use canonical padded base64"
        }
        require(signature.size == 3309) { "Invalid owner signature size" }
        val canonicalProof = canonicalClaims.deepCopy().apply { addProperty("signature", text("signature")) }
        require(raw.contentEquals(canonicalProof.toString().toByteArray(StandardCharsets.UTF_8))) {
            "Owner proof is not canonical v2 JSON"
        }
        val signed = (DOMAIN + canonicalClaims.toString()).toByteArray(StandardCharsets.UTF_8)
        val verifier = MLDSASigner()
        verifier.init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65,
            owner.signingPublic))
        verifier.update(signed, 0, signed.size)
        require(verifier.verifySignature(signature)) { "Owner proof signature failed" }
    }
}
