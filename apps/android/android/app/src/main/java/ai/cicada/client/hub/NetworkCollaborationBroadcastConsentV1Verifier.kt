package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale

/** Pure BROADCAST grant verifier. It has no TASK mode, RPC, storage, or signing API. */
internal object NetworkCollaborationBroadcastConsentV1Verifier {
    private const val GRANT_DOMAIN = "cicada/network/collaboration-key-grant/v1\u0000"
    private const val MANIFEST_DOMAIN = "cicada/network/collaboration-key-manifest/v1\u0000"
    private const val PURPOSE = "BROADCAST"
    private const val MAX_MANIFEST_BYTES = 64 * 1024
    private const val MAX_GRANT_BYTES = 16 * 1024
    private const val SIGNATURE_BYTES = 3309
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val BASE_SECONDS = DateTimeFormatter
        .ofPattern("uuuu-MM-dd'T'HH:mm:ss", Locale.ROOT)
        .withZone(ZoneOffset.UTC)

    /**
     * This context must be assembled from independently trusted Owner keys and a fresh
     * authenticated current Network/Endpoint projection. A candidate manifest alone is
     * never current authority.
     */
    data class CurrentAuthority(
        val isCurrent: Boolean,
        val hubId: String,
        val networkId: String,
        val endpointId: String,
        val principalId: String,
        val ownerId: String,
        val nodeId: String,
        val nativeSessionDigest: String,
        val bindingId: String,
        val bindingEpoch: Long,
        val membershipRevision: Long,
        val endpointEnrollmentRevision: Long,
        val candidateVersion: Long,
        val candidateFingerprint: String,
        val candidatePublicIdentity: ClientWireCrypto.PublicIdentity,
        val ownerPublicIdentity: ClientWireCrypto.PublicIdentity,
        val currentManifestDigest: String,
    )

    data class VerifiedGrant(
        val purpose: String,
        val hubId: String,
        val networkId: String,
        val endpointId: String,
        val ownerId: String,
        val ownerKeyId: String,
        val manifestDigest: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
    )

    /**
     * Verify a canonical current manifest and its separately carried Owner grant.
     * The expected authority values and owner key are supplied by the caller.
     */
    fun verify(
        manifestCanonicalJson: ByteArray,
        ownerGrantJson: ByteArray,
        authority: CurrentAuthority,
        now: Instant,
    ): VerifiedGrant {
        require(manifestCanonicalJson.isNotEmpty() && manifestCanonicalJson.size <= MAX_MANIFEST_BYTES &&
            ownerGrantJson.isNotEmpty() && ownerGrantJson.size <= MAX_GRANT_BYTES) {
            "Invalid Network collaboration manifest or grant size"
        }
        validateAuthority(authority)

        val manifest = parseCanonicalObject(manifestCanonicalJson, "Network collaboration manifest")
        require(manifest.keySet().toList() == manifestFields) {
            "Network collaboration manifest has a noncanonical field shape"
        }
        val candidate = objectField(manifest, "candidate")
        require(candidate.keySet().toList() == candidateFields) {
            "Network collaboration candidate has a noncanonical field shape"
        }
        val candidateIdentityJson = objectField(candidate, "public_identity")
        require(candidateIdentityJson.keySet().toList() == publicIdentityFields) {
            "Network collaboration candidate identity has a noncanonical field shape"
        }
        val candidateIdentity = ClientWireCrypto.PublicIdentity.parse(candidateIdentityJson)
        require(candidateIdentity.toJson() == candidateIdentityJson.toString()) {
            "Network collaboration candidate identity is not canonical"
        }

        require(integer(manifest, "version") == 1L && string(manifest, "digest").isEmpty()) {
            "Unsupported Network collaboration manifest"
        }
        require(string(manifest, "hub_id") == authority.hubId &&
            string(manifest, "network_id") == authority.networkId &&
            string(manifest, "endpoint_id") == authority.endpointId &&
            string(manifest, "principal_id") == authority.principalId &&
            string(manifest, "owner_id") == authority.ownerId &&
            string(manifest, "node_id") == authority.nodeId &&
            string(manifest, "native_session_digest") == authority.nativeSessionDigest &&
            string(manifest, "binding_id") == authority.bindingId &&
            positiveInteger(manifest, "binding_epoch") == authority.bindingEpoch &&
            positiveInteger(manifest, "membership_revision") == authority.membershipRevision &&
            positiveInteger(manifest, "endpoint_enrollment_revision") ==
                authority.endpointEnrollmentRevision) {
            "Network collaboration manifest does not match current Hub/Network/Endpoint authority"
        }
        require(string(candidate, "network_id") == authority.networkId &&
            string(candidate, "endpoint_id") == authority.endpointId &&
            string(candidate, "principal_id") == authority.principalId &&
            string(candidate, "owner_id") == authority.ownerId &&
            string(candidate, "node_id") == authority.nodeId &&
            string(candidate, "binding_id") == authority.bindingId &&
            positiveInteger(candidate, "binding_epoch") == authority.bindingEpoch &&
            positiveInteger(candidate, "version") == authority.candidateVersion &&
            string(candidate, "fingerprint") == authority.candidateFingerprint &&
            candidateIdentity.sameAs(authority.candidatePublicIdentity)) {
            "Network collaboration candidate is outside current Endpoint binding authority"
        }
        // Candidate attestation bytes are intentionally not treated as a trust anchor here.
        canonicalBase64(string(candidate, "attestation"), "candidate attestation")

        val computedManifestDigest = sha256(
            MANIFEST_DOMAIN.toByteArray(StandardCharsets.UTF_8) +
                PURPOSE.toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0) + manifestCanonicalJson,
        )
        require(computedManifestDigest == authority.currentManifestDigest) {
            "Network collaboration manifest digest differs from current authority"
        }

        val grant = parseCanonicalObject(ownerGrantJson, "Network collaboration Owner grant")
        require(grant.keySet().toList() == grantFields) {
            "Network collaboration Owner grant has a noncanonical field shape"
        }
        val version = integer(grant, "version")
        val purpose = string(grant, "purpose")
        val hubId = string(grant, "hub_id")
        val networkId = string(grant, "network_id")
        val endpointId = string(grant, "endpoint_id")
        val ownerId = string(grant, "owner_id")
        val ownerKeyId = string(grant, "owner_key_id")
        val manifestDigest = string(grant, "manifest_digest")
        val issuedAtText = string(grant, "issued_at")
        val expiresAtText = string(grant, "expires_at")
        val nonce = string(grant, "nonce")
        val signatureText = string(grant, "signature")
        val signature = canonicalBase64(signatureText, "Owner signature")

        require(version == 1L && purpose == PURPOSE && SHA256.matches(manifestDigest) &&
            SHA256.matches(nonce) && signature.size == SIGNATURE_BYTES &&
            hubId == authority.hubId && networkId == authority.networkId &&
            endpointId == authority.endpointId && ownerId == authority.ownerId &&
            ownerKeyId == authority.ownerPublicIdentity.id &&
            manifestDigest == computedManifestDigest) {
            "BROADCAST Owner grant does not match current Network collaboration authority"
        }
        val issuedAt = canonicalUtc(issuedAtText)
        val expiresAt = canonicalUtc(expiresAtText)
        require(expiresAt > issuedAt && issuedAt <= now && now < expiresAt) {
            "BROADCAST Owner grant is outside its validity interval"
        }

        val canonicalGrant = encodeGrant(
            hubId, networkId, endpointId, ownerId, ownerKeyId, manifestDigest,
            issuedAtText, expiresAtText, nonce, signatureText,
        ).toByteArray(StandardCharsets.UTF_8)
        require(MessageDigest.isEqual(ownerGrantJson, canonicalGrant)) {
            "BROADCAST Owner grant JSON is not canonical"
        }
        val signedBytes = GRANT_DOMAIN.toByteArray(StandardCharsets.UTF_8) + encodeSignedClaims(
            hubId, networkId, endpointId, ownerId, ownerKeyId, manifestDigest,
            issuedAtText, expiresAtText, nonce,
        ).toByteArray(StandardCharsets.UTF_8)
        require(ClientWireCrypto.verify(authority.ownerPublicIdentity, signedBytes, signature)) {
            "BROADCAST Owner ML-DSA signature is invalid"
        }

        return VerifiedGrant(purpose, hubId, networkId, endpointId, ownerId, ownerKeyId,
            manifestDigest, issuedAt, expiresAt)
    }

    private val manifestFields = listOf(
        "version", "hub_id", "network_id", "endpoint_id", "principal_id", "owner_id",
        "node_id", "native_session_digest", "binding_id", "binding_epoch",
        "membership_revision", "endpoint_enrollment_revision", "candidate", "digest",
    )
    private val candidateFields = listOf(
        "network_id", "endpoint_id", "principal_id", "owner_id", "node_id", "binding_id",
        "binding_epoch", "public_identity", "fingerprint", "attestation", "version",
    )
    private val publicIdentityFields = listOf("id", "kem_public", "signing_public")
    private val grantFields = listOf(
        "version", "purpose", "hub_id", "network_id", "endpoint_id", "owner_id",
        "owner_key_id", "manifest_digest", "issued_at", "expires_at", "nonce", "signature",
    )

    private fun validateAuthority(authority: CurrentAuthority) {
        require(authority.isCurrent) { "Network collaboration authority is not current" }
        require(listOf(authority.hubId, authority.networkId, authority.endpointId,
            authority.principalId, authority.ownerId, authority.nodeId, authority.bindingId,
            authority.candidateFingerprint).all(::canonicalToken) &&
            SHA256.matches(authority.nativeSessionDigest) &&
            SHA256.matches(authority.currentManifestDigest) &&
            listOf(authority.bindingEpoch, authority.membershipRevision,
                authority.endpointEnrollmentRevision, authority.candidateVersion).all { it > 0 }) {
            "Invalid current Network collaboration authority"
        }
        authority.ownerPublicIdentity.validate()
        authority.candidatePublicIdentity.validate()
    }

    private fun canonicalToken(value: String): Boolean {
        if (value.isEmpty() || value.toByteArray(StandardCharsets.UTF_8).size > 256) return false
        var offset = 0
        while (offset < value.length) {
            val point = value.codePointAt(offset)
            if (Character.isWhitespace(point) || Character.isSpaceChar(point) ||
                Character.isISOControl(point) || point == '/'.code || point == '\\'.code) return false
            offset += Character.charCount(point)
        }
        return true
    }

    private fun parseCanonicalObject(raw: ByteArray, label: String): JsonObject {
        val text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(raw)).toString()
        val parsed = JsonParser.parseString(text)
        require(parsed.isJsonObject && parsed.asJsonObject.toString() == text) {
            "Invalid or noncanonical $label JSON"
        }
        return parsed.asJsonObject
    }

    private fun objectField(value: JsonObject, name: String): JsonObject {
        val field = value.get(name)
        require(field != null && field.isJsonObject) { "Invalid $name" }
        return field.asJsonObject
    }

    private fun integer(value: JsonObject, name: String): Long {
        val field = value.get(name)
        require(field != null && field.isJsonPrimitive && field.asJsonPrimitive.isNumber &&
            Regex("0|[1-9][0-9]*").matches(field.asString)) { "Invalid $name" }
        return field.asString.toLong()
    }

    private fun positiveInteger(value: JsonObject, name: String): Long = integer(value, name).also {
        require(it > 0) { "Invalid $name" }
    }

    private fun string(value: JsonObject, name: String): String {
        val field = value.get(name)
        require(field != null && field.isJsonPrimitive && field.asJsonPrimitive.isString) {
            "Invalid $name"
        }
        return field.asString
    }

    private fun canonicalBase64(value: String, label: String): ByteArray {
        val decoded = Base64.getDecoder().decode(value)
        require(Base64.getEncoder().encodeToString(decoded) == value) { "Noncanonical $label" }
        return decoded
    }

    private fun canonicalUtc(value: String): Instant {
        val instant = Instant.parse(value)
        val seconds = BASE_SECONDS.format(instant)
        val canonical = if (instant.nano == 0) {
            "${seconds}Z"
        } else {
            "${seconds}.${instant.nano.toString().padStart(9, '0').trimEnd('0')}Z"
        }
        require(value == canonical) { "Timestamp is not canonical UTC RFC3339Nano" }
        return instant
    }

    private fun encodeSignedClaims(
        hubId: String,
        networkId: String,
        endpointId: String,
        ownerId: String,
        ownerKeyId: String,
        manifestDigest: String,
        issuedAt: String,
        expiresAt: String,
        nonce: String,
    ): String = ClientWireCrypto.json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("purpose").value(PURPOSE)
            .name("hub_id").value(hubId)
            .name("network_id").value(networkId)
            .name("endpoint_id").value(endpointId)
            .name("owner_id").value(ownerId)
            .name("owner_key_id").value(ownerKeyId)
            .name("manifest_digest").value(manifestDigest)
            .name("issued_at").value(issuedAt)
            .name("expires_at").value(expiresAt)
            .name("nonce").value(nonce)
            .name("signature").nullValue()
            .endObject()
    }

    private fun encodeGrant(
        hubId: String,
        networkId: String,
        endpointId: String,
        ownerId: String,
        ownerKeyId: String,
        manifestDigest: String,
        issuedAt: String,
        expiresAt: String,
        nonce: String,
        signature: String,
    ): String = ClientWireCrypto.json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("purpose").value(PURPOSE)
            .name("hub_id").value(hubId)
            .name("network_id").value(networkId)
            .name("endpoint_id").value(endpointId)
            .name("owner_id").value(ownerId)
            .name("owner_key_id").value(ownerKeyId)
            .name("manifest_digest").value(manifestDigest)
            .name("issued_at").value(issuedAt)
            .name("expires_at").value(expiresAt)
            .name("nonce").value(nonce)
            .name("signature").value(signature)
            .endObject()
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
