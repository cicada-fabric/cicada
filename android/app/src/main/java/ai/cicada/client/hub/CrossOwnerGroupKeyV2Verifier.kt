package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

/**
 * Candidate-only verifier for the Core cross-owner Group key v2 public DTO.
 *
 * This object has no RPC, storage, or routing API. Callers must supply current
 * authority values and both Owner public keys from independently trusted,
 * authenticated sources. The Hub's `current` flag and proof-record metadata
 * are not self-authenticating; callers still need fresh authoritative state.
 * It verifies only a completed status containing both approvals, not the
 * first-Owner confirmation workflow before the second approval exists.
 */
internal object CrossOwnerGroupKeyV2Verifier {
    private const val OPERATION = "group-endpoint-key-grant:v2:cross-owner"
    private const val MANIFEST_DOMAIN = "cicada/group/cross-owner-key-manifest/v2\u0000"
    private const val BINDING_DOMAIN = "cicada/group/cross-owner-key-binding/v2\u0000"
    private const val OWNER_GRANT_DOMAIN = "cicada/communication-link/owner-key-grant/v2\u0000"
    private const val FINGERPRINT_DOMAIN = "cicada/nodekeys/peer-key-fingerprint/v1\u0000"
    private const val MAX_JSON_DEPTH = 32
    private const val MAX_JSON_NODES = 8192
    private val noncePattern = Regex("[0-9a-f]{64}")
    private val supportedCapabilities = setOf("space.read", "space.write", "space.moderate")

    // These lists mirror the field declaration order of Core's public DTOs.
    private val statusFields = listOf("manifest", "endpoint_consent", "group_admission", "current")
    private val manifestFields = listOf(
        "version", "operation", "hub_id", "network_id", "group_id", "group_revision",
        "endpoint_id", "principal_id", "endpoint_owner_id", "group_owner_id", "node_id",
        "binding_id", "binding_epoch", "membership_revision", "endpoint_join_revision",
        "candidate_version", "candidate_key_id", "candidate_fingerprint",
        "candidate_proof_digest", "candidate_public_identity", "candidate_attestation",
        "candidate_binding_digest", "capabilities", "cross_owner_context_shared",
        "history_included", "expires_at", "digest",
    )
    private val statusProofFields = listOf(
        "proof_id", "group_id", "endpoint_id", "signer_owner_id", "signer_side",
        "owner_key_id", "manifest_digest", "accepted_at", "current_status", "signed_proof",
    )
    // OwnerLinkKeyGrant v2 deliberately signs only these ten claims. Its
    // signature field is excluded, unlike Endpoint attestation v1 below.
    private val ownerGrantClaims = listOf(
        "version", "owner_id", "link_id", "contract_digest", "key_binding_digest",
        "expected_link_version", "side", "issued_at", "expires_at", "nonce",
    )
    private val ownerGrantFields = ownerGrantClaims + "signature"

    data class OwnerAuthority(
        val ownerId: String,
        val keyId: String,
        val publicIdentity: ClientWireCrypto.PublicIdentity?,
        val proofId: String,
        val acceptedAt: String,
        val grantIssuedAt: String,
        val grantExpiresAt: String,
    )

    /** Values from a fresh authority view, never copied from the candidate DTO. */
    data class AuthorityContext(
        val hubId: String,
        val networkId: String,
        val groupId: String,
        val groupRevision: Long,
        val endpointId: String,
        val principalId: String,
        val endpointOwner: OwnerAuthority,
        val groupOwner: OwnerAuthority,
        val nodeId: String,
        val bindingId: String,
        val bindingEpoch: Long,
        val membershipRevision: Long,
        val endpointJoinRevision: Long,
        val candidateVersion: Long,
        val candidatePublicIdentity: ClientWireCrypto.PublicIdentity?,
        val capabilities: List<String>,
        val manifestExpiresAt: String,
    )

    data class VerifiedCandidate(
        val publicIdentity: ClientWireCrypto.PublicIdentity,
        val manifestDigest: String,
        val candidateBindingDigest: String,
        /** Earliest expiry across the manifest and both signed Owner grants. */
        val effectiveExpiresAt: Instant,
    )

    /**
     * Verify one complete Core CrossOwnerGroupKeyStatus wire object.
     * `now` must be supplied by the caller's trusted clock.
     */
    fun verify(
        rawStatus: ByteArray,
        authority: AuthorityContext,
        now: Instant,
    ): VerifiedCandidate {
        require(rawStatus.isNotEmpty() && rawStatus.size <= 128 * 1024) {
            "Invalid cross-owner Group status size"
        }
        val status = parseStrictJson(rawStatus, "cross-owner Group status")
        shape(status, statusFields, "cross-owner Group status")
        require(status.get("current")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }
            ?.asBoolean == true) { "Cross-owner Group key status is not current" }
        validateAuthority(authority)

        val manifest = objectField(status, "manifest")
        shape(manifest, manifestFields, "cross-owner Group manifest")
        require(positive(manifest, "version") == 2L && text(manifest, "operation") == OPERATION) {
            "Unsupported cross-owner Group manifest version or operation"
        }
        require(text(manifest, "hub_id") == authority.hubId &&
            text(manifest, "network_id") == authority.networkId &&
            text(manifest, "group_id") == authority.groupId &&
            positive(manifest, "group_revision") == authority.groupRevision &&
            text(manifest, "endpoint_id") == authority.endpointId &&
            text(manifest, "principal_id") == authority.principalId &&
            text(manifest, "endpoint_owner_id") == authority.endpointOwner.ownerId &&
            text(manifest, "group_owner_id") == authority.groupOwner.ownerId &&
            text(manifest, "node_id") == authority.nodeId &&
            text(manifest, "binding_id") == authority.bindingId &&
            positive(manifest, "binding_epoch") == authority.bindingEpoch &&
            positive(manifest, "membership_revision") == authority.membershipRevision &&
            positive(manifest, "endpoint_join_revision") == authority.endpointJoinRevision &&
            positive(manifest, "candidate_version") == authority.candidateVersion
        ) { "Cross-owner Group authority context changed" }

        require(manifest.get("cross_owner_context_shared")?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isBoolean
        }?.asBoolean == true && manifest.get("history_included")?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isBoolean
        }?.asBoolean == false) { "Cross-owner Group context flags are invalid" }
        val capabilities = stringArray(manifest, "capabilities")
        require(capabilities == authority.capabilities && capabilities.distinct().size == capabilities.size &&
            "space.read" in capabilities) { "Cross-owner Group capabilities changed" }

        val expiresAtText = text(manifest, "expires_at")
        require(expiresAtText == authority.manifestExpiresAt) {
            "Cross-owner Group manifest expiry changed"
        }
        val manifestExpiry = GroupKeyManifestVerifier.parseCanonicalUtc(expiresAtText)
        require(manifestExpiry > now) { "Cross-owner Group manifest expired" }

        val public = identity(objectField(manifest, "candidate_public_identity"))
        val expectedPublic = requireNotNull(authority.candidatePublicIdentity) {
            "Missing independently trusted candidate identity"
        }.also { it.validate() }
        require(public.sameAs(expectedPublic) &&
            public.id == text(manifest, "candidate_key_id")) {
            "Cross-owner Group candidate identity changed"
        }

        val attestation = canonicalBase64(manifest, "candidate_attestation")
        val proofDigest = sha256(attestation)
        require(proofDigest == text(manifest, "candidate_proof_digest")) {
            "Endpoint attestation digest mismatch"
        }
        val attestedPublic = GroupKeyManifestVerifier.verifyProof(
            rawProof = attestation,
            expectedEndpoint = authority.endpointId,
            expectedPrincipal = authority.principalId,
            expectedNode = authority.nodeId,
            expectedBinding = authority.bindingId,
            expectedEpoch = authority.bindingEpoch,
            expectedPublic = publicJson(public),
            expectedDigest = proofDigest,
        )
        require(attestedPublic.sameAs(public)) { "Endpoint attestation identity mismatch" }

        val fingerprint = "sha256:" + sha256(
            bytes(FINGERPRINT_DOMAIN) + public.kemPublic + public.signingPublic,
        )
        require(fingerprint == text(manifest, "candidate_fingerprint")) {
            "Endpoint key fingerprint mismatch"
        }

        val bindingDigest = bindingDigest(manifest)
        require(bindingDigest == text(manifest, "candidate_binding_digest")) {
            "Cross-owner Group candidate binding digest mismatch"
        }
        val manifestDigest = manifestDigest(manifest, public)
        require(manifestDigest == text(manifest, "digest")) {
            "Cross-owner Group manifest digest mismatch"
        }

        val endpointGrantExpiry = verifyOwnerProof(
            objectField(status, "endpoint_consent"), manifest, authority.endpointOwner,
            role = "ENDPOINT", signedSide = "SOURCE", expectedManifestDigest = manifestDigest,
            expectedBindingDigest = bindingDigest, expectedVersion = authority.candidateVersion,
            manifestExpiry = manifestExpiry, now = now,
        )
        val groupGrantExpiry = verifyOwnerProof(
            objectField(status, "group_admission"), manifest, authority.groupOwner,
            role = "GROUP", signedSide = "TARGET", expectedManifestDigest = manifestDigest,
            expectedBindingDigest = bindingDigest, expectedVersion = authority.candidateVersion,
            manifestExpiry = manifestExpiry, now = now,
        )

        val effectiveExpiry = minOf(manifestExpiry, endpointGrantExpiry, groupGrantExpiry)
        return VerifiedCandidate(public, manifestDigest, bindingDigest, effectiveExpiry)
    }

    private fun validateAuthority(authority: AuthorityContext) {
        require(listOf(authority.hubId, authority.networkId, authority.groupId,
            authority.endpointId, authority.principalId, authority.nodeId, authority.bindingId,
            authority.endpointOwner.ownerId, authority.groupOwner.ownerId).all(::canonicalToken)) {
            "Invalid external cross-owner Group authority context"
        }
        require(authority.endpointOwner.ownerId != authority.groupOwner.ownerId &&
            authority.endpointOwner.keyId != authority.groupOwner.keyId) {
            "Cross-owner Group trust requires two distinct Owners and keys"
        }
        val endpointPublic = requireNotNull(authority.endpointOwner.publicIdentity) {
            "Missing independently trusted Endpoint Owner key"
        }.also { it.validate() }
        val groupPublic = requireNotNull(authority.groupOwner.publicIdentity) {
            "Missing independently trusted Group Owner key"
        }.also { it.validate() }
        require(endpointPublic.id == authority.endpointOwner.keyId &&
            groupPublic.id == authority.groupOwner.keyId && !endpointPublic.sameAs(groupPublic)) {
            "Cross-owner Group Owner trust keys do not match their authority records"
        }
        require(authority.endpointOwner.proofId != authority.groupOwner.proofId &&
            listOf(authority.endpointOwner.proofId, authority.groupOwner.proofId).all(::canonicalToken)) {
            "Cross-owner Group Owner proof records are not distinct"
        }
        require(listOf(authority.groupRevision, authority.bindingEpoch,
            authority.membershipRevision, authority.endpointJoinRevision,
            authority.candidateVersion).all { it > 0 }) {
            "Invalid external cross-owner Group revisions"
        }
        require(authority.capabilities.isNotEmpty() &&
            authority.capabilities.all { it in supportedCapabilities } &&
            "space.read" in authority.capabilities) {
            "Invalid external cross-owner Group capabilities"
        }
        GroupKeyManifestVerifier.parseCanonicalUtc(authority.endpointOwner.acceptedAt)
        GroupKeyManifestVerifier.parseCanonicalUtc(authority.groupOwner.acceptedAt)
        listOf(authority.endpointOwner, authority.groupOwner).forEach { owner ->
            require(canonicalToken(owner.keyId) &&
                owner.proofId.isNotEmpty()) { "Invalid expected Owner grant authority" }
            GroupKeyManifestVerifier.parseCanonicalUtc(owner.grantIssuedAt)
            GroupKeyManifestVerifier.parseCanonicalUtc(owner.grantExpiresAt)
        }
        GroupKeyManifestVerifier.parseCanonicalUtc(authority.manifestExpiresAt)
        require(authority.capabilities.distinct().size == authority.capabilities.size) {
            "Duplicate external cross-owner Group capability"
        }
    }

    private fun verifyOwnerProof(
        statusProof: JsonObject,
        manifest: JsonObject,
        authority: OwnerAuthority,
        role: String,
        signedSide: String,
        expectedManifestDigest: String,
        expectedBindingDigest: String,
        expectedVersion: Long,
        manifestExpiry: Instant,
        now: Instant,
    ): Instant {
        shape(statusProof, statusProofFields, "cross-owner Group Owner proof record")
        require(text(statusProof, "proof_id") == authority.proofId &&
            text(statusProof, "group_id") == text(manifest, "group_id") &&
            text(statusProof, "endpoint_id") == text(manifest, "endpoint_id") &&
            text(statusProof, "signer_owner_id") == authority.ownerId &&
            text(statusProof, "signer_side") == role &&
            text(statusProof, "owner_key_id") == authority.keyId &&
            text(statusProof, "manifest_digest") == expectedManifestDigest &&
            text(statusProof, "current_status") == "CURRENT") {
            "Cross-owner Group Owner proof record does not match its role"
        }
        val acceptedAtText = text(statusProof, "accepted_at")
        val acceptedAt = GroupKeyManifestVerifier.parseCanonicalUtc(acceptedAtText)
        require(acceptedAtText == authority.acceptedAt && acceptedAt <= now) {
            "Cross-owner Group Owner proof acceptance state changed"
        }

        val rawProof = canonicalBase64(statusProof, "signed_proof")
        require(rawProof.isNotEmpty() && rawProof.size <= 32 * 1024) {
            "Invalid cross-owner Group Owner proof size"
        }
        val proof = parseStrictJson(rawProof, "OwnerLinkKeyGrant v2")
        shape(proof, ownerGrantFields, "OwnerLinkKeyGrant v2")
        require(positive(proof, "version") == 2L &&
            text(proof, "owner_id") == authority.ownerId &&
            text(proof, "link_id") == OPERATION &&
            text(proof, "contract_digest") == expectedManifestDigest &&
            text(proof, "key_binding_digest") == expectedBindingDigest &&
            positive(proof, "expected_link_version") == expectedVersion &&
            text(proof, "side") == signedSide &&
            text(proof, "issued_at") == authority.grantIssuedAt &&
            text(proof, "expires_at") == authority.grantExpiresAt &&
            text(proof, "nonce").matches(noncePattern)) {
            "OwnerLinkKeyGrant v2 claims do not match the exact Group proof"
        }

        val issuedAt = GroupKeyManifestVerifier.parseCanonicalUtc(text(proof, "issued_at"))
        val expiresAt = GroupKeyManifestVerifier.parseCanonicalUtc(text(proof, "expires_at"))
        require(issuedAt <= now && expiresAt > now && expiresAt > issuedAt &&
            expiresAt <= manifestExpiry && acceptedAt >= issuedAt && acceptedAt < expiresAt) {
            "OwnerLinkKeyGrant v2 is outside its authority period"
        }

        val claims = orderedFields(proof, ownerGrantClaims)
        val signatureText = text(proof, "signature")
        val canonicalProof = claims.deepCopy().apply { addProperty("signature", signatureText) }
        require(MessageDigest.isEqual(rawProof, bytes(canonicalJson(canonicalProof)))) {
            "OwnerLinkKeyGrant v2 is not canonical JSON"
        }
        val signature = canonicalBase64(proof, "signature")
        require(signature.size == 3309) { "Invalid OwnerLinkKeyGrant v2 signature size" }
        val signed = bytes(OWNER_GRANT_DOMAIN) + bytes(canonicalJson(claims))
        val trustedOwner = requireNotNull(authority.publicIdentity) {
            "Missing independently trusted Owner key"
        }
        require(ClientWireCrypto.verify(trustedOwner, signed, signature)) {
            "OwnerLinkKeyGrant v2 signature failed"
        }
        return expiresAt
    }

    private fun manifestDigest(manifest: JsonObject, public: ClientWireCrypto.PublicIdentity): String {
        val claims = JsonObject()
        for (field in manifestFields) {
            when (field) {
                "candidate_public_identity" -> claims.add(field, publicJson(public))
                "digest" -> claims.addProperty(field, "")
                else -> claims.add(field, manifest.get(field).deepCopy())
            }
        }
        return sha256(bytes(MANIFEST_DOMAIN) + bytes(canonicalJson(claims)))
    }

    private fun bindingDigest(manifest: JsonObject): String {
        val claims = JsonObject().apply {
            add("hub_id", manifest.get("hub_id").deepCopy())
            add("network_id", manifest.get("network_id").deepCopy())
            add("group_id", manifest.get("group_id").deepCopy())
            add("endpoint_id", manifest.get("endpoint_id").deepCopy())
            add("binding_id", manifest.get("binding_id").deepCopy())
            add("binding_epoch", manifest.get("binding_epoch").deepCopy())
            add("candidate_key_id", manifest.get("candidate_key_id").deepCopy())
            add("candidate_version", manifest.get("candidate_version").deepCopy())
            add("fingerprint", manifest.get("candidate_fingerprint").deepCopy())
            add("proof_digest", manifest.get("candidate_proof_digest").deepCopy())
        }
        return sha256(bytes(BINDING_DOMAIN) + bytes(canonicalJson(claims)))
    }

    private fun identity(source: JsonObject): ClientWireCrypto.PublicIdentity {
        shape(source, listOf("id", "kem_public", "signing_public"), "Endpoint public identity")
        val id = text(source, "id")
        val kem = canonicalBase64(source, "kem_public")
        val signing = canonicalBase64(source, "signing_public")
        return ClientWireCrypto.PublicIdentity(id, kem, signing).also { it.validate() }
    }

    private fun publicJson(public: ClientWireCrypto.PublicIdentity): JsonObject = JsonObject().apply {
        addProperty("id", public.id)
        addProperty("kem_public", Base64.getEncoder().encodeToString(public.kemPublic))
        addProperty("signing_public", Base64.getEncoder().encodeToString(public.signingPublic))
    }

    private fun canonicalBase64(source: JsonObject, field: String): ByteArray {
        val encoded = text(source, field)
        val decoded = try { Base64.getDecoder().decode(encoded) }
        catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid cross-owner Group base64 field: $field", error)
        }
        require(Base64.getEncoder().encodeToString(decoded) == encoded) {
            "Noncanonical cross-owner Group base64 field: $field"
        }
        return decoded
    }

    private fun orderedFields(source: JsonObject, names: List<String>): JsonObject = JsonObject().apply {
        for (name in names) add(name, source.get(name)?.deepCopy()
            ?: throw IllegalArgumentException("Missing cross-owner Group field: $name"))
    }

    private fun shape(source: JsonObject, names: List<String>, label: String) {
        require(source.size() == names.size && source.keySet() == names.toSet()) {
            "Invalid $label fields"
        }
    }

    private fun text(source: JsonObject, name: String): String = source.get(name)?.takeIf {
        it.isJsonPrimitive && it.asJsonPrimitive.isString
    }?.asString ?: throw IllegalArgumentException("Invalid cross-owner Group field: $name")

    private fun objectField(source: JsonObject, name: String): JsonObject = source.get(name)
        ?.takeIf { it.isJsonObject }?.asJsonObject
        ?: throw IllegalArgumentException("Invalid cross-owner Group object: $name")

    private fun positive(source: JsonObject, name: String): Long {
        val primitive = source.get(name)?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isNumber
        }?.asJsonPrimitive ?: throw IllegalArgumentException("Invalid cross-owner Group integer: $name")
        val token = primitive.asString
        require(token.matches(Regex("[1-9][0-9]*"))) {
            "Noncanonical cross-owner Group integer: $name"
        }
        return token.toLongOrNull()?.takeIf { it > 0 }
            ?: throw IllegalArgumentException("Invalid cross-owner Group integer: $name")
    }

    private fun stringArray(source: JsonObject, name: String): List<String> {
        val array = source.get(name)?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Invalid cross-owner Group array: $name")
        return array.map { element ->
            element.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: throw IllegalArgumentException("Invalid cross-owner Group array member: $name")
        }
    }

    private fun canonicalToken(value: String): Boolean = value.isNotEmpty() &&
        value == value.trim() && value.toByteArray(StandardCharsets.UTF_8).size <= 256 &&
        value.none { it.isWhitespace() || it.isISOControl() || it == '/' || it == '\\' } &&
        isValidUtf8(value)

    private fun isValidUtf8(value: String): Boolean = try {
        StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value))
        true
    } catch (_: Exception) {
        false
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)

    /** encoding/json-compatible compact JSON for the ASCII claims used in these DTOs. */
    private fun canonicalJson(value: JsonElement): String = buildString {
        appendJson(value, this)
    }

    private fun appendJson(value: JsonElement, out: StringBuilder) {
        when {
            value.isJsonNull -> out.append("null")
            value.isJsonObject -> {
                out.append('{')
                var first = true
                for ((name, child) in value.asJsonObject.entrySet()) {
                    if (!first) out.append(',')
                    first = false
                    appendQuoted(name, out)
                    out.append(':')
                    appendJson(child, out)
                }
                out.append('}')
            }
            value.isJsonArray -> {
                out.append('[')
                value.asJsonArray.forEachIndexed { index, child ->
                    if (index > 0) out.append(',')
                    appendJson(child, out)
                }
                out.append(']')
            }
            value.asJsonPrimitive.isString -> appendQuoted(value.asString, out)
            value.asJsonPrimitive.isBoolean || value.asJsonPrimitive.isNumber ->
                out.append(value.asJsonPrimitive.asString)
            else -> throw IllegalArgumentException("Unsupported cross-owner Group JSON value")
        }
    }

    private fun appendQuoted(value: String, out: StringBuilder) {
        out.append('"')
        for (character in value) {
            when (character) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000c' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '<' -> out.append("\\u003c")
                '>' -> out.append("\\u003e")
                '&' -> out.append("\\u0026")
                '\u2028' -> out.append("\\u2028")
                '\u2029' -> out.append("\\u2029")
                else -> if (character.code < 0x20) {
                    out.append("\\u").append(character.code.toString(16).padStart(4, '0'))
                } else {
                    out.append(character)
                }
            }
        }
        out.append('"')
    }

    private fun parseStrictJson(raw: ByteArray, label: String): JsonObject {
        val decoded = try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
        } catch (error: Exception) {
            throw IllegalArgumentException("Invalid UTF-8 in $label", error)
        }
        require(!decoded.startsWith('\uFEFF')) { "Invalid UTF-8 BOM in $label" }
        return try {
            JsonReader(StringReader(decoded)).apply { strictness = Strictness.STRICT }.use { reader ->
                val parsed = readValue(reader, label, depth = 0, nodes = intArrayOf(0))
                require(reader.peek() == JsonToken.END_DOCUMENT && parsed.isJsonObject) {
                    "Invalid JSON object in $label"
                }
                parsed.asJsonObject
            }
        } catch (error: IOException) {
            throw IllegalArgumentException("Malformed JSON in $label", error)
        }
    }

    /** JsonReader's object builder would overwrite duplicate names; reject them explicitly. */
    private fun readValue(
        reader: JsonReader,
        label: String,
        depth: Int,
        nodes: IntArray,
    ): JsonElement {
        require(depth <= MAX_JSON_DEPTH) { "JSON nesting limit exceeded in $label" }
        nodes[0] += 1
        require(nodes[0] <= MAX_JSON_NODES) { "JSON item limit exceeded in $label" }
        return when (reader.peek()) {
            JsonToken.BEGIN_OBJECT -> {
                reader.beginObject()
                val value = JsonObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    require(!value.has(name)) { "Duplicate field in $label" }
                    value.add(name, readValue(reader, label, depth + 1, nodes))
                }
                reader.endObject()
                value
            }
            JsonToken.BEGIN_ARRAY -> {
                reader.beginArray()
                val value = JsonArray()
                while (reader.hasNext()) value.add(readValue(reader, label, depth + 1, nodes))
                reader.endArray()
                value
            }
            JsonToken.STRING -> JsonPrimitive(reader.nextString())
            JsonToken.NUMBER -> {
                val token = reader.nextString()
                require(token.matches(Regex("0|[1-9][0-9]*"))) {
                    "Noncanonical integer in $label"
                }
                val number = token.toLongOrNull()
                    ?: throw IllegalArgumentException("Integer overflow in $label")
                JsonPrimitive(number)
            }
            JsonToken.BOOLEAN -> JsonPrimitive(reader.nextBoolean())
            JsonToken.NULL -> {
                reader.nextNull()
                JsonNull.INSTANCE
            }
            else -> throw IllegalArgumentException("Invalid JSON token in $label")
        }
    }
}
