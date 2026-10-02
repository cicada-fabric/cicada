package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Collections

/**
 * Native-only, in-memory provenance for one direct `link.key_manifest` response.
 * ClientHubSession may create it only after the pinned Hub response has passed
 * signature/decryption, operation-ID, request-sequence, response-sequence, and
 * active-profile checks. This object must never be serialized to or reconstructed
 * from React Native data.
 */
internal class FreshLinkManifestRead internal constructor(
    val profileId: String,
    val profileGeneration: Long,
    val hubId: String,
    val ownerId: String,
    val deviceId: String,
    val sessionEpoch: Long,
    val operation: String,
    val operationId: String,
    val requestSequence: Long,
    val responseSequence: Long,
    val authenticatedResultSha256: String,
    val selectedLinkId: String,
    val selectedLinkVersion: Long,
    val localSide: String,
)

/**
 * Native-only provenance for a direct `link.key_grants` result, captured after
 * the encrypted session authenticates and correlates that response. The
 * manifest digest binds the status read to one previously verified manifest;
 * the result hash binds the exact returned array. This object must not cross
 * the React Native bridge or be recreated from cached/recovered JSON.
 */
internal class FreshLinkOwnerGrantStatusRead internal constructor(
    val profileId: String,
    val profileGeneration: Long,
    val hubId: String,
    val ownerId: String,
    val deviceId: String,
    val sessionEpoch: Long,
    val operation: String,
    val operationId: String,
    val requestSequence: Long,
    val responseSequence: Long,
    val authenticatedResultSha256: String,
    val selectedLinkId: String,
    val selectedLinkVersion: Long,
    val localSide: String,
    val manifestDigest: String,
)

/** Shared structural checks for untrusted key-grant result rows. */
private object LinkConsentStatusShape {
    val sha256Hex = Regex("[0-9a-f]{64}")
    val fields = setOf(
        "link_id", "side", "owner_id", "key_id", "manifest_digest", "accepted",
        "accepted_at", "current_status", "evidence",
    )
    val requiredFields = setOf("link_id", "side", "owner_id", "accepted", "current_status")
    val currentStatuses = setOf(
        "MISSING", "ACCEPTED", "KEY_BINDING_STALE", "OWNER_KEY_REVOKED",
        "PROOF_EXPIRED", "INVALID", "LEGACY_KEY_UNBOUND",
    )

    fun validToken(value: String): Boolean = value.isNotEmpty() && value.length <= 256 &&
        value == value.trim() && value.none { Character.isISOControl(it) || it == '/' || it == '\\' }
}

/**
 * Result of validating one current, authenticated Link manifest and binding it
 * to externally trusted Owner identity pins. It does not claim that either
 * Owner's grant was accepted, that the Link is routable, or that review policy
 * is active. Freshness is transaction-scoped: callers must obtain a new
 * `FreshLinkManifestRead` before any later confirmation and consume it once in
 * their native review ledger.
 */
internal class VerifiedCurrentLinkAuthority internal constructor(
    val provenance: FreshLinkManifestRead,
    val currentLink: LinkKeyManifestVerifier.CurrentLinkAuthority,
    val manifest: LinkKeyManifestVerifier.VerifiedManifest,
    sourceOwnerPin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
    targetOwnerPin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
    private val manifestJson: JsonObject,
) {
    private val sourcePin = copyOwnerPin(sourceOwnerPin)
    private val targetPin = copyOwnerPin(targetOwnerPin)
    val sourceOwnerPin: LinkKeyManifestVerifier.OwnerPublicKeyPin get() = copyOwnerPin(sourcePin)
    val targetOwnerPin: LinkKeyManifestVerifier.OwnerPublicKeyPin get() = copyOwnerPin(targetPin)

    /**
     * Checks both retained OwnerLinkKeyGrant v2 proofs and their current Hub
     * status against these exact full-key pins and the verified manifest tuple.
     * `accepted=true` by itself is never sufficient.
     */
    fun verifyOwnerGrants(
        provenance: FreshLinkOwnerGrantStatusRead,
        result: JsonArray,
        now: Instant = Instant.now(),
    ): LinkKeyManifestVerifier.VerifiedRetainedOwnerConsents {
        val statuses = verifiedStatusArray(provenance, result)
        return LinkKeyManifestVerifier.verifyRetainedOwnerConsentsCandidateV164(
            manifestJson = manifestJson.deepCopy(),
            statuses = statuses,
            currentLink = currentLink,
            trustedSourceOwnerPin = sourcePin,
            trustedTargetOwnerPin = targetPin,
            now = now,
        )
    }

    /**
     * Verifies the selected side's current retained proof and key lifecycle
     * from the same directly authenticated status read. A valid non-current
     * status returns null; this method never makes a claim about peer consent.
     */
    fun verifyOwnerGrantStatusForSide(
        provenance: FreshLinkOwnerGrantStatusRead,
        result: JsonArray,
        side: String,
        now: Instant = Instant.now(),
    ): LinkKeyManifestVerifier.VerifiedRetainedOwnerGrantStatus? {
        require(side == "SOURCE" || side == "TARGET") { "Invalid Link Owner side" }
        val statuses = verifiedStatusArray(provenance, result)
        val selected = statuses.single { it.get("side").asString == side }
        val pin = if (side == "SOURCE") sourcePin else targetPin
        return LinkKeyManifestVerifier.verifyRetainedOwnerGrantStatusCandidateV164(
            manifestJson = manifestJson.deepCopy(),
            status = selected,
            currentLink = currentLink,
            trustedOwnerPin = pin,
            side = side,
            now = now,
        )
    }

    private fun verifiedStatusArray(
        statusRead: FreshLinkOwnerGrantStatusRead,
        result: JsonArray,
    ): List<JsonObject> {
        require(statusRead.profileId == provenance.profileId &&
            statusRead.profileGeneration == provenance.profileGeneration &&
            statusRead.hubId == provenance.hubId &&
            statusRead.ownerId == provenance.ownerId &&
            statusRead.deviceId == provenance.deviceId &&
            statusRead.sessionEpoch == provenance.sessionEpoch &&
            statusRead.operation == "link.key_grants" &&
            LinkConsentStatusShape.validToken(statusRead.operationId) && statusRead.requestSequence > 0 &&
            statusRead.responseSequence > 0 && statusRead.selectedLinkId == currentLink.linkId &&
            statusRead.selectedLinkVersion == currentLink.linkVersion &&
            statusRead.localSide == provenance.localSide &&
            statusRead.manifestDigest == manifest.digest &&
            statusRead.localSide in setOf("SOURCE", "TARGET") &&
            statusRead.ownerId == (if (statusRead.localSide == "SOURCE") currentLink.source.ownerId
                else currentLink.target.ownerId) &&
            LinkConsentStatusShape.sha256Hex.matches(statusRead.authenticatedResultSha256)) {
            "Invalid authenticated Link key-grant status provenance"
        }
        val snapshot = result.deepCopy()
        require(LinkConsentAuthorityFactory.ownerGrantStatusResultSha256(snapshot) == statusRead.authenticatedResultSha256) {
            "Link key-grant status result differs from the authenticated native response"
        }
        require(snapshot.size() == 2) { "Expected both Link Owner status rows" }
        val statuses = snapshot.map { element ->
            element.takeIf { it.isJsonObject }?.asJsonObject?.deepCopy()
                ?: throw IllegalArgumentException("Invalid Link Owner status row")
        }
        require(statuses.map { it.get("side")?.asString }.toSet() == setOf("SOURCE", "TARGET")) {
            "Expected one status for each Link Owner side"
        }
        statuses.forEach { status ->
            val side = status.get("side")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: throw IllegalArgumentException("Invalid Link Owner status side")
            val owner = status.get("owner_id")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: throw IllegalArgumentException("Invalid Link Owner status owner")
            val linkId = status.get("link_id")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: throw IllegalArgumentException("Invalid Link Owner status Link")
            val accepted = status.get("accepted")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
                ?: throw IllegalArgumentException("Invalid Link Owner acceptance status")
            val currentStatus = status.get("current_status")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: throw IllegalArgumentException("Invalid Link Owner current status")
            val expectedOwner = if (side == "SOURCE") currentLink.source.ownerId
                else currentLink.target.ownerId
            require(status.keySet().all { it in LinkConsentStatusShape.fields } &&
                status.keySet().containsAll(LinkConsentStatusShape.requiredFields) &&
                linkId == currentLink.linkId && owner == expectedOwner &&
                currentStatus in LinkConsentStatusShape.currentStatuses &&
                (currentStatus != "ACCEPTED" || accepted)) {
                "Link Owner status is outside the verified current Link tuple"
            }
        }
        return statuses
    }

    /**
     * Verifies one offline OwnerLinkKeyGrant proof by full public key and exact
     * Link tuple. This checks signature, canonical bytes, side, nonce shape and
     * time bounds; it does not assert that the Hub currently accepts the grant.
     */
    fun verifyOwnerGrant(
        side: String,
        rawProof: ByteArray,
        now: Instant = Instant.now(),
    ): LinkKeyManifestVerifier.VerifiedOwnerGrant =
        LinkKeyManifestVerifier.verifyOwnerGrant(
            rawProof = rawProof.clone(),
            pinnedOwnerKey = when (side) {
                "SOURCE" -> sourcePin
                "TARGET" -> targetPin
                else -> throw IllegalArgumentException("Invalid Link Owner side")
            },
            currentLink = currentLink,
            manifestJson = manifestJson.deepCopy(),
            side = side,
            now = now,
        )

    /** Maps verified Link scope and independent identity pins to the policy verifier input. */
    fun asPolicyCurrentLink(): LinkReviewPolicyV164CurrentLink = LinkReviewPolicyV164CurrentLink(
        linkId = currentLink.linkId,
        linkVersion = currentLink.linkVersion,
        contractDigest = manifest.contractDigest,
        localSide = provenance.localSide,
        sourceOwnerId = currentLink.source.ownerId,
        targetOwnerId = currentLink.target.ownerId,
        sourceEndpointId = currentLink.source.endpointId,
        sourceGroupId = currentLink.source.groupId,
        targetEndpointId = currentLink.target.endpointId,
        targetGroupId = currentLink.target.groupId,
        expiresAt = manifest.linkExpiresAt,
        sourceOwnerPin = sourcePin.toPolicyPin(),
        targetOwnerPin = targetPin.toPolicyPin(),
    )

    private fun LinkKeyManifestVerifier.OwnerPublicKeyPin.toPolicyPin() =
        LinkReviewPolicyV164OwnerPin(ownerId, keyId, copyIdentity(publicIdentity))
}

private fun copyOwnerPin(pin: LinkKeyManifestVerifier.OwnerPublicKeyPin) =
    LinkKeyManifestVerifier.OwnerPublicKeyPin(
        ownerId = pin.ownerId,
        keyId = pin.keyId,
        publicIdentity = copyIdentity(pin.publicIdentity),
    )

private fun copyIdentity(identity: ClientWireCrypto.PublicIdentity) =
    ClientWireCrypto.PublicIdentity(identity.id, identity.kemPublic, identity.signingPublic)

/** Builds verified Link scope only from a fresh, directly authenticated native manifest read. */
internal object LinkConsentAuthorityFactory {
    /** Candidate validation is not production operation or release authority. */
    const val CANDIDATE_READY = true

    private const val MAX_CONTRACT_BYTES = 32 * 1024
    private val manifestFields = listOf(
        "version", "link_id", "link_version", "contract_digest", "contract_canonical",
        "source", "target", "digest",
    )
    private val contractFields = listOf(
        "link_id", "source_endpoint_id", "source_principal_id", "source_group_id",
        "source_owner_id", "source_node_id", "target_endpoint_id", "target_principal_id",
        "target_group_id", "target_owner_id", "target_node_id", "direction", "actions",
        "data_scopes", "transport_hub_id", "expires_at", "scope_snapshot",
    )
    private val scopeSnapshotFields = listOf(
        "source_membership_revision", "source_join_revision", "source_group_version",
        "target_membership_revision", "target_join_revision", "target_group_version",
    )
    private val candidateFields = listOf(
        "endpoint_id", "group_id", "principal_id", "owner_id", "node_id", "binding_id",
        "binding_epoch", "candidate_version", "key_id", "key_fingerprint", "proof_digest",
        "public_identity", "attestation",
    )

    /**
     * Stable content binding for the opaque native response provenance. The
     * session computes this on the directly authenticated decrypted result and
     * the factory recomputes it before parsing; the hash itself is not proof of
     * authentication or freshness.
     */
    internal fun manifestResultSha256(manifestJson: JsonObject): String = sha256(
        manifestJson.toString().toByteArray(StandardCharsets.UTF_8),
    )

    /** Stable content binding for the exact authenticated `link.key_grants` result array. */
    internal fun ownerGrantStatusResultSha256(result: JsonArray): String = sha256(
        result.toString().toByteArray(StandardCharsets.UTF_8),
    )

    /**
     * Reconstructs the current Link scope from the Hub's single-transaction
     * `link.key_manifest` snapshot, verifies its full canonical bytes and both
     * complete Endpoint attestations, and checks independent source/target
     * Owner public-key pins. Owner current-registration state/version do not
     * appear in this manifest and are never invented here. The manifest DTO
     * has no Link-state field; `PROPOSED` is asserted because Core's
     * `GetCommunicationLinkKeyManifest` calls `validateCurrentCommunicationLinkScope`,
     * which rejects every Link state except `CommunicationLinkProposed` before
     * returning the manifest. The authenticated result still must match the
     * natively captured selection's Link ID and version.
     */
    fun verifyFreshManifest(
        provenance: FreshLinkManifestRead,
        manifestJson: JsonObject,
        sourceOwnerPin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
        targetOwnerPin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
        now: Instant = Instant.now(),
    ): VerifiedCurrentLinkAuthority {
        validateProvenance(provenance)
        require(manifestResultSha256(manifestJson) == provenance.authenticatedResultSha256) {
            "Link manifest result differs from the authenticated native response"
        }
        val current = authorityFromManifest(manifestJson)
        require(current.linkId == provenance.selectedLinkId &&
            current.linkVersion == provenance.selectedLinkVersion) {
            "Fresh Link manifest differs from the authenticated selected Link version"
        }
        val localOwner = if (provenance.localSide == "SOURCE") current.source.ownerId
            else current.target.ownerId
        require(localOwner == provenance.ownerId) {
            "Fresh Link manifest side does not belong to the authenticated local Owner"
        }
        validateOwnerPin(sourceOwnerPin, current.source.ownerId)
        validateOwnerPin(targetOwnerPin, current.target.ownerId)

        val manifestCopy = manifestJson.deepCopy()
        val verifiedManifest = LinkKeyManifestVerifier.verifyManifest(manifestCopy, current, now)
        require(verifiedManifest.linkId == provenance.selectedLinkId &&
            verifiedManifest.linkVersion == provenance.selectedLinkVersion) {
            "Verified Link manifest differs from the authenticated selected Link version"
        }
        return VerifiedCurrentLinkAuthority(
            provenance = provenance,
            currentLink = current,
            manifest = verifiedManifest,
            sourceOwnerPin = sourceOwnerPin,
            targetOwnerPin = targetOwnerPin,
            manifestJson = manifestCopy,
        )
    }

    private fun validateProvenance(provenance: FreshLinkManifestRead) {
        require(provenance.profileId.isNotEmpty() && provenance.profileId.length <= 256 &&
            provenance.profileGeneration > 0 && validToken(provenance.hubId) &&
            validToken(provenance.ownerId) && validToken(provenance.deviceId) &&
            provenance.sessionEpoch > 0 && provenance.operation == "link.key_manifest" &&
            validToken(provenance.operationId) && provenance.requestSequence > 0 &&
            provenance.responseSequence > 0 && SHA256_HEX.matches(provenance.authenticatedResultSha256) &&
            validToken(provenance.selectedLinkId) &&
            provenance.selectedLinkVersion > 0 && provenance.localSide in setOf("SOURCE", "TARGET")) {
            "Invalid authenticated Link manifest read provenance"
        }
    }

    /** Parses only enough strict DTO data to reconstruct the verifier's expected current scope. */
    private fun authorityFromManifest(manifest: JsonObject): LinkKeyManifestVerifier.CurrentLinkAuthority {
        requireOrderedFields(manifest, manifestFields, "Communication Link key manifest")
        require(positiveInteger(manifest, "version") == 2L) {
            "Unsupported Communication Link key manifest version"
        }
        val linkId = requiredString(manifest, "link_id")
        val linkVersion = positiveInteger(manifest, "link_version")
        val canonicalContract = requiredString(manifest, "contract_canonical")
        val contractBytes = decodeCanonicalBase64(canonicalContract)
        require(contractBytes.size in 1..MAX_CONTRACT_BYTES) {
            "Communication Link contract is outside the size limit"
        }
        val contract = parseUtf8Object(contractBytes, "Communication Link contract")
        requireOrderedFields(contract, contractFields, "Communication Link contract")
        require(requiredString(contract, "link_id") == linkId) {
            "Communication Link contract identity differs from its manifest"
        }
        val snapshot = contract.get("scope_snapshot")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing Communication Link scope snapshot")
        requireOrderedFields(snapshot, scopeSnapshotFields, "Communication Link scope snapshot")
        val sourceCandidate = manifest.get("source")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing Communication Link source candidate")
        val targetCandidate = manifest.get("target")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing Communication Link target candidate")
        requireOrderedFields(sourceCandidate, candidateFields, "Communication Link source candidate")
        requireOrderedFields(targetCandidate, candidateFields, "Communication Link target candidate")

        fun endpoint(prefix: String, candidate: JsonObject) =
            LinkKeyManifestVerifier.CurrentEndpointAuthority(
                endpointId = requiredString(contract, "${prefix}_endpoint_id"),
                groupId = requiredString(contract, "${prefix}_group_id"),
                principalId = requiredString(contract, "${prefix}_principal_id"),
                ownerId = requiredString(contract, "${prefix}_owner_id"),
                nodeId = requiredString(contract, "${prefix}_node_id"),
                bindingId = requiredString(candidate, "binding_id"),
                bindingEpoch = positiveInteger(candidate, "binding_epoch"),
                candidateVersion = positiveInteger(candidate, "candidate_version"),
                membershipRevision = positiveInteger(snapshot, "${prefix}_membership_revision"),
                joinRevision = positiveInteger(snapshot, "${prefix}_join_revision"),
                groupVersion = positiveInteger(snapshot, "${prefix}_group_version"),
            )

        return LinkKeyManifestVerifier.CurrentLinkAuthority(
            linkId = linkId,
            linkVersion = linkVersion,
            // Guaranteed by the Store guard for `link.key_manifest`; state is not in the signed DTO.
            state = "PROPOSED",
            direction = requiredString(contract, "direction"),
            actions = Collections.unmodifiableList(stringArray(contract, "actions")),
            dataScopes = Collections.unmodifiableList(stringArray(contract, "data_scopes")),
            transportHubId = requiredString(contract, "transport_hub_id"),
            expiresAt = requiredString(contract, "expires_at"),
            source = endpoint("source", sourceCandidate),
            target = endpoint("target", targetCandidate),
        )
    }

    private fun validateOwnerPin(
        pin: LinkKeyManifestVerifier.OwnerPublicKeyPin,
        expectedOwnerId: String,
    ) {
        pin.publicIdentity.validate()
        require(validToken(pin.ownerId) && validToken(pin.keyId) &&
            pin.ownerId == expectedOwnerId && pin.keyId == pin.publicIdentity.id) {
            "Independent Owner full-key pin does not match the verified Link side"
        }
    }

    private fun stringArray(value: JsonObject, field: String): List<String> {
        val array = value.get(field)?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("Invalid Communication Link $field")
        return array.map { element ->
            element.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: invalid("Invalid Communication Link $field item")
        }
    }

    private fun decodeCanonicalBase64(value: String): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Communication Link contract base64", error)
        }
        require(Base64.getEncoder().encodeToString(decoded) == value) {
            "Noncanonical Communication Link contract base64"
        }
        return decoded
    }

    private fun parseUtf8Object(bytes: ByteArray, label: String): JsonObject {
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (error: Exception) {
            throw IllegalArgumentException("Invalid UTF-8 in $label", error)
        }
        val parsed = try {
            JsonParser.parseString(text)
        } catch (error: Exception) {
            throw IllegalArgumentException("Invalid $label JSON", error)
        }
        require(parsed.isJsonObject) { "$label must be a JSON object" }
        return parsed.asJsonObject
    }

    private fun requireOrderedFields(value: JsonObject, expected: List<String>, label: String) {
        require(value.keySet().toList() == expected) {
            "$label has missing, extra, or reordered fields"
        }
    }

    private fun requiredString(value: JsonObject, field: String): String = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: invalid("Invalid Communication Link $field")

    private fun positiveInteger(value: JsonObject, field: String): Long {
        val token = value.get(field)
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
        require(token != null && token.matches(Regex("[1-9][0-9]*"))) {
            "Invalid positive Communication Link integer: $field"
        }
        return token.toLongOrNull() ?: invalid("Communication Link integer is out of range: $field")
    }

    private fun validToken(value: String): Boolean = value.isNotEmpty() && value.length <= 256 &&
        value == value.trim() && value.none { Character.isISOControl(it) || it == '/' || it == '\\' }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun invalid(message: String): Nothing = throw IllegalArgumentException(message)

    private val SHA256_HEX = Regex("[0-9a-f]{64}")
    private val LINK_STATUS_FIELDS = setOf(
        "link_id", "side", "owner_id", "key_id", "manifest_digest", "accepted",
        "accepted_at", "current_status", "evidence",
    )
    private val LINK_STATUS_REQUIRED_FIELDS = setOf(
        "link_id", "side", "owner_id", "accepted", "current_status",
    )
    private val LINK_CURRENT_STATUSES = setOf(
        "MISSING", "ACCEPTED", "KEY_BINDING_STALE", "OWNER_KEY_REVOKED",
        "PROOF_EXPIRED", "INVALID", "LEGACY_KEY_UNBOUND",
    )
}
