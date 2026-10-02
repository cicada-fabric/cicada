package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Locale

/**
 * Pure verifier for the pinned Client-Control Link key evidence contract.
 *
 * `CurrentLinkAuthority` must capture the selected session's freshly
 * authenticated Hub snapshot; a fresh encrypted manifest is that authority.
 * Candidate self-signatures alone never establish current scope. Owner keys
 * require independent full-key pins plus authenticated current lifecycle data;
 * manifest/key discovery cannot establish their trust. This verifier does not
 * enable Link routing.
 */
internal object LinkKeyManifestVerifier {
    /** The v1.6.3 retained-proof response extension is a candidate only. */
    const val RETAINED_LINK_PROOF_CANDIDATE_READY = false

    private const val CONTRACT_DOMAIN = "cicada/communication-link/proposal/v1\u0000"
    private const val MANIFEST_DOMAIN = "cicada/communication-link/key-manifest/v2\u0000"
    private const val FINGERPRINT_DOMAIN = "cicada/nodekeys/peer-key-fingerprint/v1\u0000"
    private const val OWNER_GRANT_DOMAIN = "cicada/communication-link/owner-key-grant/v2\u0000"
    private const val MAX_CONTRACT_BYTES = 32 * 1024
    private const val MAX_ATTESTATION_BYTES = 32 * 1024
    private const val MAX_OWNER_GRANT_BYTES = 16 * 1024
    private const val ML_DSA_65_SIGNATURE_BYTES = 3309

    private val sha256Hex = Regex("[0-9a-f]{64}")
    private val ownerGrantFields = listOf(
        "version", "owner_id", "link_id", "contract_digest", "key_binding_digest",
        "expected_link_version", "side", "issued_at", "expires_at", "nonce", "signature",
    )
    private val retainedEvidenceFields = setOf(
        "link_version", "contract_digest", "manifest_digest", "owner_key_id",
        "owner_public_identity", "owner_key_state", "owner_key_version",
        "signed_proof", "verified_at",
    )
    private val retainedStatusFields = setOf(
        "link_id", "side", "owner_id", "key_id", "manifest_digest", "accepted",
        "accepted_at", "current_status", "evidence",
    )
    private val retainedStatusRequiredFields = setOf(
        "link_id", "side", "owner_id", "accepted", "current_status",
    )
    private val retainedCurrentStatuses = setOf(
        "MISSING", "ACCEPTED", "KEY_BINDING_STALE", "OWNER_KEY_REVOKED",
        "PROOF_EXPIRED", "INVALID", "LEGACY_KEY_UNBOUND",
    )
    private val manifestFields = listOf(
        "version", "link_id", "link_version", "contract_digest", "contract_canonical",
        "source", "target", "digest",
    )
    private val sideFields = listOf(
        "endpoint_id", "group_id", "principal_id", "owner_id", "node_id", "binding_id",
        "binding_epoch", "candidate_version", "key_id", "key_fingerprint", "proof_digest",
        "public_identity", "attestation",
    )
    private val contractFields = listOf(
        "link_id", "source_endpoint_id", "source_principal_id", "source_group_id",
        "source_owner_id", "source_node_id", "target_endpoint_id", "target_principal_id",
        "target_group_id", "target_owner_id", "target_node_id", "direction", "actions",
        "data_scopes", "transport_hub_id", "expires_at", "scope_snapshot",
    )

    /** A fresh Endpoint/Group/Node/SessionBinding snapshot, including its candidate version. */
    data class CurrentEndpointAuthority(
        val endpointId: String,
        val groupId: String,
        val principalId: String,
        val ownerId: String,
        val nodeId: String,
        val bindingId: String,
        val bindingEpoch: Long,
        val candidateVersion: Long,
        val membershipRevision: Long,
        val joinRevision: Long,
        val groupVersion: Long,
    )

    /** Fresh authenticated Link terms and both Endpoint scopes from the same Hub snapshot. */
    data class CurrentLinkAuthority(
        val linkId: String,
        val linkVersion: Long,
        val state: String,
        val direction: String,
        val actions: List<String>,
        val dataScopes: List<String>,
        val transportHubId: String,
        val expiresAt: String,
        val source: CurrentEndpointAuthority,
        val target: CurrentEndpointAuthority,
    )

    /** Independently pinned full Owner key with fresh authenticated ACTIVE state/version. */
    data class CurrentOwnerKeyAuthority(
        val ownerId: String,
        val keyId: String,
        val publicIdentity: ClientWireCrypto.PublicIdentity,
        val state: String,
        val version: Long,
    )

    /**
     * Independently trusted Owner public key. It carries no Hub registration
     * state or version; those facts must come from a fresh authenticated status.
     * A local signing key must also be correlated by the native caller to the
     * current OwnerDeviceGrant/enrollment association. A peer key must come
     * from an independent trust pin; Hub discovery evidence alone is not trust.
     */
    data class OwnerPublicKeyPin(
        val ownerId: String,
        val keyId: String,
        val publicIdentity: ClientWireCrypto.PublicIdentity,
    )

    /** Exact side grant inputs assembled from fresh Link state and a verified manifest. */
    data class CurrentOwnerGrantAuthority(
        val currentOwnerKey: CurrentOwnerKeyAuthority,
        val ownerId: String,
        val linkId: String,
        val contractDigest: String,
        val manifestDigest: String,
        val linkVersion: Long,
        val side: String,
        val linkExpiresAt: Instant,
    )

    data class VerifiedEndpointCandidate(
        val endpointId: String,
        val groupId: String,
        val ownerId: String,
        val candidateVersion: Long,
        /** Verified CICADA Node peer-key fingerprint, distinct from Client Owner-key fingerprinting. */
        val keyFingerprint: String,
        val publicIdentity: ClientWireCrypto.PublicIdentity,
    )

    /** Result of verifying every manifest claim and both complete Endpoint attestations. */
    class VerifiedManifest internal constructor(
        val linkId: String,
        val linkVersion: Long,
        val contractDigest: String,
        val digest: String,
        val linkExpiresAt: Instant,
        val source: VerifiedEndpointCandidate,
        val target: VerifiedEndpointCandidate,
    )

    data class VerifiedOwnerGrant(
        val ownerId: String,
        val ownerKeyId: String,
        val linkId: String,
        val contractDigest: String,
        val manifestDigest: String,
        val linkVersion: Long,
        val side: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
        val nonce: String,
    )

    /** Verified consent metadata only; it is not routing or native-delivery authority. */
    data class VerifiedRetainedOwnerConsents(
        val linkId: String,
        val linkVersion: Long,
        val contractDigest: String,
        val manifestDigest: String,
        val verifiedAt: Instant,
        val source: VerifiedOwnerGrant,
        val target: VerifiedOwnerGrant,
        /** Current Hub lifecycle fields, retained only after matching both full independent pins. */
        val sourceOwnerKey: CurrentOwnerKeyAuthority,
        val targetOwnerKey: CurrentOwnerKeyAuthority,
    )

    /**
     * One side's currently verified retained consent and current Owner key
     * lifecycle. This is consent metadata only and says nothing about the
     * other Link side.
     */
    data class VerifiedRetainedOwnerGrantStatus(
        val linkId: String,
        val linkVersion: Long,
        val contractDigest: String,
        val manifestDigest: String,
        val verifiedAt: Instant,
        val ownerGrant: VerifiedOwnerGrant,
        val currentOwnerKey: CurrentOwnerKeyAuthority,
    )

    /**
     * Verifies the manifest against independently supplied current Link and
     * Endpoint authority. The full contract bytes are reconstructed in Go's
     * encoding/json order/escaping and compared byte-for-byte before hashing.
     */
    fun verifyManifest(
        manifest: JsonObject,
        current: CurrentLinkAuthority,
        now: Instant = Instant.now(),
    ): VerifiedManifest {
        val linkExpiry = validateCurrentLinkAuthority(current, now)
        requireOrderedFields(manifest, manifestFields, "Communication Link key manifest")

        val version = positiveInteger(manifest, "version")
        val linkId = string(manifest, "link_id")
        val linkVersion = positiveInteger(manifest, "link_version")
        val contractDigest = string(manifest, "contract_digest")
        val contractText = string(manifest, "contract_canonical")
        val digest = string(manifest, "digest")
        require(version == 2L && linkId == current.linkId && linkVersion == current.linkVersion &&
            sha256Hex.matches(contractDigest) && sha256Hex.matches(digest)) {
            "Communication Link key manifest scope or version mismatch"
        }

        val contractBytes = decodeCanonicalBase64(contractText, "contract_canonical")
        require(contractBytes.size in 1..MAX_CONTRACT_BYTES) {
            "Communication Link contract is outside the size limit"
        }
        val contractJson = parseObject(contractBytes, "Communication Link contract")
        requireOrderedFields(contractJson, contractFields, "Communication Link contract")
        val expectedContract = canonicalContract(current)
        require(MessageDigest.isEqual(contractBytes, expectedContract)) {
            "Communication Link contract does not match fresh Link/Group/Endpoint scope"
        }

        val computedContractDigest = sha256(CONTRACT_DOMAIN.toByteArray(UTF8) + contractBytes)
        require(contractDigest == computedContractDigest) {
            "Communication Link contract digest mismatch"
        }

        val sourceWire = manifest.get("source")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing Communication Link source candidate")
        val targetWire = manifest.get("target")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing Communication Link target candidate")
        val source = verifyCandidateDetails(sourceWire, current.source)
        val target = verifyCandidateDetails(targetWire, current.target)

        val claimBytes = canonicalManifestClaims(
            linkId = linkId,
            linkVersion = linkVersion,
            contractDigest = contractDigest,
            contractCanonical = contractText,
            source = source,
            target = target,
        ).toByteArray(UTF8)
        require(sha256(MANIFEST_DOMAIN.toByteArray(UTF8) + claimBytes) == digest) {
            "Communication Link key manifest digest mismatch"
        }

        return VerifiedManifest(
            linkId = linkId,
            linkVersion = linkVersion,
            contractDigest = contractDigest,
            digest = digest,
            linkExpiresAt = linkExpiry,
            source = source.publicResult(),
            target = target.publicResult(),
        )
    }

    /** Returns only the canonical contract digest; it does not verify key evidence or authorize use. */
    internal fun contractDigestForAuthority(
        current: CurrentLinkAuthority,
        now: Instant = Instant.now(),
    ): String {
        validateCurrentLinkAuthority(current, now)
        return sha256(CONTRACT_DOMAIN.toByteArray(UTF8) + canonicalContract(current))
    }

    /** Reusable strict Endpoint-candidate check, backed by the existing v1 proof verifier. */
    fun verifyEndpointCandidate(
        candidate: JsonObject,
        expected: CurrentEndpointAuthority,
    ): VerifiedEndpointCandidate = verifyCandidateDetails(candidate, expected).publicResult()

    /**
     * Verifies one OwnerLinkKeyGrant v2 with the exact current Owner key and
     * re-verifies the complete manifest against fresh Link/Endpoint authority.
     * Nonce replay prevention belongs to the Hub's transactional store and is
     * deliberately not claimed here.
     */
    fun verifyOwnerGrant(
        rawProof: ByteArray,
        currentOwnerKey: CurrentOwnerKeyAuthority,
        currentLink: CurrentLinkAuthority,
        manifestJson: JsonObject,
        side: String,
        now: Instant = Instant.now(),
    ): VerifiedOwnerGrant {
        val linkExpiry = validateCurrentLinkAuthority(currentLink, now)
        val verifiedManifest = verifyManifest(manifestJson, currentLink, now)
        require(side == "SOURCE" || side == "TARGET") { "Invalid OwnerLinkKeyGrant side" }
        val expectedOwnerId = if (side == "SOURCE") currentLink.source.ownerId
            else currentLink.target.ownerId
        require(currentOwnerKey.ownerId == expectedOwnerId &&
            verifiedManifest.linkId == currentLink.linkId &&
            verifiedManifest.linkVersion == currentLink.linkVersion &&
            verifiedManifest.linkExpiresAt == linkExpiry) {
            "OwnerLinkKeyGrant authority does not match the verified current Link manifest"
        }
        return verifyOwnerGrantEvidence(
            rawProof,
            CurrentOwnerGrantAuthority(
                currentOwnerKey = currentOwnerKey,
                ownerId = expectedOwnerId,
                linkId = currentLink.linkId,
                contractDigest = verifiedManifest.contractDigest,
                manifestDigest = verifiedManifest.digest,
                linkVersion = currentLink.linkVersion,
                side = side,
                linkExpiresAt = linkExpiry,
            ),
            now,
        )
    }

    /**
     * Verifies an OwnerLinkKeyGrant signature with an independently trusted
     * full public-key pin and exact verified Link tuple. This proves the proof
     * was signed by that key; it does not prove that the Hub currently regards
     * the key as active. Use retained/current status evidence for that claim.
     */
    fun verifyOwnerGrant(
        rawProof: ByteArray,
        pinnedOwnerKey: OwnerPublicKeyPin,
        currentLink: CurrentLinkAuthority,
        manifestJson: JsonObject,
        side: String,
        now: Instant = Instant.now(),
    ): VerifiedOwnerGrant {
        require(rawProof.isNotEmpty() && rawProof.size <= MAX_OWNER_GRANT_BYTES) {
            "Invalid OwnerLinkKeyGrant size"
        }
        val linkExpiry = validateCurrentLinkAuthority(currentLink, now)
        val manifest = verifyManifest(manifestJson, currentLink, now)
        require(side == "SOURCE" || side == "TARGET") { "Invalid OwnerLinkKeyGrant side" }
        val expectedOwnerId = if (side == "SOURCE") currentLink.source.ownerId
            else currentLink.target.ownerId
        validateOwnerPublicKeyPin(pinnedOwnerKey, expectedOwnerId)
        require(manifest.linkId == currentLink.linkId &&
            manifest.linkVersion == currentLink.linkVersion && manifest.linkExpiresAt == linkExpiry) {
            "OwnerLinkKeyGrant authority does not match the verified current Link manifest"
        }
        return verifyOwnerGrantProof(
            rawProof,
            OwnerGrantProofAuthority(
                ownerId = expectedOwnerId,
                keyId = pinnedOwnerKey.keyId,
                publicIdentity = pinnedOwnerKey.publicIdentity,
                linkId = manifest.linkId,
                contractDigest = manifest.contractDigest,
                manifestDigest = manifest.digest,
                linkVersion = currentLink.linkVersion,
                side = side,
                linkExpiresAt = linkExpiry,
            ),
            now,
        )
    }

    /**
     * Candidate-only validation for the additive v1.6.3 `link.key_grants`
     * retained-evidence DTO. The Hub-returned identities are compared with
     * exact Owner keys supplied by an independent current trust source. Both
     * statuses must describe one snapshot and the exact independently verified
     * current manifest. A successful result proves consent only.
     */
    fun verifyRetainedOwnerConsentsCandidateV163(
        manifestJson: JsonObject,
        statuses: List<JsonObject>,
        currentLink: CurrentLinkAuthority,
        trustedSourceOwnerKey: CurrentOwnerKeyAuthority,
        trustedTargetOwnerKey: CurrentOwnerKeyAuthority,
        now: Instant = Instant.now(),
    ): VerifiedRetainedOwnerConsents {
        require(statuses.size == 2) { "Expected both Link Owner consent statuses" }
        val linkExpiry = validateCurrentLinkAuthority(currentLink, now)
        val manifest = verifyManifest(manifestJson, currentLink, now)
        val expectedBySide = mapOf(
            "SOURCE" to (currentLink.source.ownerId to trustedSourceOwnerKey),
            "TARGET" to (currentLink.target.ownerId to trustedTargetOwnerKey),
        )
        val seenSides = mutableSetOf<String>()
        var commonVerifiedAt: Instant? = null
        val verifiedBySide = mutableMapOf<String, VerifiedOwnerGrant>()

        for (status in statuses) {
            require(status.keySet().all { it in retainedStatusFields } &&
                status.keySet().containsAll(retainedStatusRequiredFields)) {
                "Invalid retained Link key-grant status fields"
            }
            val side = string(status, "side")
            require(side in expectedBySide.keys && seenSides.add(side)) {
                "Duplicate or invalid retained Link side"
            }
            val (expectedOwnerId, trustedOwnerKey) = expectedBySide.getValue(side)
            require(string(status, "link_id") == manifest.linkId &&
                string(status, "owner_id") == expectedOwnerId &&
                boolean(status, "accepted") && string(status, "current_status") == "ACCEPTED") {
                "Retained Link status is not current ACCEPTED evidence for this side"
            }

            val evidence = status.get("evidence")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("Missing retained Link Owner evidence")
            require(evidence.keySet() == retainedEvidenceFields) {
                "Invalid retained Link Owner evidence fields"
            }
            val evidenceLinkVersion = positiveInteger(evidence, "link_version")
            val evidenceContractDigest = string(evidence, "contract_digest")
            val evidenceManifestDigest = string(evidence, "manifest_digest")
            val evidenceOwnerKeyId = string(evidence, "owner_key_id")
            val evidenceKeyState = string(evidence, "owner_key_state")
            val evidenceKeyVersion = positiveInteger(evidence, "owner_key_version")
            val verifiedAt = canonicalUtc(string(evidence, "verified_at"))
            require(verifiedAt <= now && (commonVerifiedAt == null || commonVerifiedAt == verifiedAt)) {
                "Retained Link statuses do not share one nonfuture Hub snapshot"
            }
            commonVerifiedAt = verifiedAt

            val identityJson = evidence.get("owner_public_identity")
                ?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("Missing retained Owner public identity")
            val evidenceOwnerKey = ClientWireCrypto.PublicIdentity.parse(identityJson)
            require(trustedOwnerKey.ownerId == expectedOwnerId &&
                trustedOwnerKey.state == "ACTIVE" && trustedOwnerKey.version > 0 &&
                trustedOwnerKey.keyId == evidenceOwnerKeyId &&
                trustedOwnerKey.keyId == evidenceOwnerKey.id &&
                trustedOwnerKey.publicIdentity.sameAs(evidenceOwnerKey) &&
                evidenceKeyState == trustedOwnerKey.state &&
                evidenceKeyVersion == trustedOwnerKey.version) {
                "Hub-retained Owner key does not match the independently trusted current key"
            }
            if (status.has("key_id")) {
                require(string(status, "key_id") == evidenceOwnerKeyId) {
                    "Retained Link status key ID disagrees with Owner evidence"
                }
            }
            if (status.has("manifest_digest")) {
                require(string(status, "manifest_digest") == manifest.digest) {
                    "Retained Link status manifest digest mismatch"
                }
            }
            require(evidenceLinkVersion == manifest.linkVersion &&
                evidenceContractDigest == manifest.contractDigest &&
                evidenceManifestDigest == manifest.digest) {
                "Retained Link evidence does not match the verified current manifest"
            }

            val rawProof = decodeCanonicalBase64(
                string(evidence, "signed_proof"),
                "retained OwnerLinkKeyGrant",
            )
            val verifiedGrant = verifyOwnerGrantEvidence(
                rawProof,
                CurrentOwnerGrantAuthority(
                    currentOwnerKey = trustedOwnerKey,
                    ownerId = expectedOwnerId,
                    linkId = manifest.linkId,
                    contractDigest = manifest.contractDigest,
                    manifestDigest = manifest.digest,
                    linkVersion = manifest.linkVersion,
                    side = side,
                    linkExpiresAt = linkExpiry,
                ),
                now,
            )
            verifiedBySide[side] = verifiedGrant
        }

        require(seenSides == setOf("SOURCE", "TARGET")) {
            "Retained Link status pair is incomplete"
        }
        return VerifiedRetainedOwnerConsents(
            linkId = manifest.linkId,
            linkVersion = manifest.linkVersion,
            contractDigest = manifest.contractDigest,
            manifestDigest = manifest.digest,
            verifiedAt = requireNotNull(commonVerifiedAt),
            source = requireNotNull(verifiedBySide["SOURCE"]),
            target = requireNotNull(verifiedBySide["TARGET"]),
            sourceOwnerKey = trustedSourceOwnerKey,
            targetOwnerKey = trustedTargetOwnerKey,
        )
    }

    /**
     * Verifies current retained bilateral grants against identity-only trust
     * pins. Owner registration state/version are taken only from the fresh
     * authenticated `link.key_grants` evidence, after its complete identity
     * matches the independently supplied pin; no lifecycle version is inferred.
     */
    fun verifyRetainedOwnerConsentsCandidateV164(
        manifestJson: JsonObject,
        statuses: List<JsonObject>,
        currentLink: CurrentLinkAuthority,
        trustedSourceOwnerPin: OwnerPublicKeyPin,
        trustedTargetOwnerPin: OwnerPublicKeyPin,
        now: Instant = Instant.now(),
    ): VerifiedRetainedOwnerConsents {
        require(statuses.size == 2) { "Expected both Link Owner consent statuses" }
        validateOwnerPublicKeyPin(trustedSourceOwnerPin, currentLink.source.ownerId)
        validateOwnerPublicKeyPin(trustedTargetOwnerPin, currentLink.target.ownerId)
        val expectedPins = mapOf(
            "SOURCE" to trustedSourceOwnerPin,
            "TARGET" to trustedTargetOwnerPin,
        )
        val currentKeys = mutableMapOf<String, CurrentOwnerKeyAuthority>()
        for (status in statuses) {
            val side = string(status, "side")
            val pin = expectedPins[side]
                ?: invalid("Duplicate or invalid retained Link side")
            require(!currentKeys.containsKey(side)) { "Duplicate retained Link side" }
            val evidence = status.get("evidence")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("Missing retained Link Owner evidence")
            val evidenceOwnerId = string(status, "owner_id")
            val evidenceKeyId = string(evidence, "owner_key_id")
            val evidenceState = string(evidence, "owner_key_state")
            val evidenceVersion = positiveInteger(evidence, "owner_key_version")
            val identityJson = evidence.get("owner_public_identity")
                ?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("Missing retained Owner public identity")
            val evidenceIdentity = ClientWireCrypto.PublicIdentity.parse(identityJson)
            require(evidenceOwnerId == pin.ownerId && evidenceKeyId == pin.keyId &&
                evidenceState == "ACTIVE" && evidenceKeyId == evidenceIdentity.id &&
                pin.publicIdentity.sameAs(evidenceIdentity)) {
                "Hub-retained Owner key does not match the independent full-key pin"
            }
            currentKeys[side] = CurrentOwnerKeyAuthority(
                ownerId = evidenceOwnerId,
                keyId = evidenceKeyId,
                publicIdentity = evidenceIdentity,
                state = evidenceState,
                version = evidenceVersion,
            )
        }
        require(currentKeys.keys == setOf("SOURCE", "TARGET")) {
            "Retained Link status pair is incomplete"
        }
        return verifyRetainedOwnerConsentsCandidateV163(
            manifestJson = manifestJson,
            statuses = statuses,
            currentLink = currentLink,
            trustedSourceOwnerKey = requireNotNull(currentKeys["SOURCE"]),
            trustedTargetOwnerKey = requireNotNull(currentKeys["TARGET"]),
            now = now,
        )
    }

    /**
     * Verifies one current retained Link Owner grant against an independent
     * full-key pin. It returns null for a well-formed status without current
     * accepted proof evidence; it never infers consent from `accepted=true`
     * alone or makes a claim about the other side.
     */
    fun verifyRetainedOwnerGrantStatusCandidateV164(
        manifestJson: JsonObject,
        status: JsonObject,
        currentLink: CurrentLinkAuthority,
        trustedOwnerPin: OwnerPublicKeyPin,
        side: String,
        now: Instant = Instant.now(),
    ): VerifiedRetainedOwnerGrantStatus? {
        require(side == "SOURCE" || side == "TARGET") { "Invalid retained Link Owner side" }
        val linkExpiry = validateCurrentLinkAuthority(currentLink, now)
        val manifest = verifyManifest(manifestJson, currentLink, now)
        val expectedOwnerId = if (side == "SOURCE") currentLink.source.ownerId
            else currentLink.target.ownerId
        validateOwnerPublicKeyPin(trustedOwnerPin, expectedOwnerId)
        require(status.keySet().all { it in retainedStatusFields } &&
            status.keySet().containsAll(retainedStatusRequiredFields)) {
            "Invalid retained Link key-grant status fields"
        }
        require(string(status, "link_id") == manifest.linkId &&
            string(status, "side") == side && string(status, "owner_id") == expectedOwnerId) {
            "Retained Link status does not match the selected Link side"
        }
        val accepted = boolean(status, "accepted")
        val currentStatus = string(status, "current_status")
        require(currentStatus in retainedCurrentStatuses &&
            (currentStatus != "ACCEPTED" || accepted)) {
            "Invalid retained Link current status"
        }
        if (status.has("accepted_at")) {
            val acceptedAt = canonicalUtc(string(status, "accepted_at"))
            require(acceptedAt <= now) { "Retained Link acceptance time is in the future" }
        }
        if (!accepted || currentStatus != "ACCEPTED") return null

        val evidence = status.get("evidence")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: return null
        require(evidence.keySet() == retainedEvidenceFields) {
            "Invalid retained Link Owner evidence fields"
        }
        val evidenceLinkVersion = positiveInteger(evidence, "link_version")
        val evidenceContractDigest = string(evidence, "contract_digest")
        val evidenceManifestDigest = string(evidence, "manifest_digest")
        val evidenceOwnerKeyId = string(evidence, "owner_key_id")
        val evidenceKeyState = string(evidence, "owner_key_state")
        val evidenceKeyVersion = positiveInteger(evidence, "owner_key_version")
        val verifiedAt = canonicalUtc(string(evidence, "verified_at"))
        require(verifiedAt <= now && evidenceKeyState == "ACTIVE" &&
            evidenceLinkVersion == manifest.linkVersion &&
            evidenceContractDigest == manifest.contractDigest &&
            evidenceManifestDigest == manifest.digest) {
            "Retained Link evidence is stale or not current"
        }

        val identityJson = evidence.get("owner_public_identity")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing retained Owner public identity")
        val evidenceIdentity = ClientWireCrypto.PublicIdentity.parse(identityJson)
        require(evidenceOwnerKeyId == trustedOwnerPin.keyId &&
            evidenceOwnerKeyId == evidenceIdentity.id &&
            trustedOwnerPin.publicIdentity.sameAs(evidenceIdentity)) {
            "Hub-retained Owner key does not match the independent full-key pin"
        }
        if (status.has("key_id")) {
            require(string(status, "key_id") == evidenceOwnerKeyId) {
                "Retained Link status key ID disagrees with Owner evidence"
            }
        }
        if (status.has("manifest_digest")) {
            require(string(status, "manifest_digest") == manifest.digest) {
                "Retained Link status manifest digest mismatch"
            }
        }
        val rawProof = decodeCanonicalBase64(
            string(evidence, "signed_proof"),
            "retained OwnerLinkKeyGrant",
        )
        val currentOwnerKey = CurrentOwnerKeyAuthority(
            ownerId = expectedOwnerId,
            keyId = evidenceOwnerKeyId,
            publicIdentity = evidenceIdentity,
            state = evidenceKeyState,
            version = evidenceKeyVersion,
        )
        val ownerGrant = verifyOwnerGrantEvidence(
            rawProof,
            CurrentOwnerGrantAuthority(
                currentOwnerKey = currentOwnerKey,
                ownerId = expectedOwnerId,
                linkId = manifest.linkId,
                contractDigest = manifest.contractDigest,
                manifestDigest = manifest.digest,
                linkVersion = manifest.linkVersion,
                side = side,
                linkExpiresAt = linkExpiry,
            ),
            now,
        )
        return VerifiedRetainedOwnerGrantStatus(
            linkId = manifest.linkId,
            linkVersion = manifest.linkVersion,
            contractDigest = manifest.contractDigest,
            manifestDigest = manifest.digest,
            verifiedAt = verifiedAt,
            ownerGrant = ownerGrant,
            currentOwnerKey = currentOwnerKey,
        )
    }

    /**
     * Verifies the signed OwnerGrant against explicit fresh authority. Callers
     * should obtain this authority only after verifying the current Link
     * manifest and looking up the selected Owner key as ACTIVE.
     */
    internal fun verifyOwnerGrantEvidence(
        rawProof: ByteArray,
        expected: CurrentOwnerGrantAuthority,
        now: Instant = Instant.now(),
    ): VerifiedOwnerGrant {
        val ownerKey = expected.currentOwnerKey
        validateOwnerPublicKeyPin(
            OwnerPublicKeyPin(ownerKey.ownerId, ownerKey.keyId, ownerKey.publicIdentity),
            expected.ownerId,
        )
        require(ownerKey.state == "ACTIVE" && ownerKey.version > 0) {
            "Invalid current OwnerLinkKeyGrant authority"
        }
        return verifyOwnerGrantProof(
            rawProof = rawProof,
            expected = OwnerGrantProofAuthority(
                ownerId = expected.ownerId,
                keyId = ownerKey.keyId,
                publicIdentity = ownerKey.publicIdentity,
                linkId = expected.linkId,
                contractDigest = expected.contractDigest,
                manifestDigest = expected.manifestDigest,
                linkVersion = expected.linkVersion,
                side = expected.side,
                linkExpiresAt = expected.linkExpiresAt,
            ),
            now = now,
        )
    }

    private data class OwnerGrantProofAuthority(
        val ownerId: String,
        val keyId: String,
        val publicIdentity: ClientWireCrypto.PublicIdentity,
        val linkId: String,
        val contractDigest: String,
        val manifestDigest: String,
        val linkVersion: Long,
        val side: String,
        val linkExpiresAt: Instant,
    )

    private fun verifyOwnerGrantProof(
        rawProof: ByteArray,
        expected: OwnerGrantProofAuthority,
        now: Instant,
    ): VerifiedOwnerGrant {
        require(rawProof.isNotEmpty() && rawProof.size <= MAX_OWNER_GRANT_BYTES) {
            "Invalid OwnerLinkKeyGrant size"
        }
        validateOwnerPublicKeyPin(
            OwnerPublicKeyPin(expected.ownerId, expected.keyId, expected.publicIdentity),
            expected.ownerId,
        )
        require(canonicalToken(expected.linkId) && expected.linkVersion > 0 &&
            sha256Hex.matches(expected.contractDigest) &&
            sha256Hex.matches(expected.manifestDigest) &&
            expected.side in setOf("SOURCE", "TARGET") && expected.linkExpiresAt > now) {
            "Invalid OwnerLinkKeyGrant authority"
        }

        val proof = parseObject(rawProof, "OwnerLinkKeyGrant")
        requireOrderedFields(proof, ownerGrantFields, "OwnerLinkKeyGrant")
        val version = integer(proof, "version")
        val ownerId = string(proof, "owner_id")
        val linkId = string(proof, "link_id")
        val proofContractDigest = string(proof, "contract_digest")
        val manifestDigest = string(proof, "key_binding_digest")
        val linkVersion = positiveInteger(proof, "expected_link_version")
        val proofSide = string(proof, "side")
        val issuedText = string(proof, "issued_at")
        val expiresText = string(proof, "expires_at")
        val nonce = string(proof, "nonce")
        val signatureText = string(proof, "signature")
        require(version == 2L && sha256Hex.matches(proofContractDigest) &&
            sha256Hex.matches(manifestDigest) && sha256Hex.matches(nonce) &&
            ownerId == expected.ownerId && linkId == expected.linkId &&
            proofContractDigest == expected.contractDigest &&
            manifestDigest == expected.manifestDigest &&
            linkVersion == expected.linkVersion && proofSide == expected.side) {
            "OwnerLinkKeyGrant does not match the exact current Link side and manifest"
        }

        val issuedAt = canonicalUtc(issuedText)
        val expiresAt = canonicalUtc(expiresText)
        require(expiresAt > issuedAt && issuedAt <= now && now < expiresAt &&
            expiresAt <= expected.linkExpiresAt) {
            "OwnerLinkKeyGrant is outside its validity period or exceeds Link expiry"
        }

        val signature = decodeCanonicalBase64(signatureText, "OwnerLinkKeyGrant signature")
        require(signature.size == ML_DSA_65_SIGNATURE_BYTES) {
            "Invalid OwnerLinkKeyGrant ML-DSA-65 signature size"
        }
        val claims = canonicalOwnerGrantClaims(
            ownerId = ownerId,
            linkId = linkId,
            contractDigest = proofContractDigest,
            manifestDigest = manifestDigest,
            linkVersion = linkVersion,
            side = proofSide,
            issuedAt = issuedText,
            expiresAt = expiresText,
            nonce = nonce,
        )
        val canonicalProof = canonicalOwnerGrantProof(
            claims = claims,
            signatureText = signatureText,
        ).toByteArray(UTF8)
        require(MessageDigest.isEqual(rawProof, canonicalProof)) {
            "OwnerLinkKeyGrant JSON is not canonical"
        }
        val signedBytes = OWNER_GRANT_DOMAIN.toByteArray(UTF8) + claims.toByteArray(UTF8)
        require(ClientWireCrypto.verify(expected.publicIdentity, signedBytes, signature)) {
            "OwnerLinkKeyGrant ML-DSA signature failed"
        }

        return VerifiedOwnerGrant(
            ownerId = ownerId,
            ownerKeyId = expected.keyId,
            linkId = linkId,
            contractDigest = proofContractDigest,
            manifestDigest = manifestDigest,
            linkVersion = linkVersion,
            side = proofSide,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            nonce = nonce,
        )
    }

    private data class CandidateDetails(
        val endpointId: String,
        val groupId: String,
        val principalId: String,
        val ownerId: String,
        val nodeId: String,
        val bindingId: String,
        val bindingEpoch: Long,
        val candidateVersion: Long,
        val keyId: String,
        val fingerprint: String,
        val proofDigest: String,
        val publicIdentity: ClientWireCrypto.PublicIdentity,
        val attestation: String,
    ) {
        fun publicResult() = VerifiedEndpointCandidate(
            endpointId = endpointId,
            groupId = groupId,
            ownerId = ownerId,
            candidateVersion = candidateVersion,
            keyFingerprint = fingerprint,
            publicIdentity = publicIdentity,
        )

        fun canonicalJson(): String = goObject(
            "endpoint_id" to goString(endpointId),
            "group_id" to goString(groupId),
            "principal_id" to goString(principalId),
            "owner_id" to goString(ownerId),
            "node_id" to goString(nodeId),
            "binding_id" to goString(bindingId),
            "binding_epoch" to bindingEpoch.toString(),
            "candidate_version" to candidateVersion.toString(),
            "key_id" to goString(keyId),
            "key_fingerprint" to goString(fingerprint),
            "proof_digest" to goString(proofDigest),
            "public_identity" to publicIdentity.toJson(),
            "attestation" to goString(attestation),
        )
    }

    private fun verifyCandidateDetails(
        candidate: JsonObject,
        expected: CurrentEndpointAuthority,
    ): CandidateDetails {
        validateEndpointAuthority(expected)
        requireOrderedFields(candidate, sideFields, "Communication Link Endpoint candidate")
        val endpointId = string(candidate, "endpoint_id")
        val groupId = string(candidate, "group_id")
        val principalId = string(candidate, "principal_id")
        val ownerId = string(candidate, "owner_id")
        val nodeId = string(candidate, "node_id")
        val bindingId = string(candidate, "binding_id")
        val bindingEpoch = positiveInteger(candidate, "binding_epoch")
        val candidateVersion = positiveInteger(candidate, "candidate_version")
        val keyId = string(candidate, "key_id")
        val fingerprint = string(candidate, "key_fingerprint")
        val proofDigest = string(candidate, "proof_digest")
        val identityJson = candidate.get("public_identity")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("Missing Endpoint candidate public identity")
        val attestationText = string(candidate, "attestation")
        require(endpointId == expected.endpointId && groupId == expected.groupId &&
            principalId == expected.principalId && ownerId == expected.ownerId &&
            nodeId == expected.nodeId && bindingId == expected.bindingId &&
            bindingEpoch == expected.bindingEpoch && candidateVersion == expected.candidateVersion) {
            "Endpoint candidate does not match fresh Endpoint/Group/Node/binding scope"
        }

        val attestation = decodeCanonicalBase64(attestationText, "Endpoint attestation")
        require(attestation.size in 1..MAX_ATTESTATION_BYTES) {
            "Endpoint attestation is outside the size limit"
        }
        require(sha256Hex.matches(proofDigest)) { "Invalid Endpoint proof digest" }
        val public = GroupKeyManifestVerifier.verifyProof(
            rawProof = attestation,
            expectedEndpoint = expected.endpointId,
            expectedPrincipal = expected.principalId,
            expectedNode = expected.nodeId,
            expectedBinding = expected.bindingId,
            expectedEpoch = expected.bindingEpoch,
            expectedPublic = identityJson,
            expectedDigest = proofDigest,
        )
        require(keyId == public.id) { "Endpoint candidate key ID mismatch" }
        val fingerprintBytes = FINGERPRINT_DOMAIN.toByteArray(UTF8) +
            public.kemPublic + public.signingPublic
        val computedFingerprint = "sha256:" + sha256(fingerprintBytes)
        require(fingerprint == computedFingerprint) { "Endpoint candidate fingerprint mismatch" }

        val details = CandidateDetails(
            endpointId, groupId, principalId, ownerId, nodeId, bindingId,
            bindingEpoch, candidateVersion, keyId, fingerprint, proofDigest,
            public, attestationText,
        )
        return details
    }

    private fun validateCurrentLinkAuthority(current: CurrentLinkAuthority, now: Instant): Instant {
        require(canonicalToken(current.linkId) && current.linkVersion > 0 && current.state == "PROPOSED" &&
            current.direction in setOf("forward", "bidirectional") &&
            (current.transportHubId.isEmpty() || canonicalToken(current.transportHubId))) {
            "Invalid fresh Communication Link authority"
        }
        validateEndpointAuthority(current.source)
        validateEndpointAuthority(current.target)
        require(current.source.endpointId != current.target.endpointId) {
            "Communication Link scope must identify two distinct Endpoints"
        }
        validateSortedWords(current.actions, setOf("send", "ask", "reply"), 3, "actions")
        require(current.actions.size > 0 && current.actions != listOf("reply")) {
            "Communication Link requires send or ask"
        }
        validateSortedWords(current.dataScopes, null, 16, "data_scopes")
        val expiry = canonicalUtc(current.expiresAt)
        require(now < expiry) { "Communication Link is expired" }
        return expiry
    }

    private fun validateEndpointAuthority(scope: CurrentEndpointAuthority) {
        require(listOf(scope.endpointId, scope.groupId, scope.principalId, scope.ownerId,
            scope.nodeId, scope.bindingId).all(::canonicalToken) &&
            scope.bindingEpoch > 0 && scope.candidateVersion > 0 &&
            scope.membershipRevision > 0 && scope.joinRevision > 0 && scope.groupVersion > 0) {
            "Invalid fresh Endpoint/Group/Node/binding authority"
        }
    }

    private fun validateSortedWords(
        values: List<String>,
        allowed: Set<String>?,
        maximum: Int,
        label: String,
    ) {
        require(values.isNotEmpty() && values.size <= maximum && values.distinct().size == values.size &&
            values.zipWithNext().all { (previous, next) -> compareUtf8(previous, next) < 0 } &&
            values.all { value ->
                value.isNotEmpty() && value.toByteArray(UTF8).size <= 128 &&
                    value == value.lowercase(Locale.ROOT) &&
                    value != "*" && value.none { it in " \t\n\r" } &&
                    (allowed == null || value in allowed)
            }) { "Invalid or noncanonical Communication Link $label" }
    }

    private fun canonicalContract(current: CurrentLinkAuthority): ByteArray {
        val source = current.source
        val target = current.target
        val scopeSnapshot = goObject(
            "source_membership_revision" to source.membershipRevision.toString(),
            "source_join_revision" to source.joinRevision.toString(),
            "source_group_version" to source.groupVersion.toString(),
            "target_membership_revision" to target.membershipRevision.toString(),
            "target_join_revision" to target.joinRevision.toString(),
            "target_group_version" to target.groupVersion.toString(),
        )
        val serialized = goObject(
            "link_id" to goString(current.linkId),
            "source_endpoint_id" to goString(source.endpointId),
            "source_principal_id" to goString(source.principalId),
            "source_group_id" to goString(source.groupId),
            "source_owner_id" to goString(source.ownerId),
            "source_node_id" to goString(source.nodeId),
            "target_endpoint_id" to goString(target.endpointId),
            "target_principal_id" to goString(target.principalId),
            "target_group_id" to goString(target.groupId),
            "target_owner_id" to goString(target.ownerId),
            "target_node_id" to goString(target.nodeId),
            "direction" to goString(current.direction),
            "actions" to goArray(current.actions),
            "data_scopes" to goArray(current.dataScopes),
            "transport_hub_id" to goString(current.transportHubId),
            "expires_at" to goString(current.expiresAt),
            "scope_snapshot" to scopeSnapshot,
        )
        return serialized.toByteArray(UTF8)
    }

    private fun canonicalManifestClaims(
        linkId: String,
        linkVersion: Long,
        contractDigest: String,
        contractCanonical: String,
        source: CandidateDetails,
        target: CandidateDetails,
    ): String = goObject(
        "version" to "2",
        "link_id" to goString(linkId),
        "link_version" to linkVersion.toString(),
        "contract_digest" to goString(contractDigest),
        "contract_canonical" to goString(contractCanonical),
        "source" to source.canonicalJson(),
        "target" to target.canonicalJson(),
    )

    private fun canonicalOwnerGrantClaims(
        ownerId: String,
        linkId: String,
        contractDigest: String,
        manifestDigest: String,
        linkVersion: Long,
        side: String,
        issuedAt: String,
        expiresAt: String,
        nonce: String,
    ): String = goObject(
        "version" to "2",
        "owner_id" to goString(ownerId),
        "link_id" to goString(linkId),
        "contract_digest" to goString(contractDigest),
        "key_binding_digest" to goString(manifestDigest),
        "expected_link_version" to linkVersion.toString(),
        "side" to goString(side),
        "issued_at" to goString(issuedAt),
        "expires_at" to goString(expiresAt),
        "nonce" to goString(nonce),
    )

    private fun canonicalOwnerGrantProof(claims: String, signatureText: String): String =
        claims.dropLast(1) + ",\"signature\":" + goString(signatureText) + "}"

    private fun canonicalUtc(text: String): Instant = try {
        GroupKeyManifestVerifier.parseCanonicalUtc(text)
    } catch (error: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid canonical UTC RFC3339Nano time", error)
    }

    private fun decodeCanonicalBase64(encoded: String, label: String): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid $label base64", error)
        }
        require(Base64.getEncoder().encodeToString(decoded) == encoded) {
            "Noncanonical $label base64"
        }
        return decoded
    }

    private fun parseObject(raw: ByteArray, label: String): JsonObject {
        require(raw.isNotEmpty()) { "Empty $label JSON" }
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
        } catch (error: Exception) {
            throw IllegalArgumentException("Invalid UTF-8 in $label", error)
        }
        val parsed = try { JsonParser.parseString(text) }
        catch (error: Exception) { throw IllegalArgumentException("Invalid $label JSON", error) }
        require(parsed.isJsonObject) { "$label must be a JSON object" }
        return parsed.asJsonObject
    }

    private fun requireOrderedFields(value: JsonObject, expected: List<String>, label: String) {
        require(value.keySet().toList() == expected) { "$label has missing, extra, or reordered fields" }
    }

    private fun string(value: JsonObject, field: String): String = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: invalid("Invalid $field")

    private fun boolean(value: JsonObject, field: String): Boolean = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
        ?: invalid("Invalid $field")

    private fun integer(value: JsonObject, field: String): Long {
        val element = value.get(field)
        val token = element?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asString
        require(token != null && token.matches(Regex("0|[1-9][0-9]*"))) {
            "Invalid canonical integer: $field"
        }
        return token.toLongOrNull() ?: invalid("Integer is out of range: $field")
    }

    private fun positiveInteger(value: JsonObject, field: String): Long = integer(value, field).also {
        require(it > 0) { "Expected positive integer: $field" }
    }

    private fun canonicalToken(value: String): Boolean {
        if (value.isEmpty() || value.toByteArray(UTF8).size > 256 || value != value.trim()) return false
        var offset = 0
        while (offset < value.length) {
            val codePoint = value.codePointAt(offset)
            if (Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint) ||
                Character.isISOControl(codePoint) || codePoint == '/'.code || codePoint == '\\'.code) {
                return false
            }
            offset += Character.charCount(codePoint)
        }
        return true
    }

    private fun validateOwnerPublicKeyPin(pin: OwnerPublicKeyPin, expectedOwnerId: String) {
        pin.publicIdentity.validate()
        require(canonicalToken(pin.ownerId) && canonicalToken(pin.keyId) &&
            pin.ownerId == expectedOwnerId && pin.keyId == pin.publicIdentity.id) {
            "Invalid independent Owner full-key pin"
        }
    }

    /** Go encoding/json string escaping, including HTML and U+2028/U+2029. */
    private fun goString(value: String): String = buildString {
        append('"')
        var index = 0
        while (index < value.length) {
            val char = value[index]
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                '<' -> append("\\u003c")
                '>' -> append("\\u003e")
                '&' -> append("\\u0026")
                '\u2028' -> append("\\u2028")
                '\u2029' -> append("\\u2029")
                else -> when {
                    char.code < 0x20 -> append("\\u00").append(char.code.toString(16).padStart(2, '0'))
                    Character.isHighSurrogate(char) -> {
                        require(index + 1 < value.length && Character.isLowSurrogate(value[index + 1])) {
                            "Unpaired UTF-16 surrogate in canonical Link JSON"
                        }
                        append(char).append(value[index + 1])
                        index += 1
                    }
                    Character.isLowSurrogate(char) -> invalid("Unpaired UTF-16 surrogate in canonical Link JSON")
                    else -> append(char)
                }
            }
            index += 1
        }
        append('"')
    }

    private fun goObject(vararg fields: Pair<String, String>): String = buildString {
        append('{')
        fields.forEachIndexed { index, (name, encodedValue) ->
            if (index != 0) append(',')
            append(goString(name)).append(':').append(encodedValue)
        }
        append('}')
    }

    private fun goArray(values: List<String>): String = values.joinToString(",", "[", "]", transform = ::goString)

    private fun compareUtf8(left: String, right: String): Int {
        val leftBytes = left.toByteArray(UTF8)
        val rightBytes = right.toByteArray(UTF8)
        val common = minOf(leftBytes.size, rightBytes.size)
        for (index in 0 until common) {
            val difference = (leftBytes[index].toInt() and 0xff) - (rightBytes[index].toInt() and 0xff)
            if (difference != 0) return difference
        }
        return leftBytes.size - rightBytes.size
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun invalid(message: String): Nothing = throw IllegalArgumentException(message)

    private val UTF8 = StandardCharsets.UTF_8
}
