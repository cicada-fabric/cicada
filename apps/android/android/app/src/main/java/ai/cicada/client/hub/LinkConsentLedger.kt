package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/**
 * Durable, profile-local evidence for the closed v1.6.4 Link consent flow.
 *
 * This ledger is not an RPC capability. `ClientHubSession` may create a record only
 * after verifying a fresh encrypted Hub response, and may resolve a write fence
 * only after authenticating the original response or validating a fresh activated
 * pair against the stored proof and exact authority tuple. No JavaScript value is
 * accepted as evidence of currentness, authentication, or successful recovery.
 */
internal data class LinkConsentLedger(
    val ownerPins: List<OwnerPin> = emptyList(),
    val review: Review? = null,
    val writeFence: WriteFence? = null,
) {
    data class OwnerPin(
        val ownerId: String,
        val keyId: String,
        /** Full public identity only. Owner private-key material is never accepted. */
        val publicIdentityJson: String,
        /** ClientWireCrypto.PublicIdentity.fingerprint(), lowercase hex without a prefix. */
        val fingerprint: String,
        /** Local pin-store revision; this is not a Hub Owner-key version. */
        val pinRevision: Long,
        val confirmedAt: String,
        val trustSource: String = "USER_CONFIRMED_INDEPENDENT_CHANNEL",
    )

    data class SideScope(
        val endpointId: String,
        val groupId: String,
        val principalId: String,
        val ownerId: String,
        val nodeId: String,
        val bindingId: String,
        val bindingEpoch: Long,
        val candidateVersion: Long,
        val keyId: String,
        val keyFingerprint: String,
        val proofDigest: String,
        val membershipRevision: Long,
        val joinRevision: Long,
        val groupVersion: Long,
        val ownerKeyId: String,
        val ownerFingerprint: String,
        /** Nullable until fresh authenticated Owner-key evidence supplies lifecycle. */
        val ownerKeyState: String?,
        /** Nullable until fresh authenticated evidence; never locally defaulted. */
        val ownerKeyVersion: Long?,
        /** Revision of the independently confirmed local public-key pin. */
        val ownerPinRevision: Long,
    )

    data class ReviewerQualification(
        val endpointId: String,
        val groupId: String,
        val membershipRevision: Long,
        val joinRevision: Long,
        val groupVersion: Long,
        val bindingId: String,
        val bindingEpoch: Long,
        val action: String,
        val leaseExpiresAt: String,
    )

    data class ReadCorrelation(
        val operation: String,
        val operationId: String,
        val requestSequence: Long,
        val responseSequence: Long,
        val origin: String = "DIRECT",
    )

    /** Complete authority tuple shown to the user and used to bind Owner proofs. */
    data class AuthorityTuple(
        val profileId: String,
        val profileGeneration: Long,
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val sessionEpoch: Long,
        val linkId: String,
        val linkVersion: Long,
        val contractDigest: String,
        val manifestDigest: String,
        val localSide: String,
        val kind: String,
        val direction: String,
        val actions: List<String>,
        val dataScopes: List<String>,
        val expiresAt: String,
        val source: SideScope,
        val target: SideScope,
        val expectedPolicyVersion: Long? = null,
        val policyVersion: Long? = null,
        val policyDigest: String? = null,
        val maximumProofExpiresAt: String? = null,
        val reviewers: List<ReviewerQualification> = emptyList(),
    )

    data class Review(
        val reviewId: String,
        val consentDigest: String,
        val tuple: AuthorityTuple,
        val manifestRead: ReadCorrelation,
        val statusRead: ReadCorrelation,
        val previewRead: ReadCorrelation?,
        /** Canonical reviewed policy DTO, needed to revalidate a fresh preview at submit. */
        val policyJson: String?,
        /** Canonical claims supplied to an external signer; contains no private key. */
        val signingRequestJson: String,
        val createdAt: String,
    )

    enum class FenceState {
        PENDING,
        STILL_PROCESSING,
        UNCERTAIN,
        RECOVERY_UNAVAILABLE,
        RECOVERY_REJECTED,
        AUTH_REVOKED,
    }

    data class WriteFence(
        val operation: String,
        val operationId: String,
        val requestSequence: Long,
        val expectedResponseSequence: Long,
        /** Exact canonical signed Owner proof used in the encrypted request. */
        val signedProofJson: String,
        val signedProofSha256: String,
        /** Exact encrypted packet sent by the existing native RPC transport. */
        val packetJson: String,
        val packetSha256: String,
        val reviewId: String,
        val consentDigest: String,
        val tupleDigest: String,
        val state: FenceState,
    )

    data class VerifiedOriginalCompletion internal constructor(
        val operationId: String,
        val requestSequence: Long,
        val responseSequence: Long,
        val packetSha256: String,
        val signedProofSha256: String,
        val tupleDigest: String,
    )

    data class VerifiedActivatedPair internal constructor(
        val linkId: String,
        val linkVersion: Long,
        val contractDigest: String,
        val manifestDigest: String,
        val policyDigest: String?,
        val policyVersion: Long?,
        val tupleDigest: String,
        val includedSignedProofSha256: Set<String>,
        /** Set only by native direct-response processing after route authentication. */
        val freshResponseSequence: Long,
    )

    fun pinOwner(identity: ClientWireCrypto.PublicIdentity, ownerId: String,
                  expectedFingerprint: String, confirmed: Boolean,
                  confirmedAt: Instant): Pair<LinkConsentLedger, OwnerPin> {
        requireOwnerToken(ownerId, "owner ID")
        identity.validate()
        require(identity.fingerprint() == expectedFingerprint && SHA256.matches(expectedFingerprint)) {
            "Owner fingerprint does not match the independently supplied public identity"
        }
        require(confirmed) { "Explicit Owner pin confirmation is required" }
        require(writeFence == null) { "Resolve the original Link consent packet before changing Owner pins" }
        val canonicalIdentity = identity.toJson()
        val existing = ownerPins.singleOrNull { it.ownerId == ownerId && it.keyId == identity.id }
        if (existing != null) {
            require(existing.publicIdentityJson == canonicalIdentity && existing.fingerprint == expectedFingerprint) {
                "An Owner key ID cannot be rebound to different public bytes"
            }
            return this to existing
        }
        require(ownerPins.size < MAX_OWNER_PINS) { "Owner pin capacity reached" }
        val revision = (ownerPins.maxOfOrNull { it.pinRevision } ?: 0L) + 1L
        require(revision > 0L) { "Owner pin revision exhausted" }
        val pin = OwnerPin(ownerId, identity.id, canonicalIdentity, expectedFingerprint,
            revision, canonicalUtc(confirmedAt), "USER_CONFIRMED_INDEPENDENT_CHANNEL")
        return copy(ownerPins = (ownerPins + pin).sortedWith(compareBy(OwnerPin::ownerId, OwnerPin::keyId))) to pin
    }

    fun ownerPin(ownerId: String, keyId: String): OwnerPin? =
        ownerPins.singleOrNull { it.ownerId == ownerId && it.keyId == keyId }

    fun prepare(review: Review): LinkConsentLedger {
        require(writeFence == null) { "Resolve the original Link consent packet before preparing another review" }
        validateReview(review)
        val sourcePin = ownerPin(review.tuple.source.ownerId, review.tuple.source.ownerKeyId)
        val targetPin = ownerPin(review.tuple.target.ownerId, review.tuple.target.ownerKeyId)
        require(sourcePin != null && targetPin != null &&
            sourcePin.pinRevision == review.tuple.source.ownerPinRevision &&
            targetPin.pinRevision == review.tuple.target.ownerPinRevision &&
            sourcePin.ownerId == review.tuple.source.ownerId && sourcePin.keyId == review.tuple.source.ownerKeyId &&
            sourcePin.fingerprint == review.tuple.source.ownerFingerprint &&
            targetPin.ownerId == review.tuple.target.ownerId && targetPin.keyId == review.tuple.target.ownerKeyId &&
            targetPin.fingerprint == review.tuple.target.ownerFingerprint) {
            "Review does not match the independently pinned current Owner keys"
        }
        require((review.tuple.localSide == "SOURCE" && review.tuple.ownerId == review.tuple.source.ownerId) ||
            (review.tuple.localSide == "TARGET" && review.tuple.ownerId == review.tuple.target.ownerId)) {
            "Review local side does not match the authenticated Owner"
        }
        return copy(review = review)
    }

    fun stage(write: WriteFence): LinkConsentLedger {
        require(writeFence == null) { "An original Link consent packet is unresolved" }
        val prepared = review ?: throw IllegalArgumentException("Fresh Link consent review is missing")
        require(write.reviewId == prepared.reviewId && write.consentDigest == prepared.consentDigest &&
            write.tupleDigest == digestTuple(prepared.tuple) &&
            write.operation in LINK_WRITE_OPERATIONS && write.state == FenceState.PENDING) {
            "Link consent packet is not bound to the reviewed authority tuple"
        }
        validateFence(write)
        return copy(writeFence = write)
    }

    /** 409 and recovery outcomes only advance the fence state; none clear it. */
    fun markFenceState(operationId: String, requestSequence: Long, next: FenceState): LinkConsentLedger {
        val fence = writeFence ?: throw IllegalArgumentException("No Link consent packet is unresolved")
        require(fence.operationId == operationId && fence.requestSequence == requestSequence) {
            "Recovery result does not correlate with the original Link consent packet"
        }
        // Every recovery result remains fenced. Only completeOriginal or
        // resolveActivatedPair may remove the record.
        return copy(writeFence = fence.copy(state = next))
    }

    /** A generic status snapshot deliberately does not mutate or reconcile the Link fence. */
    fun observeGenericSnapshot(): LinkConsentLedger = this

    /** Profile selection changes invalidate only the one-use review, never an unresolved packet. */
    fun invalidateReviewForProfileGeneration(newGeneration: Long): LinkConsentLedger {
        require(newGeneration > 0)
        val selected = review ?: return this
        return if (selected.tuple.profileGeneration == newGeneration || writeFence != null) this else copy(review = null)
    }

    fun completeOriginal(completion: VerifiedOriginalCompletion): LinkConsentLedger {
        val fence = writeFence ?: throw IllegalArgumentException("No Link consent packet is unresolved")
        require(completion.operationId == fence.operationId &&
            completion.requestSequence == fence.requestSequence &&
            completion.responseSequence == fence.expectedResponseSequence &&
            completion.packetSha256 == fence.packetSha256 &&
            completion.signedProofSha256 == fence.signedProofSha256 &&
            completion.tupleDigest == fence.tupleDigest) {
            "Authenticated terminal response does not match the original Link consent packet and tuple"
        }
        return copy(writeFence = null, review = null)
    }

    /**
     * Resolves an uncertain partial grant only when a fresh active status contains
     * the exact original signed proof and exactly the original consent tuple.
     */
    fun resolveActivatedPair(pair: VerifiedActivatedPair): LinkConsentLedger {
        val fence = writeFence ?: throw IllegalArgumentException("No Link consent packet is unresolved")
        val selected = review ?: throw IllegalArgumentException("Original Link consent authority tuple is missing")
        val tuple = selected.tuple
        require(pair.freshResponseSequence > fence.expectedResponseSequence &&
            pair.linkId == tuple.linkId && pair.linkVersion == tuple.linkVersion &&
            pair.contractDigest == tuple.contractDigest && pair.manifestDigest == tuple.manifestDigest &&
            pair.policyDigest == tuple.policyDigest && pair.policyVersion == tuple.policyVersion &&
            pair.tupleDigest == fence.tupleDigest &&
            fence.signedProofSha256 in pair.includedSignedProofSha256) {
            "Fresh active Owner pair does not bind the original Link consent proof and tuple"
        }
        return copy(writeFence = null, review = null)
    }

    fun toJsonObject(): JsonObject = JsonObject().apply {
        addProperty("schema", SCHEMA)
        add("owner_pins", JsonArray().apply { ownerPins.forEach { add(it.toJson()) } })
        review?.let { add("review", it.toJson()) }
        writeFence?.let { add("write_fence", it.toJson()) }
    }

    fun encode(): ByteArray = toJsonObject().toString().toByteArray(StandardCharsets.UTF_8).also {
        require(it.size <= MAX_LEDGER_BYTES) { "Link consent ledger exceeds its storage limit" }
    }

    companion object {
        const val SCHEMA = 1
        const val MAX_LEDGER_BYTES = 512 * 1024
        const val MAX_OWNER_PINS = 64
        const val MAX_PROOF_BYTES = 16 * 1024
        const val MAX_PACKET_BYTES = 256 * 1024
        const val MAX_REVIEWERS = 8
        private const val MAX_ID_BYTES = 256
        const val MAX_PUBLIC_IDENTITY_BYTES = 8 * 1024
        private const val MAX_SIGNING_REQUEST_BYTES = 24 * 1024
        private val SHA256 = Regex("[0-9a-f]{64}")
        private val LINK_WRITE_OPERATIONS = setOf("link.key_grant", "link.review_policy_grant")

        fun empty(): LinkConsentLedger = LinkConsentLedger()

        fun decode(raw: ByteArray): LinkConsentLedger {
            require(raw.isNotEmpty() && raw.size <= MAX_LEDGER_BYTES) { "Link consent ledger size is invalid" }
            val json = JsonParser.parseString(String(raw, StandardCharsets.UTF_8))
            require(json.isJsonObject) { "Link consent ledger root is invalid" }
            val root = json.asJsonObject
            exactKeys(root, setOf("schema", "owner_pins"), setOf("review", "write_fence"))
            require(intValue(root, "schema") == SCHEMA) { "Unsupported Link consent ledger schema" }
            val pinsArray = arrayValue(root, "owner_pins")
            require(pinsArray.size() <= MAX_OWNER_PINS) { "Owner pin capacity exceeded" }
            val pins = pinsArray.map { element -> parsePin(objectValue(element, "owner pin")) }
            require(pins == pins.sortedWith(compareBy(OwnerPin::ownerId, OwnerPin::keyId)) &&
                pins.map { it.ownerId to it.keyId }.distinct().size == pins.size) {
                "Owner pin records are duplicated or unsorted"
            }
            val review = root.get("review")?.let { if (it.isJsonNull) null else parseReview(objectValue(it, "review")) }
            val fence = root.get("write_fence")?.let { if (it.isJsonNull) null else parseFence(objectValue(it, "write fence")) }
            val ledger = LinkConsentLedger(pins, review, fence)
            if (review != null) validateReview(review)
            if (fence != null) validateFence(fence)
            if (fence != null) {
                require(review != null && review.reviewId == fence.reviewId &&
                    review.consentDigest == fence.consentDigest && digestTuple(review.tuple) == fence.tupleDigest) {
                    "Link consent fence is detached from its original review tuple"
                }
            }
            return ledger
        }

        fun digestTuple(tuple: AuthorityTuple): String = sha256(tuple.toJson().toString().toByteArray(StandardCharsets.UTF_8))

        fun digest(raw: ByteArray): String = sha256(raw)

        private fun parsePin(value: JsonObject): OwnerPin {
            exactKeys(value, setOf("owner_id", "key_id", "public_identity_json", "fingerprint", "pin_revision", "confirmed_at", "trust_source"))
            val owner = stringValue(value, "owner_id")
            val key = stringValue(value, "key_id")
            val identityJson = stringValue(value, "public_identity_json")
            val fingerprint = stringValue(value, "fingerprint")
            val revision = longValue(value, "pin_revision")
            val confirmedAt = stringValue(value, "confirmed_at")
            val trustSource = stringValue(value, "trust_source")
            requireOwnerToken(owner, "owner ID")
            requireOwnerToken(key, "Owner key ID")
            require(identityJson.toByteArray(StandardCharsets.UTF_8).size <= MAX_PUBLIC_IDENTITY_BYTES &&
                SHA256.matches(fingerprint) && revision > 0 && trustSource == "USER_CONFIRMED_INDEPENDENT_CHANNEL") { "Owner pin record is invalid" }
            val identityObj = JsonParser.parseString(identityJson)
            require(identityObj.isJsonObject && identityObj.asJsonObject.keySet() == setOf("id", "kem_public", "signing_public") &&
                stringValue(identityObj.asJsonObject, "id") == key &&
                identityObj.asJsonObject.toString() == identityJson) { "Owner pin public identity is not canonical" }
            val identity = ClientWireCrypto.PublicIdentity.parse(identityObj.asJsonObject)
            require(identity.fingerprint() == fingerprint) { "Owner pin fingerprint differs from its public bytes" }
            canonicalUtc(confirmedAt)
            return OwnerPin(owner, key, identityJson, fingerprint, revision, confirmedAt, trustSource)
        }

        private fun parseReview(value: JsonObject): Review {
            exactKeys(value, setOf("review_id", "consent_digest", "tuple", "manifest_read", "status_read",
                "preview_read", "policy_json", "signing_request_json", "created_at"))
            val review = Review(
                stringValue(value, "review_id"), stringValue(value, "consent_digest"),
                parseTuple(objectValue(value.get("tuple"), "authority tuple")),
                parseRead(objectValue(value.get("manifest_read"), "manifest read")),
                parseRead(objectValue(value.get("status_read"), "status read")),
                value.get("preview_read")?.let { if (it.isJsonNull) null else parseRead(objectValue(it, "preview read")) },
                nullableString(value, "policy_json"),
                stringValue(value, "signing_request_json"), stringValue(value, "created_at"),
            )
            return review
        }

        private fun parseTuple(value: JsonObject): AuthorityTuple {
            exactKeys(value, setOf("profile_id", "profile_generation", "hub_id", "owner_id", "device_id",
                "session_epoch", "link_id", "link_version", "contract_digest", "manifest_digest", "local_side",
                "kind", "direction", "actions", "data_scopes", "expires_at", "source", "target", "expected_policy_version", "policy_version", "policy_digest",
                "maximum_proof_expires_at", "reviewers"))
            val expectedVersion = nullableLong(value, "expected_policy_version")
            val policyVersion = nullableLong(value, "policy_version")
            val policyDigest = nullableString(value, "policy_digest")
            val maximumProofExpiresAt = nullableString(value, "maximum_proof_expires_at")
            val reviewers = arrayValue(value, "reviewers").map { parseReviewer(objectValue(it, "reviewer qualification")) }
            return AuthorityTuple(
                stringValue(value, "profile_id"), longValue(value, "profile_generation"),
                stringValue(value, "hub_id"), stringValue(value, "owner_id"), stringValue(value, "device_id"),
                longValue(value, "session_epoch"), stringValue(value, "link_id"), longValue(value, "link_version"),
                stringValue(value, "contract_digest"), stringValue(value, "manifest_digest"),
                stringValue(value, "local_side"), stringValue(value, "kind"), stringValue(value, "direction"),
                stringArray(value, "actions"), stringArray(value, "data_scopes"), stringValue(value, "expires_at"),
                parseSide(objectValue(value.get("source"), "source scope")),
                parseSide(objectValue(value.get("target"), "target scope")),
                expectedVersion, policyVersion, policyDigest, maximumProofExpiresAt, reviewers,
            ).also(::validateTuple)
        }

        private fun parseSide(value: JsonObject): SideScope {
            exactKeys(value, setOf("endpoint_id", "group_id", "principal_id", "owner_id", "node_id", "binding_id",
                "binding_epoch", "candidate_version", "key_id", "key_fingerprint", "proof_digest",
                "membership_revision", "join_revision", "group_version", "owner_key_id", "owner_fingerprint",
                "owner_key_state", "owner_key_version", "owner_pin_revision"))
            return SideScope(
                stringValue(value, "endpoint_id"), stringValue(value, "group_id"), stringValue(value, "principal_id"),
                stringValue(value, "owner_id"), stringValue(value, "node_id"), stringValue(value, "binding_id"),
                longValue(value, "binding_epoch"), longValue(value, "candidate_version"),
                stringValue(value, "key_id"), stringValue(value, "key_fingerprint"), stringValue(value, "proof_digest"),
                longValue(value, "membership_revision"), longValue(value, "join_revision"), longValue(value, "group_version"),
                stringValue(value, "owner_key_id"), stringValue(value, "owner_fingerprint"), nullableString(value, "owner_key_state"),
                nullableLong(value, "owner_key_version"), longValue(value, "owner_pin_revision"),
            ).also(::validateSide)
        }

        private fun parseReviewer(value: JsonObject): ReviewerQualification {
            exactKeys(value, setOf("endpoint_id", "group_id", "membership_revision", "join_revision", "group_version",
                "binding_id", "binding_epoch", "action", "lease_expires_at"))
            return ReviewerQualification(
                stringValue(value, "endpoint_id"), stringValue(value, "group_id"),
                longValue(value, "membership_revision"), longValue(value, "join_revision"),
                longValue(value, "group_version"), stringValue(value, "binding_id"),
                longValue(value, "binding_epoch"), stringValue(value, "action"), stringValue(value, "lease_expires_at"),
            ).also(::validateReviewer)
        }

        private fun parseRead(value: JsonObject): ReadCorrelation {
            exactKeys(value, setOf("operation", "operation_id", "request_sequence", "response_sequence", "origin"))
            return ReadCorrelation(stringValue(value, "operation"), stringValue(value, "operation_id"),
                longValue(value, "request_sequence"), longValue(value, "response_sequence"),
                stringValue(value, "origin")).also(::validateRead)
        }

        private fun parseFence(value: JsonObject): WriteFence {
            exactKeys(value, setOf("operation", "operation_id", "request_sequence", "expected_response_sequence",
                "signed_proof_json", "signed_proof_sha256", "packet_json", "packet_sha256", "review_id",
                "consent_digest", "tuple_digest", "state"))
            return WriteFence(
                stringValue(value, "operation"), stringValue(value, "operation_id"),
                longValue(value, "request_sequence"), longValue(value, "expected_response_sequence"),
                stringValue(value, "signed_proof_json"), stringValue(value, "signed_proof_sha256"),
                stringValue(value, "packet_json"), stringValue(value, "packet_sha256"),
                stringValue(value, "review_id"), stringValue(value, "consent_digest"),
                stringValue(value, "tuple_digest"), enumValue(value, "state", FenceState.values().toSet()),
            ).also(::validateFence)
        }

        private fun validateReview(review: Review) {
            requireOwnerToken(review.reviewId, "review ID")
            require(SHA256.matches(review.consentDigest) && review.consentDigest == digestTuple(review.tuple)) {
                "Link consent digest is invalid or detached from its authority tuple"
            }
            validateTuple(review.tuple)
            validateRead(review.manifestRead)
            validateRead(review.statusRead)
            require(review.manifestRead.operation == "link.key_manifest" &&
                review.statusRead.operation == "link.key_grants" && review.manifestRead != review.statusRead) {
                "Link review lacks independently correlated current manifest and status reads"
            }
            if (review.tuple.kind == "REVIEW_POLICY") {
                require(review.previewRead?.operation == "link.review_policy_preview") {
                    "Policy review requires a fresh correlated preview"
                }
                require(review.policyJson?.isNotBlank() == true &&
                    review.policyJson.toByteArray(StandardCharsets.UTF_8).size <= MAX_SIGNING_REQUEST_BYTES) {
                    "Policy review does not retain the exact reviewed policy DTO"
                }
                validateRetainedPolicy(review)
            } else {
                require(review.tuple.kind == "KEY" && review.previewRead == null && review.policyJson == null) {
                    "Unsupported Link review kind"
                }
            }
            review.previewRead?.let(::validateRead)
            require(review.signingRequestJson.toByteArray(StandardCharsets.UTF_8).size <= MAX_SIGNING_REQUEST_BYTES &&
                review.signingRequestJson.isNotBlank()) { "Link signing request exceeds its storage bound" }
            canonicalUtc(review.createdAt)
        }

        /**
         * Revalidates the canonical policy retained with the durable review. NONE deliberately
         * has no reviewer qualifications; METADATA must retain one qualification for every
         * configured reviewer in the same order as the signed policy.
         */
        private fun validateRetainedPolicy(review: Review) {
            val raw = requireNotNull(review.policyJson)
            val parsed = try { JsonParser.parseString(raw) } catch (_: Exception) {
                throw IllegalArgumentException("Retained Link policy JSON is invalid")
            }
            require(parsed.isJsonObject) { "Retained Link policy JSON is invalid" }
            val value = parsed.asJsonObject
            exactKeys(value, setOf("mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds"))
            val reviewerRows = arrayValue(value, "reviewers").map { element ->
                val row = objectValue(element, "retained policy reviewer")
                exactKeys(row, setOf("endpoint_id", "group_id"))
                LinkReviewPolicyConsentReviewer(
                    endpointId = stringValue(row, "endpoint_id"),
                    groupId = stringValue(row, "group_id"),
                )
            }
            val policy = LinkReviewPolicyConsentPolicy(
                mode = stringValue(value, "mode"),
                reviewers = reviewerRows,
                maxFailovers = intValue(value, "max_failovers"),
                reviewerLeaseSeconds = intValue(value, "reviewer_lease_seconds"),
                maxReviewAgeSeconds = intValue(value, "max_review_age_seconds"),
            )
            val canonical = LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy)
            require(raw == canonical &&
                sha256(canonical.toByteArray(StandardCharsets.UTF_8)) == review.tuple.policyDigest) {
                "Retained Link policy is noncanonical or detached from its reviewed digest"
            }
            val policyScopes = policy.reviewers.map { it.endpointId to it.groupId }
            val qualificationScopes = review.tuple.reviewers.map { it.endpointId to it.groupId }
            require(policyScopes == qualificationScopes &&
                (policy.mode != "NONE" || qualificationScopes.isEmpty()) &&
                (policy.mode != "METADATA" || qualificationScopes.isNotEmpty())) {
                "Retained Link policy reviewers do not match current qualifications"
            }
        }

        private fun validateTuple(tuple: AuthorityTuple) {
            listOf(tuple.profileId, tuple.hubId, tuple.ownerId, tuple.deviceId, tuple.linkId).forEach {
                requireOwnerToken(it, "Link authority identifier")
            }
            require(tuple.profileGeneration > 0 && tuple.sessionEpoch > 0 && tuple.linkVersion > 0 &&
                tuple.localSide in setOf("SOURCE", "TARGET") && tuple.kind in setOf("KEY", "REVIEW_POLICY") &&
                SHA256.matches(tuple.contractDigest) && SHA256.matches(tuple.manifestDigest) &&
                tuple.direction in setOf("forward", "bidirectional") &&
                tuple.actions.size in 1..3 && tuple.actions.distinct().size == tuple.actions.size &&
                tuple.actions.zipWithNext().all { (a, b) -> a < b } &&
                tuple.actions.all { it in setOf("send", "ask", "reply") } && tuple.actions != listOf("reply") &&
                tuple.dataScopes.size <= 16 && tuple.dataScopes.distinct().size == tuple.dataScopes.size &&
                tuple.dataScopes.zipWithNext().all { (a, b) -> a < b } && tuple.dataScopes.all(::validContractToken)) {
                "Link authority tuple is invalid"
            }
            canonicalUtc(tuple.expiresAt)
            validateSide(tuple.source)
            validateSide(tuple.target)
            require(tuple.source.endpointId != tuple.target.endpointId) {
                "Link source and target scope is invalid"
            }
            require((tuple.localSide == "SOURCE" && tuple.ownerId == tuple.source.ownerId) ||
                (tuple.localSide == "TARGET" && tuple.ownerId == tuple.target.ownerId)) {
                "Link local side does not match the authenticated Owner"
            }
            if (tuple.kind == "REVIEW_POLICY") {
                require(tuple.expectedPolicyVersion != null && tuple.expectedPolicyVersion >= 0 &&
                    tuple.policyVersion != null && tuple.policyVersion > tuple.expectedPolicyVersion &&
                    tuple.policyDigest?.let(SHA256::matches) == true && tuple.maximumProofExpiresAt != null) {
                    "Link policy authority tuple is incomplete"
                }
                canonicalUtc(tuple.maximumProofExpiresAt!!)
                require(tuple.reviewers.size <= MAX_REVIEWERS) {
                    "Link policy reviewer qualifications are oversized"
                }
                tuple.reviewers.forEach(::validateReviewer)
                require(tuple.reviewers.map { it.endpointId to it.groupId }.distinct().size == tuple.reviewers.size) {
                    "Link reviewer qualifications contain duplicate scopes"
                }
                val local = if (tuple.localSide == "SOURCE") tuple.source else tuple.target
                require(local.ownerKeyState == "ACTIVE" && local.ownerKeyVersion != null && local.ownerKeyVersion > 0) {
                    "Policy consent requires fresh verified local Owner-key lifecycle evidence"
                }
            } else {
                require(tuple.expectedPolicyVersion == null && tuple.policyVersion == null &&
                    tuple.policyDigest == null && tuple.maximumProofExpiresAt == null && tuple.reviewers.isEmpty()) {
                    "Key grant tuple contains unrelated policy fields"
                }
            }
        }

        private fun validateSide(side: SideScope) {
            listOf(side.endpointId, side.groupId, side.principalId, side.ownerId, side.nodeId,
                side.bindingId, side.keyId, side.ownerKeyId).forEach { requireOwnerToken(it, "Link side identifier") }
            require(side.bindingEpoch > 0 && side.candidateVersion > 0 && side.membershipRevision > 0 &&
                side.joinRevision > 0 && side.groupVersion > 0 && side.ownerPinRevision > 0 &&
                ((side.ownerKeyState == null && side.ownerKeyVersion == null) ||
                    (side.ownerKeyState == "ACTIVE" && side.ownerKeyVersion != null && side.ownerKeyVersion > 0)) &&
                SHA256.matches(side.keyFingerprint.removePrefix("sha256:")) && SHA256.matches(side.proofDigest) &&
                SHA256.matches(side.ownerFingerprint)) {
                "Link Endpoint or Owner scope is invalid"
            }
        }

        private fun validateReviewer(value: ReviewerQualification) {
            requireOwnerToken(value.endpointId, "reviewer Endpoint")
            requireOwnerToken(value.groupId, "reviewer Group")
            requireOwnerToken(value.bindingId, "reviewer binding")
            require(value.membershipRevision > 0 && value.joinRevision > 0 && value.groupVersion > 0 &&
                value.bindingEpoch > 0 && value.action == "link.review") {
                "Link reviewer qualification is invalid"
            }
            canonicalUtc(value.leaseExpiresAt)
        }

        private fun validateRead(read: ReadCorrelation) {
            require(read.operation in setOf("link.key_manifest", "link.key_grants", "link.review_policy_status", "link.review_policy_preview") &&
                read.operationId.isNotBlank() && read.operationId.length <= MAX_ID_BYTES &&
                read.requestSequence > 0 && read.responseSequence > 0 && read.origin == "DIRECT") {
                "Link read correlation is invalid or not a fresh direct response"
            }
        }

        private fun validateFence(fence: WriteFence) {
            require(fence.operation in LINK_WRITE_OPERATIONS && fence.operationId.isNotBlank() &&
                fence.operationId.length <= MAX_ID_BYTES && fence.requestSequence > 0 &&
                fence.expectedResponseSequence > 0 &&
                fence.signedProofJson.toByteArray(StandardCharsets.UTF_8).size in 1..MAX_PROOF_BYTES &&
                SHA256.matches(fence.signedProofSha256) &&
                sha256(fence.signedProofJson.toByteArray(StandardCharsets.UTF_8)) == fence.signedProofSha256 &&
                fence.packetJson.toByteArray(StandardCharsets.UTF_8).size in 1..MAX_PACKET_BYTES &&
                SHA256.matches(fence.packetSha256) &&
                sha256(fence.packetJson.toByteArray(StandardCharsets.UTF_8)) == fence.packetSha256 &&
                fence.reviewId.isNotBlank() && fence.consentDigest.let(SHA256::matches) &&
                SHA256.matches(fence.tupleDigest)) { "Link consent write fence is invalid" }
        }

        private fun OwnerPin.toJson() = JsonObject().apply {
            addProperty("owner_id", ownerId); addProperty("key_id", keyId)
            addProperty("public_identity_json", publicIdentityJson); addProperty("fingerprint", fingerprint)
            addProperty("pin_revision", pinRevision); addProperty("confirmed_at", confirmedAt)
            addProperty("trust_source", trustSource)
        }

        private fun Review.toJson() = JsonObject().apply {
            addProperty("review_id", reviewId); addProperty("consent_digest", consentDigest)
            add("tuple", tuple.toJson()); add("manifest_read", manifestRead.toJson()); add("status_read", statusRead.toJson())
            previewRead?.let { add("preview_read", it.toJson()) } ?: add("preview_read", com.google.gson.JsonNull.INSTANCE)
            policyJson?.let { addProperty("policy_json", it) } ?: add("policy_json", com.google.gson.JsonNull.INSTANCE)
            addProperty("signing_request_json", signingRequestJson); addProperty("created_at", createdAt)
        }

        private fun AuthorityTuple.toJson() = JsonObject().apply {
            addProperty("profile_id", profileId); addProperty("profile_generation", profileGeneration)
            addProperty("hub_id", hubId); addProperty("owner_id", ownerId); addProperty("device_id", deviceId)
            addProperty("session_epoch", sessionEpoch); addProperty("link_id", linkId); addProperty("link_version", linkVersion)
            addProperty("contract_digest", contractDigest); addProperty("manifest_digest", manifestDigest)
            addProperty("local_side", localSide); addProperty("kind", kind)
            addProperty("direction", direction)
            add("actions", JsonArray().apply { actions.forEach(::add) })
            add("data_scopes", JsonArray().apply { dataScopes.forEach(::add) })
            addProperty("expires_at", expiresAt)
            add("source", source.toJson()); add("target", target.toJson())
            expectedPolicyVersion?.let { addProperty("expected_policy_version", it) } ?: add("expected_policy_version", com.google.gson.JsonNull.INSTANCE)
            policyVersion?.let { addProperty("policy_version", it) } ?: add("policy_version", com.google.gson.JsonNull.INSTANCE)
            policyDigest?.let { addProperty("policy_digest", it) } ?: add("policy_digest", com.google.gson.JsonNull.INSTANCE)
            maximumProofExpiresAt?.let { addProperty("maximum_proof_expires_at", it) } ?: add("maximum_proof_expires_at", com.google.gson.JsonNull.INSTANCE)
            add("reviewers", JsonArray().apply { reviewers.forEach { add(it.toJson()) } })
        }

        private fun SideScope.toJson() = JsonObject().apply {
            addProperty("endpoint_id", endpointId); addProperty("group_id", groupId); addProperty("principal_id", principalId)
            addProperty("owner_id", ownerId); addProperty("node_id", nodeId); addProperty("binding_id", bindingId)
            addProperty("binding_epoch", bindingEpoch); addProperty("candidate_version", candidateVersion)
            addProperty("key_id", keyId); addProperty("key_fingerprint", keyFingerprint); addProperty("proof_digest", proofDigest)
            addProperty("membership_revision", membershipRevision); addProperty("join_revision", joinRevision)
            addProperty("group_version", groupVersion); addProperty("owner_key_id", ownerKeyId)
            addProperty("owner_fingerprint", ownerFingerprint)
            ownerKeyState?.let { addProperty("owner_key_state", it) } ?: add("owner_key_state", com.google.gson.JsonNull.INSTANCE)
            ownerKeyVersion?.let { addProperty("owner_key_version", it) } ?: add("owner_key_version", com.google.gson.JsonNull.INSTANCE)
            addProperty("owner_pin_revision", ownerPinRevision)
        }

        private fun ReviewerQualification.toJson() = JsonObject().apply {
            addProperty("endpoint_id", endpointId); addProperty("group_id", groupId)
            addProperty("membership_revision", membershipRevision); addProperty("join_revision", joinRevision)
            addProperty("group_version", groupVersion); addProperty("binding_id", bindingId)
            addProperty("binding_epoch", bindingEpoch); addProperty("action", action)
            addProperty("lease_expires_at", leaseExpiresAt)
        }

        private fun ReadCorrelation.toJson() = JsonObject().apply {
            addProperty("operation", operation); addProperty("operation_id", operationId)
            addProperty("request_sequence", requestSequence); addProperty("response_sequence", responseSequence)
            addProperty("origin", origin)
        }

        private fun WriteFence.toJson() = JsonObject().apply {
            addProperty("operation", operation); addProperty("operation_id", operationId)
            addProperty("request_sequence", requestSequence); addProperty("expected_response_sequence", expectedResponseSequence)
            addProperty("signed_proof_json", signedProofJson); addProperty("signed_proof_sha256", signedProofSha256)
            addProperty("packet_json", packetJson); addProperty("packet_sha256", packetSha256)
            addProperty("review_id", reviewId); addProperty("consent_digest", consentDigest)
            addProperty("tuple_digest", tupleDigest); addProperty("state", state.name)
        }

        private fun exactKeys(value: JsonObject, required: Set<String>, optional: Set<String> = emptySet()) {
            require(value.keySet().containsAll(required) && value.keySet().all { it in required || it in optional }) {
                "Link consent ledger object fields are invalid"
            }
        }

        private fun objectValue(value: JsonElement?, label: String): JsonObject {
            require(value != null && value.isJsonObject) { "Link consent ledger $label is invalid" }
            return value.asJsonObject
        }

        private fun arrayValue(value: JsonObject, field: String): JsonArray {
            val element = value.get(field)
            require(element != null && element.isJsonArray) { "Link consent ledger $field is invalid" }
            return element.asJsonArray
        }

        private fun stringArray(value: JsonObject, field: String): List<String> {
            val items = arrayValue(value, field)
            require(items.all { it.isJsonPrimitive && it.asJsonPrimitive.isString }) {
                "Link consent ledger $field is invalid"
            }
            return items.map { it.asString }
        }

        private fun stringValue(value: JsonObject, field: String): String {
            val element = value.get(field)
            require(element != null && element.isJsonPrimitive && element.asJsonPrimitive.isString) {
                "Link consent ledger $field is invalid"
            }
            return element.asString
        }

        private fun longValue(value: JsonObject, field: String): Long {
            val element = value.get(field)
            require(element != null && element.isJsonPrimitive && element.asJsonPrimitive.isNumber &&
                Regex("0|[1-9][0-9]*").matches(element.asString)) { "Link consent ledger $field is invalid" }
            return element.asString.toLong()
        }

        private fun intValue(value: JsonObject, field: String): Int = longValue(value, field).toInt()

        private fun nullableLong(value: JsonObject, field: String): Long? =
            if (value.get(field)?.isJsonNull == true) null else longValue(value, field)

        private fun nullableString(value: JsonObject, field: String): String? =
            if (value.get(field)?.isJsonNull == true) null else stringValue(value, field)

        private fun <T : Enum<T>> enumValue(value: JsonObject, field: String, entries: Set<T>): T {
            val text = stringValue(value, field)
            return entries.singleOrNull { it.name == text } ?: throw IllegalArgumentException("Link ledger enum is invalid")
        }

        private fun requireOwnerToken(value: String, label: String) {
            require(value.isNotBlank() && value.toByteArray(StandardCharsets.UTF_8).size <= MAX_ID_BYTES &&
                value == value.trim() && value.none { it.isISOControl() || it == '/' || it == '\\' }) {
                "Link consent ledger $label is invalid"
            }
        }

        private fun validContractToken(value: String): Boolean = value.isNotBlank() && value.length <= 128 &&
            value == value.trim() && value.none { it.isISOControl() || it == '/' || it == '\\' }

        private fun canonicalUtc(value: Instant): String = GroupKeyManifestVerifier.formatCanonicalUtc(value)

        private fun canonicalUtc(value: String) {
            val parsed = Instant.parse(value)
            // Existing encrypted ledgers used Java Instant.toString(); preserve those bytes while
            // accepting Go-formatted Link timestamps written by newer clients.
            require(value == parsed.toString() ||
                value == GroupKeyManifestVerifier.formatCanonicalUtc(parsed)) {
                "Link consent ledger timestamp is not canonical UTC"
            }
        }

        private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(value).joinToString("") { "%02x".format(it) }

    }
}
