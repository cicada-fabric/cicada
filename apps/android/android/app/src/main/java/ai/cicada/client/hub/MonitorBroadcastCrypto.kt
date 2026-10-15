package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.stream.JsonWriter
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Arrays
import java.util.Base64

/** Independent Client implementation of the public Monitor Broadcast v2 contract. */
internal object MonitorBroadcastCrypto {
    private const val TYPE = "MONITOR_BROADCAST"
    private const val SUITE = "ML-KEM-768+ML-DSA-65/AES-256-GCM"
    private const val CONSENT_DOMAIN = "cicada/client/monitor-broadcast/consent/v1\u0000"
    private const val AAD_DOMAIN = "cicada/client/monitor-broadcast/aad/v1\u0000"
    private const val SIGN_DOMAIN = "cicada/client/monitor-broadcast/sign/v1\u0000"
    private const val BODY_MAX_BYTES = 16 * 1024
    private const val PREVIEW_TTL_SECONDS = 5 * 60L
    // Local defensive allowance for Hub/Client clock skew; never changes the
    // expiry timestamp serialized into the response or any signed bytes.
    private const val CLIENT_CLOCK_SKEW_TOLERANCE_SECONDS = 5L
    private const val PREVIEW_MAX_BYTES = 56 * 1024

    private val resultFields = listOf(
        "preview_id", "broadcast_id", "status", "group_id", "monitor_endpoint_id",
        "body_sha256", "snapshot_digest", "expires_at",
    )
    private val optionalResultFields = listOf(
        "approved_at", "dispatch_authorized_at", "sealed_payload_digest",
    )
    private val previewFields = listOf(
        "monitor_grant_manifest", "monitor_grant_signed_proof", "consent_scope", "consent_sha256",
    )
    private val scopeFields = listOf(
        "version", "broadcast_id", "group_id", "group_revision", "source", "recipients",
    )
    private val cardFields = listOf(
        "endpoint_id", "principal_id", "owner_id", "node_id", "membership_revision",
        "group_join_revision", "binding_id", "binding_epoch", "key_id", "key_version",
        "key_fingerprint", "key_proof_digest",
    )
    private val manifestFields = listOf(
        "version", "operation", "hub_id", "owner_id", "principal_id", "group_id",
        "group_revision", "endpoint_id", "node_id", "binding_id", "binding_epoch",
        "membership_revision", "endpoint_join_revision", "candidate_version", "candidate_key_id",
        "candidate_fingerprint", "candidate_proof_digest", "candidate_binding_digest",
        "candidate_public_identity", "candidate_attestation", "owner_key_id", "issued_at",
        "expires_at", "digest",
    )
    private val contextFields = listOf(
        "hub_id", "owner_id", "client_device_id", "client_session_epoch", "client_key_version",
        "approval_id", "broadcast_id", "group_id", "monitor_endpoint_id", "monitor_key_id",
        "monitor_binding_id", "monitor_binding_epoch", "body_sha256",
        "recipient_snapshot_sha256", "expires_at", "consent_sha256",
        "confirm_request_sequence",
    )
    private val innerFields = listOf(
        "version", "algorithm", "sequence", "kem_ciphertext", "nonce", "ciphertext",
        "sender_id", "sender_signing_public", "signature",
    )
    private val outerFields = listOf("type", "version", "suite", "context", "sealed", "signature")

    data class TrustedPrepare(
        val hubId: String,
        val ownerId: String,
        val groupId: String,
        val monitorEndpointId: String,
        val bodySha256: String,
    )

    data class ConsentEndpoint(
        val endpointId: String,
        val principalId: String,
        val ownerId: String,
        val nodeId: String,
        val membershipRevision: Long,
        val groupJoinRevision: Long,
        val bindingId: String,
        val bindingEpoch: Long,
        val keyId: String,
        val keyVersion: Long,
        val keyFingerprint: String,
        val keyProofDigest: String,
    )

    /** A prepare or recovered preview that has passed all local cryptographic checks. */
    class VerifiedPrepare internal constructor(
        val previewId: String,
        val broadcastId: String,
        val status: String,
        val groupId: String,
        val monitorEndpointId: String,
        val bodySha256: String,
        val snapshotDigest: String,
        val expiresAt: String,
        val grantExpiresAt: String,
        val validUntil: Instant,
        val monitorKeyId: String,
        val monitorBindingId: String,
        val monitorBindingEpoch: Long,
        val consentSha256: String,
        val groupRevision: Long,
        val source: ConsentEndpoint,
        recipients: List<ConsentEndpoint>,
        internal val hubId: String,
        internal val ownerId: String,
        internal val monitorPublicIdentity: ClientWireCrypto.PublicIdentity,
        internal val confirmationEligible: Boolean,
    ) {
        val recipients: List<ConsentEndpoint> = recipients.toList()
        val canConfirm: Boolean get() = canConfirmAt(Instant.now())

        internal fun canConfirmAt(now: Instant): Boolean = confirmationEligible &&
            status == "PREPARED" && validUntil.isAfter(now)
    }

    /**
     * Verifies the returned Group Endpoint candidate, owner-signed grant, the
     * complete ordered consent cards, and every binding to the request scope.
     * `result` may be the RPC facade object (`ok`/`result`) or its bare result DTO.
     */
    fun verifyPrepare(
        result: JsonObject,
        trusted: TrustedPrepare,
        ownerPublic: ClientWireCrypto.PublicIdentity,
        now: Instant = Instant.now(),
    ): VerifiedPrepare = verifyPrepareInternal(result, trusted, ownerPublic, now, historical = false)

    /**
     * Verifies the same complete evidence at the inferred prepare instant for
     * consuming an expired authenticated ledger result. The returned evidence
     * is permanently non-confirmable, even if the local clock is later reset.
     */
    fun verifyPrepareForLedger(
        result: JsonObject,
        trusted: TrustedPrepare,
        ownerPublic: ClientWireCrypto.PublicIdentity,
        now: Instant = Instant.now(),
    ): VerifiedPrepare = verifyPrepareInternal(result, trusted, ownerPublic, now, historical = true)

    private fun verifyPrepareInternal(
        result: JsonObject,
        trusted: TrustedPrepare,
        ownerPublic: ClientWireCrypto.PublicIdentity,
        now: Instant,
        historical: Boolean,
    ): VerifiedPrepare {
        require(result.toString().toByteArray(StandardCharsets.UTF_8).size <= 64 * 1024) {
            "Monitor response exceeds its protocol limit"
        }
        require(listOf(trusted.hubId, trusted.ownerId, trusted.groupId,
            trusted.monitorEndpointId).all(::canonicalId) && isDigest(trusted.bodySha256)) {
            "Invalid trusted Monitor prepare scope"
        }
        ownerPublic.validate()
        val dto = unwrapResult(result)
        require(dto.toString().toByteArray(StandardCharsets.UTF_8).size <= PREVIEW_MAX_BYTES) {
            "Monitor preview exceeds its protocol limit"
        }
        val status = string(dto, "status")
        require(status in setOf("PREPARED", "APPROVED", "DISPATCH_AUTHORIZED")) {
            "Monitor result status is not recoverable"
        }
        val expectedOrder = buildList {
            addAll(resultFields)
            optionalResultFields.filterTo(this) { dto.has(it) }
            add("preview")
        }
        require(hasExactKeys(dto, expectedOrder)) { "Monitor result has an invalid field shape" }
        for (field in optionalResultFields) {
            if (!dto.has(field)) continue
            when (field) {
                "approved_at", "dispatch_authorized_at" ->
                    GroupKeyManifestVerifier.parseCanonicalUtc(string(dto, field))
                "sealed_payload_digest" -> require(isDigest(string(dto, field))) {
                    "Invalid sealed Monitor payload digest"
                }
            }
        }
        require(recoveryMetadataMatchesStatus(dto, status)) {
            "Monitor recovery metadata does not match its state"
        }

        val previewId = string(dto, "preview_id")
        val broadcastId = string(dto, "broadcast_id")
        val groupId = string(dto, "group_id")
        val monitorEndpointId = string(dto, "monitor_endpoint_id")
        val bodySha256 = string(dto, "body_sha256")
        val snapshotDigest = string(dto, "snapshot_digest")
        val expiresAt = string(dto, "expires_at")
        require(listOf(previewId, broadcastId, groupId, monitorEndpointId).all(::canonicalId) &&
            isDigest(bodySha256) && isDigest(snapshotDigest) && bodySha256 == trusted.bodySha256 &&
            groupId == trusted.groupId && monitorEndpointId == trusted.monitorEndpointId) {
            "Monitor prepare differs from the trusted request"
        }
        val expiry = GroupKeyManifestVerifier.parseCanonicalUtc(expiresAt)
        require(expiry <= now.plusSeconds(
            PREVIEW_TTL_SECONDS + CLIENT_CLOCK_SKEW_TOLERANCE_SECONDS,
        ) && (historical || expiry.isAfter(now))) {
            "Monitor preview is expired or outside its five-minute lifetime"
        }

        val preview = dto.get("preview")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor preview evidence is missing")
        require(hasExactKeys(preview, previewFields)) { "Monitor preview has an invalid field shape" }
        val manifest = preview.get("monitor_grant_manifest")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor Group grant manifest is missing")
        require(keys(manifest) == manifestFields && canonicalManifest(manifest) == manifest.toString()) {
            "Monitor Group grant manifest is noncanonical"
        }
        val grantExpiresAt = string(manifest, "expires_at")
        val grantExpiry = GroupKeyManifestVerifier.parseCanonicalUtc(grantExpiresAt)
        val preparedAt = expiry.minusSeconds(PREVIEW_TTL_SECONDS)
        val evidenceAt = if (historical) {
            require(!expiry.isAfter(now) || !grantExpiry.isAfter(now)) {
                "Historical Monitor verification requires an expired preview or Owner grant"
            }
            require(!preparedAt.isAfter(now)) {
                "Monitor preview preparation time is in the future"
            }
            preparedAt
        } else {
            now
        }
        val verifiedManifest = GroupKeyManifestVerifier.verifyManifest(
            manifest, trusted.hubId, trusted.ownerId, trusted.groupId,
            trusted.monitorEndpointId, ownerPublic.id, evidenceAt,
        )
        val monitorPublic = ClientWireCrypto.PublicIdentity.parse(
            verifiedManifest.getAsJsonObject("candidate_public_identity"),
        )
        require(ownerPublic.id == string(manifest, "owner_key_id")) {
            "Monitor Group grant is bound to another Owner key"
        }

        val signedProof = canonicalBase64(preview, "monitor_grant_signed_proof")
        require(signedProof.isNotEmpty() && signedProof.size <= 16 * 1024) {
            "Monitor Group owner proof exceeds its protocol limit"
        }
        GroupKeyOwnerProof.verify(signedProof, verifiedManifest, ownerPublic, evidenceAt)

        val scopeJson = preview.get("consent_scope")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor consent scope is missing")
        val scope = parseConsentScope(scopeJson)
        require(canonicalConsentJson(scope) == scopeJson.toString()) {
            "Monitor consent scope is noncanonical"
        }
        val consentDigest = consentDigest(scope)
        val advertisedConsent = string(preview, "consent_sha256")
        require(isDigest(advertisedConsent) && consentDigest == advertisedConsent) {
            "Monitor consent digest mismatch"
        }
        require(scope.broadcastId == broadcastId && scope.groupId == groupId &&
            scope.groupRevision == positive(manifest, "group_revision") &&
            scope.source.endpointId == monitorEndpointId &&
            scope.source.ownerId == trusted.ownerId &&
            scope.source.endpointId == string(manifest, "endpoint_id") &&
            scope.source.principalId == string(manifest, "principal_id") &&
            scope.source.ownerId == string(manifest, "owner_id") &&
            scope.source.nodeId == string(manifest, "node_id") &&
            scope.source.membershipRevision == positive(manifest, "membership_revision") &&
            scope.source.groupJoinRevision == positive(manifest, "endpoint_join_revision") &&
            scope.source.bindingId == string(manifest, "binding_id") &&
            scope.source.bindingEpoch == positive(manifest, "binding_epoch") &&
            scope.source.keyId == monitorPublic.id &&
            scope.source.keyVersion == positive(manifest, "candidate_version") &&
            scope.source.keyFingerprint == string(manifest, "candidate_fingerprint") &&
            scope.source.keyProofDigest == string(manifest, "candidate_proof_digest")) {
            "Monitor consent source differs from the owner-signed Group grant"
        }
        require(scope.source.keyFingerprint == peerFingerprint(monitorPublic)) {
            "Monitor consent key fingerprint differs from the candidate public key"
        }

        return VerifiedPrepare(
            previewId = previewId,
            broadcastId = broadcastId,
            status = status,
            groupId = groupId,
            monitorEndpointId = monitorEndpointId,
            bodySha256 = bodySha256,
            snapshotDigest = snapshotDigest,
            expiresAt = expiresAt,
            grantExpiresAt = grantExpiresAt,
            validUntil = minOf(expiry, grantExpiry),
            monitorKeyId = monitorPublic.id,
            monitorBindingId = scope.source.bindingId,
            monitorBindingEpoch = scope.source.bindingEpoch,
            consentSha256 = consentDigest,
            groupRevision = scope.groupRevision,
            source = scope.source,
            recipients = scope.recipients,
            hubId = trusted.hubId,
            ownerId = trusted.ownerId,
            monitorPublicIdentity = monitorPublic,
            confirmationEligible = !historical,
        )
    }

    /** Returns padded-base64 of the complete, signed MonitorBroadcastEnvelope v2 bytes. */
    fun sealBody(
        deviceIdentity: ClientWireCrypto.Identity,
        verified: VerifiedPrepare,
        clientDeviceId: String,
        clientSessionEpoch: Long,
        clientKeyVersion: Long,
        confirmRequestSequence: Long,
        body: String,
    ): String {
        require(verified.status == "PREPARED" && verified.canConfirm) {
            "Only a current PREPARED Monitor preview can be confirmed"
        }
        require(canonicalId(clientDeviceId) && clientSessionEpoch > 0 && clientKeyVersion > 0 &&
            confirmRequestSequence > 0) { "Invalid authenticated Client session binding" }
        val bodyBytes = exactUtf8(body)
        require(bodyBytes.isNotEmpty() && bodyBytes.size <= BODY_MAX_BYTES) {
            "Monitor body must contain at most 16 KiB of UTF-8"
        }
        require(sha256Hex(bodyBytes) == verified.bodySha256) {
            "Monitor body differs from the reviewed body digest"
        }
        require(verified.monitorPublicIdentity.id == verified.monitorKeyId &&
            verified.source.endpointId == verified.monitorEndpointId &&
            verified.source.keyId == verified.monitorKeyId &&
            peerFingerprint(verified.monitorPublicIdentity) == verified.source.keyFingerprint &&
            isDigest(verified.snapshotDigest) && isDigest(verified.consentSha256)) {
            "Verified Monitor preview binding was changed"
        }

        val context = canonicalContext(
            hubId = verified.hubId,
            ownerId = verified.ownerId,
            clientDeviceId = clientDeviceId,
            clientSessionEpoch = clientSessionEpoch,
            clientKeyVersion = clientKeyVersion,
            approvalId = verified.previewId,
            broadcastId = verified.broadcastId,
            groupId = verified.groupId,
            monitorEndpointId = verified.monitorEndpointId,
            monitorKeyId = verified.monitorKeyId,
            monitorBindingId = verified.monitorBindingId,
            monitorBindingEpoch = verified.monitorBindingEpoch,
            bodySha256 = verified.bodySha256,
            recipientSnapshotSha256 = verified.snapshotDigest,
            expiresAt = verified.expiresAt,
            consentSha256 = verified.consentSha256,
            confirmRequestSequence = confirmRequestSequence,
        )
        val aad = (AAD_DOMAIN + context).toByteArray(StandardCharsets.UTF_8)
        val inner = try {
            ClientWireCrypto.sealRawEnvelope(
                deviceIdentity, verified.monitorPublicIdentity, confirmRequestSequence, aad, bodyBytes,
            )
        } finally {
            Arrays.fill(bodyBytes, 0.toByte())
        }
        val outerUnsigned = outerJson(context, inner, signature = null)
        val outerSignature = deviceIdentity.sign(
            (SIGN_DOMAIN + outerUnsigned).toByteArray(StandardCharsets.UTF_8),
        )
        val complete = outerJson(context, inner, ClientWireCrypto.encode(outerSignature))
            .toByteArray(StandardCharsets.UTF_8)
        require(complete.size <= 48 * 1024) { "Monitor envelope exceeds its wire limit" }
        return ClientWireCrypto.encode(complete)
    }

    /** Computes the public ordered consent digest; used by the vector test. */
    internal fun consentDigestForVector(scopeJson: JsonObject): String {
        val scope = parseConsentScope(scopeJson)
        require(canonicalConsentJson(scope) == scopeJson.toString()) {
            "Monitor consent scope is noncanonical"
        }
        return consentDigest(scope)
    }

    /** Canonical public context bytes exposed only for independent vector checks. */
    internal fun canonicalContextForVector(context: JsonObject): String {
        require(keys(context) == contextFields) { "Monitor vector context shape/order changed" }
        return canonicalContext(
            string(context, "hub_id"), string(context, "owner_id"),
            string(context, "client_device_id"), positive(context, "client_session_epoch"),
            positive(context, "client_key_version"), string(context, "approval_id"),
            string(context, "broadcast_id"), string(context, "group_id"),
            string(context, "monitor_endpoint_id"), string(context, "monitor_key_id"),
            string(context, "monitor_binding_id"), positive(context, "monitor_binding_epoch"),
            string(context, "body_sha256"), string(context, "recipient_snapshot_sha256"),
            string(context, "expires_at"), string(context, "consent_sha256"),
            positive(context, "confirm_request_sequence"),
        )
    }

    internal fun aadForVector(context: JsonObject): ByteArray =
        (AAD_DOMAIN + canonicalContextForVector(context)).toByteArray(StandardCharsets.UTF_8)

    internal fun outerSigningBytesForVector(envelope: JsonObject): ByteArray {
        require(keys(envelope) == outerFields) { "Monitor vector envelope shape/order changed" }
        val context = envelope.get("context")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor vector context is missing")
        val sealed = envelope.get("sealed")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor vector sealed envelope is missing")
        val unsigned = outerJson(canonicalContextForVector(context),
            canonicalInnerJson(sealed, nullSignature = false), null)
        return (SIGN_DOMAIN + unsigned).toByteArray(StandardCharsets.UTF_8)
    }

    internal fun innerSigningBytesForVector(sealed: JsonObject): ByteArray =
        canonicalInnerJson(sealed).toByteArray(StandardCharsets.UTF_8)

    private fun unwrapResult(source: JsonObject): JsonObject {
        if (!source.has("ok")) return source
        require(source.get("ok").isJsonPrimitive && source.get("ok").asBoolean) {
            "Monitor prepare RPC was rejected"
        }
        return source.get("result")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor prepare RPC omitted its result")
    }

    private fun recoveryMetadataMatchesStatus(dto: JsonObject, status: String): Boolean {
        val approved = dto.has("approved_at")
        val dispatched = dto.has("dispatch_authorized_at")
        val sealedDigest = dto.has("sealed_payload_digest")
        return when (status) {
            "PREPARED" -> !approved && !dispatched && !sealedDigest
            "APPROVED" -> approved && !dispatched && sealedDigest
            "DISPATCH_AUTHORIZED" -> approved && dispatched && sealedDigest
            else -> false
        }
    }

    private data class ConsentScope(
        val broadcastId: String,
        val groupId: String,
        val groupRevision: Long,
        val source: ConsentEndpoint,
        val recipients: List<ConsentEndpoint>,
    )

    private fun parseConsentScope(source: JsonObject): ConsentScope {
        require(keys(source) == scopeFields) { "Monitor consent scope has an invalid shape or field order" }
        require(positive(source, "version") == 1L) { "Unsupported Monitor consent scope version" }
        val sourceCard = source.get("source")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Monitor consent source card is missing")
        val cards = source.get("recipients")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Monitor recipients must be a JSON array")
        require(cards.size() <= 32) { "Monitor consent recipient count exceeds its limit" }
        val card = parseCard(sourceCard)
        val recipients = cards.map { element ->
            parseCard(element.takeIf { it.isJsonObject }?.asJsonObject
                ?: throw IllegalArgumentException("Monitor recipient card is malformed"))
        }
        require(recipients.all { it.ownerId == card.ownerId && it.endpointId != card.endpointId } &&
            recipients.map { it.endpointId } == recipients.map { it.endpointId }.sorted() &&
            recipients.map { it.endpointId }.distinct().size == recipients.size) {
            "Monitor recipients are foreign, duplicated, unsorted, or include the source"
        }
        val broadcastId = string(source, "broadcast_id")
        val groupId = string(source, "group_id")
        val groupRevision = positive(source, "group_revision")
        require(canonicalId(broadcastId) && canonicalId(groupId)) {
            "Monitor consent group or broadcast identity is invalid"
        }
        return ConsentScope(broadcastId, groupId, groupRevision, card, recipients)
    }

    private fun parseCard(source: JsonObject): ConsentEndpoint {
        require(keys(source) == cardFields) { "Monitor consent card has an invalid shape or field order" }
        val endpoint = ConsentEndpoint(
            endpointId = string(source, "endpoint_id"),
            principalId = string(source, "principal_id"),
            ownerId = string(source, "owner_id"),
            nodeId = string(source, "node_id"),
            membershipRevision = positive(source, "membership_revision"),
            groupJoinRevision = positive(source, "group_join_revision"),
            bindingId = string(source, "binding_id"),
            bindingEpoch = positive(source, "binding_epoch"),
            keyId = string(source, "key_id"),
            keyVersion = positive(source, "key_version"),
            keyFingerprint = string(source, "key_fingerprint"),
            keyProofDigest = string(source, "key_proof_digest"),
        )
        require(listOf(endpoint.endpointId, endpoint.principalId, endpoint.ownerId,
            endpoint.nodeId, endpoint.bindingId, endpoint.keyId).all(::canonicalId) &&
            endpoint.keyFingerprint.matches(Regex("^sha256:[0-9a-f]{64}$")) &&
            isDigest(endpoint.keyProofDigest)) { "Monitor consent card has invalid identities or key facts" }
        return endpoint
    }

    private fun canonicalConsentJson(scope: ConsentScope): String = ClientWireCrypto.json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("broadcast_id").value(scope.broadcastId)
            .name("group_id").value(scope.groupId)
            .name("group_revision").value(scope.groupRevision)
            .name("source")
        writeCard(writer, scope.source)
        writer.name("recipients").beginArray()
        for (recipient in scope.recipients) writeCard(writer, recipient)
        writer.endArray().endObject()
    }

    private fun consentDigest(scope: ConsentScope): String = sha256Hex(
        (CONSENT_DOMAIN + canonicalConsentJson(scope)).toByteArray(StandardCharsets.UTF_8),
    )

    private fun writeCard(writer: JsonWriter, card: ConsentEndpoint) {
        writer.beginObject()
            .name("endpoint_id").value(card.endpointId)
            .name("principal_id").value(card.principalId)
            .name("owner_id").value(card.ownerId)
            .name("node_id").value(card.nodeId)
            .name("membership_revision").value(card.membershipRevision)
            .name("group_join_revision").value(card.groupJoinRevision)
            .name("binding_id").value(card.bindingId)
            .name("binding_epoch").value(card.bindingEpoch)
            .name("key_id").value(card.keyId)
            .name("key_version").value(card.keyVersion)
            .name("key_fingerprint").value(card.keyFingerprint)
            .name("key_proof_digest").value(card.keyProofDigest)
            .endObject()
    }

    private fun canonicalManifest(manifest: JsonObject): String {
        val ordered = JsonObject()
        for (field in manifestFields) ordered.add(field, manifest.get(field)?.deepCopy()
            ?: throw IllegalArgumentException("Monitor manifest is missing $field"))
        return ordered.toString()
    }

    private fun canonicalContext(
        hubId: String,
        ownerId: String,
        clientDeviceId: String,
        clientSessionEpoch: Long,
        clientKeyVersion: Long,
        approvalId: String,
        broadcastId: String,
        groupId: String,
        monitorEndpointId: String,
        monitorKeyId: String,
        monitorBindingId: String,
        monitorBindingEpoch: Long,
        bodySha256: String,
        recipientSnapshotSha256: String,
        expiresAt: String,
        consentSha256: String,
        confirmRequestSequence: Long,
    ): String {
        require(listOf(hubId, ownerId, clientDeviceId, approvalId, broadcastId, groupId,
            monitorEndpointId, monitorKeyId, monitorBindingId).all(::canonicalId) &&
            clientSessionEpoch > 0 && clientKeyVersion > 0 && monitorBindingEpoch > 0 &&
            confirmRequestSequence > 0 && isDigest(bodySha256) &&
            isDigest(recipientSnapshotSha256) && isDigest(consentSha256)) {
            "Invalid Monitor envelope context"
        }
        GroupKeyManifestVerifier.parseCanonicalUtc(expiresAt)
        return ClientWireCrypto.json { writer ->
            writer.beginObject()
                .name("hub_id").value(hubId)
                .name("owner_id").value(ownerId)
                .name("client_device_id").value(clientDeviceId)
                .name("client_session_epoch").value(clientSessionEpoch)
                .name("client_key_version").value(clientKeyVersion)
                .name("approval_id").value(approvalId)
                .name("broadcast_id").value(broadcastId)
                .name("group_id").value(groupId)
                .name("monitor_endpoint_id").value(monitorEndpointId)
                .name("monitor_key_id").value(monitorKeyId)
                .name("monitor_binding_id").value(monitorBindingId)
                .name("monitor_binding_epoch").value(monitorBindingEpoch)
                .name("body_sha256").value(bodySha256)
                .name("recipient_snapshot_sha256").value(recipientSnapshotSha256)
                .name("expires_at").value(expiresAt)
                .name("consent_sha256").value(consentSha256)
                .name("confirm_request_sequence").value(confirmRequestSequence)
                .endObject()
        }
    }

    private fun canonicalInnerJson(sealed: JsonObject, nullSignature: Boolean = true): String {
        require(keys(sealed) == innerFields) { "Monitor inner envelope shape/order changed" }
        return ClientWireCrypto.json { writer ->
            writer.beginObject()
                .name("version").value(positive(sealed, "version"))
                .name("algorithm").value(string(sealed, "algorithm"))
                .name("sequence").value(positive(sealed, "sequence"))
                .name("kem_ciphertext").value(string(sealed, "kem_ciphertext"))
                .name("nonce").value(string(sealed, "nonce"))
                .name("ciphertext").value(string(sealed, "ciphertext"))
                .name("sender_id").value(string(sealed, "sender_id"))
                .name("sender_signing_public").value(string(sealed, "sender_signing_public"))
            writer.name("signature")
            if (nullSignature) writer.nullValue() else writer.value(string(sealed, "signature"))
            writer.endObject()
        }
    }

    private fun outerJson(context: String, sealed: String, signature: String?): String =
        ClientWireCrypto.json { writer ->
            writer.beginObject()
                .name("type").value(TYPE)
                .name("version").value(2)
                .name("suite").value(SUITE)
                .name("context").jsonValue(context)
                .name("sealed").jsonValue(sealed)
            writer.name("signature")
            if (signature == null) writer.nullValue() else writer.value(signature)
            writer.endObject()
        }

    private fun exactUtf8(value: String): ByteArray {
        require(value.length <= BODY_MAX_BYTES) { "Monitor body exceeds its protocol limit" }
        var index = 0
        while (index < value.length) {
            val unit = value[index]
            if (Character.isHighSurrogate(unit)) {
                require(index + 1 < value.length && Character.isLowSurrogate(value[index + 1])) {
                    "Monitor body contains malformed UTF-16"
                }
                index += 2
            } else {
                require(!Character.isLowSurrogate(unit)) { "Monitor body contains malformed UTF-16" }
                index++
            }
        }
        return value.toByteArray(StandardCharsets.UTF_8)
    }

    private fun canonicalBase64(source: JsonObject, field: String): ByteArray {
        val encoded = string(source, field)
        val decoded = try { Base64.getDecoder().decode(encoded) }
        catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid Monitor proof base64: $field", error)
        }
        require(Base64.getEncoder().encodeToString(decoded) == encoded) {
            "Monitor proof base64 is noncanonical: $field"
        }
        return decoded
    }

    private fun peerFingerprint(public: ClientWireCrypto.PublicIdentity): String =
        "sha256:" + sha256Hex(
            "cicada/nodekeys/peer-key-fingerprint/v1\u0000".toByteArray(StandardCharsets.UTF_8) +
                public.kemPublic + public.signingPublic,
        )

    private fun canonicalId(value: String): Boolean = value.isNotEmpty() &&
        value.toByteArray(StandardCharsets.UTF_8).size <= 256 && value.all { char ->
            char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' ||
                char == '.' || char == '_' || char == ':' || char == '-'
        }

    private fun isDigest(value: String): Boolean = value.matches(Regex("^[0-9a-f]{64}$"))

    private fun keys(value: JsonObject): List<String> = value.entrySet().map { it.key }

    private fun hasExactKeys(value: JsonObject, expected: List<String>): Boolean =
        keys(value).size == expected.size && keys(value).toSet() == expected.toSet()

    private fun string(source: JsonObject, field: String): String = source.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: throw IllegalArgumentException("Missing or invalid Monitor field: $field")

    private fun positive(source: JsonObject, field: String): Long {
        val token = source.get(field)?.takeIf {
            it.isJsonPrimitive && it.asJsonPrimitive.isNumber
        }?.asString
        require(token != null && token.matches(Regex("^[1-9][0-9]*$"))) {
            "Invalid Monitor positive integer: $field"
        }
        return token.toLongOrNull()?.takeIf { it > 0 }
            ?: throw IllegalArgumentException("Invalid Monitor positive integer: $field")
    }

    private fun sha256Hex(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
