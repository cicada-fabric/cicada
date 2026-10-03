package ai.cicada.client.hub

/** A fixed local diagnostic for retained Owner-grant verification failures. */
internal enum class LinkOwnerGrantVerificationReason {
    ACCEPTED_AT_IN_FUTURE,
    VERIFIED_AT_IN_FUTURE,
    OWNER_PIN_MISMATCH,
    OWNER_GRANT_TIME_INVALID,
    OWNER_GRANT_SIGNATURE_INVALID,
    OWNER_GRANT_SHAPE_INVALID,
    OWNER_GRANT_PROVENANCE_MISMATCH,
    OWNER_GRANT_TUPLE_MISMATCH,
    OWNER_GRANT_CANONICAL_ENCODING_INVALID,
    UNKNOWN,
}

/**
 * Safe cause for a HubSessionException. The original verifier exception and its message are
 * deliberately not retained; only an exact allowlisted message can select a fixed enum reason.
 */
internal class LinkOwnerGrantVerificationFailure(
    val reason: LinkOwnerGrantVerificationReason,
) : RuntimeException("LOCAL_LINK_OWNER_GRANT_VERIFICATION:${reason.name}") {
    companion object {
        private val reasonByExactMessage = mapOf(
            "Retained Link acceptance time is in the future" to
                LinkOwnerGrantVerificationReason.ACCEPTED_AT_IN_FUTURE,
            "Retained Link verification time is in the future" to
                LinkOwnerGrantVerificationReason.VERIFIED_AT_IN_FUTURE,

            "Invalid independent Owner full-key pin" to
                LinkOwnerGrantVerificationReason.OWNER_PIN_MISMATCH,
            "Hub-retained Owner key does not match the independent full-key pin" to
                LinkOwnerGrantVerificationReason.OWNER_PIN_MISMATCH,
            "Retained Link status key ID disagrees with Owner evidence" to
                LinkOwnerGrantVerificationReason.OWNER_PIN_MISMATCH,

            "Communication Link is expired" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_TIME_INVALID,
            "OwnerLinkKeyGrant is outside its validity period or exceeds Link expiry" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_TIME_INVALID,

            "Invalid OwnerLinkKeyGrant ML-DSA-65 signature size" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SIGNATURE_INVALID,
            "OwnerLinkKeyGrant ML-DSA signature failed" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SIGNATURE_INVALID,

            "Invalid retained Link Owner side" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Invalid retained Link key-grant status fields" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Invalid retained Link current status" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Invalid retained Link Owner evidence fields" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Missing retained Owner public identity" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Invalid OwnerLinkKeyGrant size" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Communication Link contract is outside the size limit" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Communication Link key manifest has missing, extra, or reordered fields" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Communication Link contract has missing, extra, or reordered fields" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Retained Link Owner evidence fields has missing, extra, or reordered fields" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "OwnerLinkKeyGrant has missing, extra, or reordered fields" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Empty OwnerLinkKeyGrant JSON" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "Invalid OwnerLinkKeyGrant JSON" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,
            "OwnerLinkKeyGrant must be a JSON object" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_SHAPE_INVALID,

            "Retained Link status does not match the selected Link side" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_PROVENANCE_MISMATCH,
            "Communication Link key manifest scope or version mismatch" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_PROVENANCE_MISMATCH,
            "Communication Link contract does not match fresh Link/Group/Endpoint scope" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_PROVENANCE_MISMATCH,
            "Communication Link contract digest mismatch" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_PROVENANCE_MISMATCH,
            "Communication Link key manifest digest mismatch" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_PROVENANCE_MISMATCH,
            "Retained Link status manifest digest mismatch" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_PROVENANCE_MISMATCH,

            "Invalid current OwnerLinkKeyGrant authority" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_TUPLE_MISMATCH,
            "Invalid OwnerLinkKeyGrant authority" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_TUPLE_MISMATCH,
            "OwnerLinkKeyGrant does not match the exact current Link side and manifest" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_TUPLE_MISMATCH,
            "Retained Link evidence is stale or not current" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_TUPLE_MISMATCH,

            "Invalid canonical UTC RFC3339Nano time" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Invalid contract_canonical base64" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Noncanonical contract_canonical base64" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Invalid retained OwnerLinkKeyGrant base64" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Noncanonical retained OwnerLinkKeyGrant base64" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Invalid OwnerLinkKeyGrant signature base64" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Noncanonical OwnerLinkKeyGrant signature base64" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "OwnerLinkKeyGrant JSON is not canonical" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
            "Communication Link key manifest JSON is not canonical" to
                LinkOwnerGrantVerificationReason.OWNER_GRANT_CANONICAL_ENCODING_INVALID,
        )

        fun from(error: Exception): LinkOwnerGrantVerificationFailure =
            LinkOwnerGrantVerificationFailure(
                reasonByExactMessage[error.message]
                    ?: LinkOwnerGrantVerificationReason.UNKNOWN,
            )
    }
}
