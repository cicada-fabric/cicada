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

/** Pure verifier for the v1 Owner Link review-policy proof. No RPC or signing API. */
internal object OwnerLinkReviewPolicyV1Verifier {
    private const val DOMAIN = "cicada/communication-link/review-policy-owner-approval/v1\u0000"
    private const val MAX_PROOF_BYTES = 16 * 1024
    private const val SIGNATURE_BYTES = 3309
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val BASE_SECONDS = DateTimeFormatter
        .ofPattern("uuuu-MM-dd'T'HH:mm:ss", Locale.ROOT)
        .withZone(ZoneOffset.UTC)

    data class ExpectedAuthority(
        val ownerId: String,
        val linkId: String,
        val contractDigest: String,
        val policyDigest: String,
        val expectedLinkVersion: Long,
        val policyVersion: Long,
        val side: String,
    )

    data class VerifiedProof(
        val ownerId: String,
        val linkId: String,
        val contractDigest: String,
        val policyDigest: String,
        val expectedLinkVersion: Long,
        val policyVersion: Long,
        val side: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
    )

    /**
     * `trustedOwner` and `expected` must come from an independently trusted Owner key
     * and fresh authenticated Link/policy state. Candidate JSON cannot supply them.
     */
    fun verify(
        proofJson: ByteArray,
        trustedOwner: ClientWireCrypto.PublicIdentity,
        expected: ExpectedAuthority,
        now: Instant,
    ): VerifiedProof {
        require(proofJson.isNotEmpty() && proofJson.size <= MAX_PROOF_BYTES) {
            "Invalid Owner review-policy proof size"
        }
        trustedOwner.validate()
        validateExpected(expected)

        val proof = parseUtf8Object(proofJson, "Owner review-policy proof")
        require(proof.keySet().toList() == proofFields) {
            "Owner review-policy proof has a noncanonical field shape"
        }
        val version = integer(proof, "version")
        val ownerId = string(proof, "owner_id")
        val linkId = string(proof, "link_id")
        val contractDigest = string(proof, "contract_digest")
        val policyDigest = string(proof, "policy_digest")
        val linkVersion = positiveInteger(proof, "expected_link_version")
        val policyVersion = positiveInteger(proof, "policy_version")
        val side = string(proof, "side")
        val issuedAtText = string(proof, "issued_at")
        val expiresAtText = string(proof, "expires_at")
        val nonce = string(proof, "nonce")
        val signature = base64(proof, "signature")

        require(version == 1L && SHA256.matches(contractDigest) && SHA256.matches(policyDigest) &&
            SHA256.matches(nonce) && side in setOf("SOURCE", "TARGET") &&
            signature.size == SIGNATURE_BYTES) {
            "Invalid Owner review-policy proof claims"
        }
        require(ownerId == expected.ownerId && linkId == expected.linkId &&
            contractDigest == expected.contractDigest && policyDigest == expected.policyDigest &&
            linkVersion == expected.expectedLinkVersion && policyVersion == expected.policyVersion &&
            side == expected.side) {
            "Owner review-policy proof does not match current Link policy authority"
        }

        val issuedAt = canonicalUtc(issuedAtText)
        val expiresAt = canonicalUtc(expiresAtText)
        require(expiresAt > issuedAt && issuedAt <= now && now < expiresAt) {
            "Owner review-policy proof is outside its validity interval"
        }

        val canonicalProof = encodeProof(
            ownerId = ownerId,
            linkId = linkId,
            contractDigest = contractDigest,
            policyDigest = policyDigest,
            expectedLinkVersion = linkVersion,
            policyVersion = policyVersion,
            side = side,
            issuedAt = issuedAtText,
            expiresAt = expiresAtText,
            nonce = nonce,
            signature = proof.get("signature").asString,
        ).toByteArray(StandardCharsets.UTF_8)
        require(MessageDigest.isEqual(proofJson, canonicalProof)) {
            "Owner review-policy proof JSON is not canonical"
        }

        val signedBytes = DOMAIN.toByteArray(StandardCharsets.UTF_8) + encodeClaims(
            ownerId = ownerId,
            linkId = linkId,
            contractDigest = contractDigest,
            policyDigest = policyDigest,
            expectedLinkVersion = linkVersion,
            policyVersion = policyVersion,
            side = side,
            issuedAt = issuedAtText,
            expiresAt = expiresAtText,
            nonce = nonce,
        ).toByteArray(StandardCharsets.UTF_8)
        require(ClientWireCrypto.verify(trustedOwner, signedBytes, signature)) {
            "Owner review-policy ML-DSA signature is invalid"
        }

        return VerifiedProof(ownerId, linkId, contractDigest, policyDigest,
            linkVersion, policyVersion, side, issuedAt, expiresAt)
    }

    private val proofFields = listOf(
        "version", "owner_id", "link_id", "contract_digest", "policy_digest",
        "expected_link_version", "policy_version", "side", "issued_at", "expires_at",
        "nonce", "signature",
    )

    private fun validateExpected(expected: ExpectedAuthority) {
        require(listOf(expected.ownerId, expected.linkId).all(::canonicalToken) &&
            SHA256.matches(expected.contractDigest) && SHA256.matches(expected.policyDigest) &&
            expected.expectedLinkVersion > 0 && expected.policyVersion > 0 &&
            expected.side in setOf("SOURCE", "TARGET")) {
            "Invalid current Owner review-policy authority"
        }
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

    private fun parseUtf8Object(raw: ByteArray, label: String): JsonObject {
        val text = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(raw)).toString()
        val parsed = JsonParser.parseString(text)
        require(parsed.isJsonObject) { "Invalid $label JSON" }
        return parsed.asJsonObject
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

    private fun base64(value: JsonObject, name: String): ByteArray {
        val encoded = string(value, name)
        val decoded = Base64.getDecoder().decode(encoded)
        require(Base64.getEncoder().encodeToString(decoded) == encoded) { "Noncanonical $name" }
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

    /** Exactly eleven ordered claims; the carried signature is deliberately absent. */
    private fun encodeClaims(
        ownerId: String,
        linkId: String,
        contractDigest: String,
        policyDigest: String,
        expectedLinkVersion: Long,
        policyVersion: Long,
        side: String,
        issuedAt: String,
        expiresAt: String,
        nonce: String,
    ): String = ClientWireCrypto.json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("owner_id").value(ownerId)
            .name("link_id").value(linkId)
            .name("contract_digest").value(contractDigest)
            .name("policy_digest").value(policyDigest)
            .name("expected_link_version").value(expectedLinkVersion)
            .name("policy_version").value(policyVersion)
            .name("side").value(side)
            .name("issued_at").value(issuedAt)
            .name("expires_at").value(expiresAt)
            .name("nonce").value(nonce)
            .endObject()
    }

    private fun encodeProof(
        ownerId: String,
        linkId: String,
        contractDigest: String,
        policyDigest: String,
        expectedLinkVersion: Long,
        policyVersion: Long,
        side: String,
        issuedAt: String,
        expiresAt: String,
        nonce: String,
        signature: String,
    ): String = ClientWireCrypto.json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("owner_id").value(ownerId)
            .name("link_id").value(linkId)
            .name("contract_digest").value(contractDigest)
            .name("policy_digest").value(policyDigest)
            .name("expected_link_version").value(expectedLinkVersion)
            .name("policy_version").value(policyVersion)
            .name("side").value(side)
            .name("issued_at").value(issuedAt)
            .name("expires_at").value(expiresAt)
            .name("nonce").value(nonce)
            .name("signature").value(signature)
            .endObject()
    }
}
