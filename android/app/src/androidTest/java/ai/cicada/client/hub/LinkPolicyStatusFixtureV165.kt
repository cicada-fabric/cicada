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
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Closed, public-only fixture parser for the v1.6.5 Link policy status instrumentation lane. */
internal object LinkPolicyStatusFixtureV165 {
    const val CONTRACT = "client-hub-v1.6.5"
    const val CATALOG = "a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9"
    const val SCHEMA = "cicada.client-v165-link-policy-status-fixture.v1"

    private const val MAX_BYTES = 64 * 1024
    private const val MAX_DEPTH = 16
    private const val MAX_NODES = 4096
    private const val MAX_ID_LENGTH = 256
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private const val KEM_PUBLIC_BYTES = 1184
    private const val SIGNING_PUBLIC_BYTES = 1952

    private val requiredFields = setOf(
        "schema", "run_id", "case_id", "fixture_lane", "scenario", "source_revision",
        "source_fingerprint", "hub_image_id", "contract_revision", "catalog_sha256", "hub_id",
        "owner_id", "device_id", "profile_id", "profile_generation", "session_epoch",
        "control_public_identity", "control_key_version", "my_side", "expected_status",
    )
    private val optionalFields = setOf("foreign_link_id", "foreign_owner_id", "recovery_result")
    private val scenarios = listOf("restart", "owner-refusal", "version-bypass", "response-loss")
    private val runIdPattern = Regex("v165-link-policy-status-[A-Za-z0-9_-]{1,64}")
    private val revisionPattern = Regex("[0-9a-f]{40}")
    private val sha256Pattern = Regex("[0-9a-f]{64}")
    private val imagePattern = Regex("sha256:[0-9a-f]{64}")
    private val profileUuidPattern = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    internal data class Fixture(
        val root: JsonObject,
        val runId: String,
        val caseId: Int,
        val lane: String,
        val scenario: String,
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val profileId: String,
        val profileGeneration: Long,
        val sessionEpoch: Long,
        val linkId: String,
        val linkVersion: Long,
        val expectedStatus: JsonObject,
        val mySide: String,
        val controlPublicIdentity: JsonObject,
        val controlKeyVersion: Long,
        val foreignLinkId: String?,
        val foreignOwnerId: String?,
        val recoveryResult: String?,
    )

    /**
     * Parse a fixture supplied by the independently pinned instrumentation call.
     * Source and image values are structurally checked here; pin comparison belongs to that call.
     */
    fun parse(raw: String, expectedRunId: String, expectedLane: String, expectedScenario: String): Fixture {
        require(raw.toByteArray(StandardCharsets.UTF_8).size in 1..MAX_BYTES) { "Fixture size is invalid" }
        require(runIdPattern.matches(expectedRunId)) { "Expected run ID is invalid" }
        require(expectedLane in setOf("KEY", "NONE")) { "Expected fixture lane is invalid" }
        require(expectedScenario in scenarios) { "Expected fixture scenario is invalid" }

        val root = parseUniqueObject(raw)
        requireExactFields(root, requiredFields, requiredFields + optionalFields, "Fixture fields are invalid")
        require(string(root, "schema") == SCHEMA) { "Fixture schema is unsupported" }

        val runId = string(root, "run_id")
        require(runIdPattern.matches(runId) && runId == expectedRunId) { "Fixture run ID does not match" }
        val caseId = integer(root, "case_id", 0L, 7L).toInt()
        val lane = string(root, "fixture_lane")
        val scenario = string(root, "scenario")
        val expectedLaneForCase = if (caseId % 2 == 0) "KEY" else "NONE"
        val expectedScenarioForCase = scenarios[caseId / 2]
        require(lane == expectedLaneForCase && lane == expectedLane) { "Fixture lane does not match its case" }
        require(scenario == expectedScenarioForCase && scenario == expectedScenario) {
            "Fixture scenario does not match its case"
        }

        require(revisionPattern.matches(string(root, "source_revision"))) { "Source revision is invalid" }
        require(sha256Pattern.matches(string(root, "source_fingerprint"))) { "Source fingerprint is invalid" }
        require(imagePattern.matches(string(root, "hub_image_id"))) { "Hub image ID is invalid" }
        require(string(root, "contract_revision") == CONTRACT) { "Contract revision does not match" }
        require(string(root, "catalog_sha256") == CATALOG) { "Catalog digest does not match" }

        val hubId = identifier(root, "hub_id")
        val ownerId = identifier(root, "owner_id")
        val deviceId = identifier(root, "device_id")
        val profileId = string(root, "profile_id")
        require(profileId == "legacy" || profileUuidPattern.matches(profileId)) { "Profile ID is invalid" }
        val profileGeneration = integer(root, "profile_generation", 1L, MAX_SAFE_INTEGER)
        val sessionEpoch = integer(root, "session_epoch", 1L, MAX_SAFE_INTEGER)
        val controlKeyVersion = integer(root, "control_key_version", 1L, MAX_SAFE_INTEGER)
        val mySide = string(root, "my_side")
        require(mySide == "SOURCE" || mySide == "TARGET") { "Owner side is invalid" }

        val identity = objectValue(root, "control_public_identity")
        validatePublicIdentity(identity)

        val expectedStatus = objectValue(root, "expected_status").deepCopy()
        val validatedStatus = LinkReviewPolicyStatusValidation.validateStatus(
            expectedStatus, string(expectedStatus, "link_id"),
            integer(expectedStatus, "link_version", 1L, MAX_SAFE_INTEGER),
        )
        require(validatedStatus.linkId == identifier(expectedStatus, "link_id") &&
            validatedStatus.linkVersion in 1L..MAX_SAFE_INTEGER) { "Expected status scope is invalid" }
        val linkId = validatedStatus.linkId
        val linkVersion = validatedStatus.linkVersion

        val foreignLinkId = optionalIdentifier(root, "foreign_link_id")
        val foreignOwnerId = optionalIdentifier(root, "foreign_owner_id")
        if (scenario == "owner-refusal") {
            require(foreignLinkId != null && foreignOwnerId != null) { "Owner refusal fixture lacks foreign scope" }
            require(foreignLinkId != linkId && foreignOwnerId != ownerId) { "Foreign scope aliases selected scope" }
        } else {
            require(foreignLinkId == null && foreignOwnerId == null) { "Foreign scope is only valid for owner refusal" }
        }

        val recoveryResult = if (root.has("recovery_result")) string(root, "recovery_result") else null
        if (scenario == "response-loss") {
            require(recoveryResult in setOf("COMPLETED", "OUTCOME_UNCERTAIN")) {
                "Response-loss fixture lacks a supported recovery result"
            }
        } else {
            require(recoveryResult == null) { "Recovery result is only valid for response loss" }
        }

        return Fixture(
            root = root.deepCopy(),
            runId = runId,
            caseId = caseId,
            lane = lane,
            scenario = scenario,
            hubId = hubId,
            ownerId = ownerId,
            deviceId = deviceId,
            profileId = profileId,
            profileGeneration = profileGeneration,
            sessionEpoch = sessionEpoch,
            linkId = linkId,
            linkVersion = linkVersion,
            expectedStatus = expectedStatus,
            mySide = mySide,
            controlPublicIdentity = identity.deepCopy(),
            controlKeyVersion = controlKeyVersion,
            foreignLinkId = foreignLinkId,
            foreignOwnerId = foreignOwnerId,
            recoveryResult = recoveryResult,
        )
    }

    /** Validate and compare the full sanitized status, including every reviewer scope field. */
    fun assertStatus(actual: JsonObject, fixture: Fixture) {
        val expected = fixture.expectedStatus
        val expectedDto = LinkReviewPolicyStatusValidation.validateStatus(
            expected, fixture.linkId, fixture.linkVersion,
        )
        val actualDto = LinkReviewPolicyStatusValidation.validateStatus(
            actual, fixture.linkId, fixture.linkVersion,
        )
        require(actualDto == expectedDto) { "Status metadata differs from the pinned fixture" }
        require(actual.getAsJsonObject("policy") == expected.getAsJsonObject("policy")) {
            "Status policy differs from the pinned reviewer scopes"
        }
        require(actual == expected) { "Status DTO differs from the pinned fixture" }
    }

    private fun validatePublicIdentity(value: JsonObject) {
        requireExactFields(value, setOf("id", "kem_public", "signing_public"),
            setOf("id", "kem_public", "signing_public"), "Control public identity fields are invalid")
        val id = string(value, "id")
        val kem = decodeCanonicalBase64(string(value, "kem_public"), KEM_PUBLIC_BYTES)
        val signing = decodeCanonicalBase64(string(value, "signing_public"), SIGNING_PUBLIC_BYTES)
        val expectedId = "pq1-" + sha256(kem + signing).take(32)
        require(id == expectedId) { "Control public identity ID does not match its public bytes" }
    }

    private fun decodeCanonicalBase64(value: String, expectedBytes: Int): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Public identity Base64 is invalid", error)
        }
        require(decoded.size == expectedBytes && Base64.getEncoder().encodeToString(decoded) == value) {
            "Public identity Base64 is not padded canonical data of the expected size"
        }
        return decoded
    }

    private fun parseUniqueObject(raw: String): JsonObject {
        try {
            val reader = JsonReader(StringReader(raw))
            reader.strictness = Strictness.STRICT
            return reader.use {
                val nodes = intArrayOf(0)
                val parsed = readValue(it, 0, nodes)
                require(parsed.isJsonObject && it.peek() == JsonToken.END_DOCUMENT) { "Fixture JSON root is invalid" }
                parsed.asJsonObject
            }
        } catch (error: IllegalArgumentException) {
            throw error
        } catch (error: Exception) {
            throw IllegalArgumentException("Fixture JSON is malformed", error)
        }
    }

    private fun readValue(reader: JsonReader, depth: Int, nodes: IntArray): JsonElement {
        require(depth <= MAX_DEPTH) { "Fixture JSON nesting is too deep" }
        nodes[0] += 1
        require(nodes[0] <= MAX_NODES) { "Fixture JSON has too many values" }
        return when (reader.peek()) {
            JsonToken.BEGIN_OBJECT -> {
                reader.beginObject()
                val result = JsonObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    require(!result.has(name)) { "Fixture JSON has duplicate fields" }
                    result.add(name, readValue(reader, depth + 1, nodes))
                }
                reader.endObject()
                result
            }
            JsonToken.BEGIN_ARRAY -> {
                reader.beginArray()
                val result = JsonArray()
                while (reader.hasNext()) result.add(readValue(reader, depth + 1, nodes))
                reader.endArray()
                result
            }
            JsonToken.STRING -> JsonPrimitive(reader.nextString())
            JsonToken.NUMBER -> {
                val token = reader.nextString()
                require(token.matches(Regex("0|[1-9][0-9]*"))) { "Fixture JSON number is not canonical" }
                val number = token.toLongOrNull() ?: throw IllegalArgumentException("Fixture number overflows")
                JsonPrimitive(number)
            }
            JsonToken.BOOLEAN -> JsonPrimitive(reader.nextBoolean())
            JsonToken.NULL -> {
                reader.nextNull()
                JsonNull.INSTANCE
            }
            else -> throw IllegalArgumentException("Fixture JSON contains an unsupported token")
        }
    }

    private fun requireExactFields(value: JsonObject, required: Set<String>, allowed: Set<String>, message: String) {
        require(value.keySet().containsAll(required) && value.keySet().all { it in allowed }) { message }
    }

    private fun objectValue(value: JsonObject, key: String): JsonObject =
        value.get(key)?.takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Fixture object field $key is invalid")

    private fun string(value: JsonObject, key: String): String =
        value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            ?: throw IllegalArgumentException("Fixture string field $key is invalid")

    private fun identifier(value: JsonObject, key: String): String = string(value, key).also {
        require(it.isNotBlank() && it.length <= MAX_ID_LENGTH && it == it.trim() && it.none { char -> char.isISOControl() }) {
            "Fixture identifier $key is invalid"
        }
    }

    private fun optionalIdentifier(value: JsonObject, key: String): String? = if (value.has(key)) identifier(value, key) else null

    private fun integer(value: JsonObject, key: String, minimum: Long, maximum: Long): Long {
        val primitive = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: throw IllegalArgumentException("Fixture integer field $key is invalid")
        val token = primitive.asString
        require(token.matches(Regex("0|[1-9][0-9]*"))) { "Fixture integer field $key is noncanonical" }
        val number = token.toLongOrNull() ?: throw IllegalArgumentException("Fixture integer field $key overflows")
        require(number in minimum..maximum && number <= MAX_SAFE_INTEGER) { "Fixture integer field $key is out of range" }
        return number
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
