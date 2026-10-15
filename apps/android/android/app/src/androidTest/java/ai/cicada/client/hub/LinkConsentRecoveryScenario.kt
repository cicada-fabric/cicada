package ai.cicada.client.hub

import com.google.gson.JsonObject

/** Strict selector input for the current Link recovery fixture. */
internal data class LinkConsentRecoveryScenario(
    val runId: String,
    val expectedOperation: String,
    val faultMode: String,
) {
    fun requireSelector(operation: String, mode: String? = null) {
        require(expectedOperation == operation) { "Recovery scenario operation differs from this selector" }
        if (mode != null) require(faultMode == mode) { "Recovery scenario mode differs from this selector" }
    }

    companion object {
        const val SCHEMA = "cicada.client-v164-link-consent-recovery-scenario.v2"
        val OPERATIONS = setOf("link.key_grant", "link.review_policy_grant")
        val MODES = setOf("response-loss", "processing", "uncertain", "legacy")
        private val RUN_ID = Regex("v164-[A-Za-z0-9_-]{1,72}")

        fun parse(value: JsonObject, expectedRunId: String): LinkConsentRecoveryScenario {
            require(value.keySet() == setOf("schema", "run_id", "expected_operation", "fault_mode")) {
                "Link recovery scenario has missing or unexpected fields"
            }
            val schema = string(value, "schema")
            val runId = string(value, "run_id")
            val operation = string(value, "expected_operation")
            val mode = string(value, "fault_mode")
            require(schema == SCHEMA && RUN_ID.matches(runId) && runId == expectedRunId) {
                "Link recovery scenario is outside this bounded run"
            }
            require(operation in OPERATIONS && mode in MODES) {
                "Link recovery scenario operation or fault mode is invalid"
            }
            return LinkConsentRecoveryScenario(runId, operation, mode)
        }

        private fun string(value: JsonObject, field: String): String = value.get(field)
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            ?.takeIf { text -> text.isNotBlank() && text.length <= 128 && text == text.trim() &&
                text.none { Character.isISOControl(it) } }
            ?: error("Link recovery scenario string field is invalid")
    }
}
