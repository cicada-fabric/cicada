package ai.cicada.client.hub

import com.google.gson.JsonObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Public-key and approval scope checks for the v1.6.1 Node confirmation DTO. */
internal object NodeControlKeyBindingVerifier {
    private val fingerprintDomain =
        "cicada/node-control/key-fingerprint/v1\u0000".toByteArray(StandardCharsets.UTF_8)

    fun verify(binding: JsonObject, hubId: String, ownerId: String, deviceId: String,
               ownerKeyId: String) {
        require(text(binding, "hub_id") == hubId)
        require(text(binding, "owner_id") == ownerId)
        require(text(binding, "client_device_id") == deviceId)
        require(text(binding, "approved_owner_device_id") == deviceId)
        require(text(binding, "owner_key_id") == ownerKeyId)
        require(text(binding, "approved_owner_key_id") == ownerKeyId)
        require(text(binding, "state") == "ACTIVE")
        for (side in listOf("node", "hub")) {
            val publicJson = binding.get("${side}_public_identity")
            require(publicJson != null && publicJson.isJsonObject)
            require(publicJson.asJsonObject.keySet() == setOf("id", "kem_public", "signing_public"))
            val identity = ClientWireCrypto.PublicIdentity.parse(publicJson.asJsonObject)
            require(text(binding, "${side}_key_id") == identity.id)
            val claimed = text(binding, "${side}_key_fingerprint")
            require(claimed.matches(Regex("[0-9a-f]{64}")))
            require(MessageDigest.isEqual(claimed.toByteArray(StandardCharsets.US_ASCII),
                fingerprint(identity).toByteArray(StandardCharsets.US_ASCII)))
        }
    }

    /** Exact pinned nodewire.IdentityFingerprint input; independent of Client device fingerprints. */
    internal fun fingerprint(identity: ClientWireCrypto.PublicIdentity): String {
        val hash = MessageDigest.getInstance("SHA-256")
        hash.update(fingerprintDomain)
        hash.update(identity.kemPublic)
        hash.update(0.toByte())
        hash.update(identity.signingPublic)
        return hash.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun text(value: JsonObject, key: String): String {
        val item = value.get(key)
        require(item != null && item.isJsonPrimitive && item.asJsonPrimitive.isString)
        return item.asString.also { require(it.isNotBlank() && it.length <= 256) }
    }
}
