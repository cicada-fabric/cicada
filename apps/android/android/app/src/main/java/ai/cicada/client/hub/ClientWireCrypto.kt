package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.stream.JsonWriter
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.SecretWithEncapsulation
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import org.bouncycastle.util.encoders.Base64
import java.io.IOException
import java.io.StringWriter
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Arrays
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Independent Kotlin implementation of the documented Client-Control v1 bytes. */
object ClientWireCrypto {
    private const val ALGORITHM = "ML-KEM-768+ML-DSA-65/AES-256-GCM"
    private val AAD_DOMAIN = bytes("cicada/client-control/packet/v1\u0000")
    private val KEY_DOMAIN = bytes("cicada/e2ee/v1/key")
    private val GRANT_DOMAIN = bytes("cicada/client/owner-device-grant/v1\u0000")
    private val FINGERPRINT_DOMAIN = bytes("cicada/client/device-public-key/v1\u0000")
    private val RANDOM = SecureRandom()

    class PublicIdentity(id: String, kemPublic: ByteArray, signingPublic: ByteArray) {
        @JvmField val id: String = id
        @JvmField val kemPublic: ByteArray = kemPublic.clone()
        @JvmField val signingPublic: ByteArray = signingPublic.clone()

        init {
            validate()
        }

        companion object {
            @JvmStatic
            fun parse(value: JsonObject): PublicIdentity = PublicIdentity(
                string(value, "id"),
                decode(string(value, "kem_public")),
                decode(string(value, "signing_public")),
            )
        }

        fun validate() {
            if (kemPublic.size != 1184 || signingPublic.size != 1952 ||
                id != "pq1-" + hex(Arrays.copyOf(sha256(join(kemPublic, signingPublic)), 16))
            ) {
                throw IllegalArgumentException("Invalid post-quantum public identity")
            }
            MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, kemPublic)
            MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, signingPublic)
        }

        fun toJson(): String = json { writer -> publicFields(writer, this) }

        fun fingerprint(): String = hex(sha256(join(FINGERPRINT_DOMAIN, bytes(toJson()))))

        fun sameAs(other: PublicIdentity?): Boolean = other != null && id == other.id &&
            MessageDigest.isEqual(kemPublic, other.kemPublic) &&
            MessageDigest.isEqual(signingPublic, other.signingPublic)
    }

    class Identity private constructor(
        private val kemPrivate: MLKEMPrivateKeyParameters,
        private val signingPrivate: MLDSAPrivateKeyParameters,
    ) : AutoCloseable {
        @JvmField val publicIdentity: PublicIdentity = PublicIdentity(
            "pq1-" + hex(
                Arrays.copyOf(
                    sha256(join(kemPrivate.publicKey, signingPrivate.publicKey)),
                    16,
                ),
            ),
            kemPrivate.publicKey,
            signingPrivate.publicKey,
        )

        companion object {
            @JvmStatic
            fun generate(): Identity {
                var kemPrivate: MLKEMPrivateKeyParameters? = null
                var signingPrivate: MLDSAPrivateKeyParameters? = null
                try {
                    val kem = MLKEMKeyPairGenerator()
                    kem.init(MLKEMKeyGenerationParameters(RANDOM, MLKEMParameters.ml_kem_768))
                    val kemPair: AsymmetricCipherKeyPair = kem.generateKeyPair()
                    kemPrivate = kemPair.private as MLKEMPrivateKeyParameters

                    val signing = MLDSAKeyPairGenerator()
                    signing.init(MLDSAKeyGenerationParameters(RANDOM, MLDSAParameters.ml_dsa_65))
                    val signingPair: AsymmetricCipherKeyPair = signing.generateKeyPair()
                    signingPrivate = signingPair.private as MLDSAPrivateKeyParameters

                    val identity = Identity(requireNotNull(kemPrivate), requireNotNull(signingPrivate))
                    kemPrivate = null
                    signingPrivate = null
                    return identity
                } finally {
                    kemPrivate?.destroy()
                    signingPrivate?.destroy()
                }
            }

            @JvmStatic
            fun fromPrivateJson(serialized: String): Identity {
                val value = JsonParser.parseString(serialized).asJsonObject
                if (integer(value, "version") != 1) {
                    throw IllegalArgumentException("Unknown key version")
                }
                var kemPrivate: MLKEMPrivateKeyParameters? = null
                var signingPrivate: MLDSAPrivateKeyParameters? = null
                try {
                    val kemEncoded = decode(string(value, "kem_private"))
                    try {
                        kemPrivate = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, kemEncoded)
                    } finally {
                        Arrays.fill(kemEncoded, 0.toByte())
                    }

                    val signingEncoded = decode(string(value, "signing_private"))
                    try {
                        signingPrivate = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, signingEncoded)
                    } finally {
                        Arrays.fill(signingEncoded, 0.toByte())
                    }

                    val identity = Identity(requireNotNull(kemPrivate), requireNotNull(signingPrivate))
                    kemPrivate = null
                    signingPrivate = null
                    return identity
                } finally {
                    kemPrivate?.destroy()
                    signingPrivate?.destroy()
                }
            }
        }

        /** Preserves the Java API while Kotlin callers can use the publicIdentity property. */
        fun publicIdentity(): PublicIdentity = publicIdentity

        /** Caller must wrap this result with Android Keystore before writing it. */
        fun privateJson(): String {
            val kemEncoded = kemPrivate.encoded
            var signingEncoded: ByteArray? = null
            try {
                signingEncoded = signingPrivate.encoded
                return json { writer ->
                    writer.beginObject()
                        .name("version").value(1)
                        .name("kem_private").value(encode(kemEncoded))
                        .name("signing_private").value(encode(requireNotNull(signingEncoded)))
                        .endObject()
                }
            } finally {
                Arrays.fill(kemEncoded, 0.toByte())
                signingEncoded?.let { Arrays.fill(it, 0.toByte()) }
            }
        }

        fun sign(message: ByteArray): ByteArray {
            val signer = MLDSASigner()
            signer.init(true, signingPrivate)
            signer.update(message, 0, message.size)
            return try {
                signer.generateSignature()
            } catch (error: Exception) {
                throw IllegalStateException("ML-DSA signing failed", error)
            }
        }

        internal fun decapsulate(ciphertext: ByteArray): ByteArray {
            if (ciphertext.size != 1088) {
                throw IllegalArgumentException("Invalid ML-KEM ciphertext")
            }
            return MLKEMExtractor(kemPrivate).extractSecret(ciphertext)
        }

        override fun close() {
            try {
                kemPrivate.destroy()
            } finally {
                signingPrivate.destroy()
            }
        }
    }

    class HubPin(hubId: String, control: PublicIdentity, keyVersion: Long) {
        @JvmField val hubId: String = hubId
        @JvmField val control: PublicIdentity = control
        @JvmField val keyVersion: Long = keyVersion

        init {
            if (hubId.isEmpty() || keyVersion != 1L) {
                throw IllegalArgumentException("Unsupported Hub identity")
            }
        }

        companion object {
            @JvmStatic
            fun parse(text: String): HubPin {
                val value = JsonParser.parseString(text).asJsonObject
                if (string(value, "contract") != "android-hub-v1" ||
                    string(value, "suite") != "ML-KEM-768+ML-DSA-65+AES-256-GCM"
                ) {
                    throw IllegalArgumentException("Unsupported Hub identity contract")
                }
                return HubPin(
                    string(value, "hub_id"),
                    PublicIdentity.parse(value.getAsJsonObject("control_public_identity")),
                    longValue(value, "control_key_version"),
                )
            }
        }

        fun sameAs(other: HubPin?): Boolean = other != null && hubId == other.hubId &&
            keyVersion == other.keyVersion && control.sameAs(other.control)
    }

    class Route {
        @JvmField var version: Int = 1
        @JvmField var direction: String = ""
        @JvmField var hubId: String = ""
        @JvmField var ownerId: String = ""
        @JvmField var deviceId: String = ""
        @JvmField var sessionEpoch: Long = 0
        @JvmField var sequence: Long = 0
        @JvmField var operationId: String = ""
        @JvmField var operation: String = ""
        @JvmField var senderKeyId: String = ""
        @JvmField var senderKeyVersion: Long = 0
        @JvmField var receiverKeyId: String = ""
        @JvmField var receiverKeyVersion: Long = 0

        companion object {
            @JvmStatic
            fun parse(value: JsonObject): Route = Route().apply {
                version = integer(value, "version")
                direction = string(value, "direction")
                hubId = string(value, "hub_id")
                ownerId = string(value, "owner_id")
                deviceId = string(value, "device_id")
                sessionEpoch = longValue(value, "session_epoch")
                sequence = longValue(value, "sequence")
                operationId = string(value, "operation_id")
                operation = string(value, "operation")
                senderKeyId = string(value, "sender_key_id")
                senderKeyVersion = longValue(value, "sender_key_version")
                receiverKeyId = string(value, "receiver_key_id")
                receiverKeyVersion = longValue(value, "receiver_key_version")
            }
        }

        fun toJson(): String = json { writer ->
            writer.beginObject()
                .name("version").value(version)
                .name("direction").value(direction)
                .name("hub_id").value(hubId)
                .name("owner_id").value(ownerId)
                .name("device_id").value(deviceId)
                .name("session_epoch").value(sessionEpoch)
                .name("sequence").value(sequence)
                .name("operation_id").value(operationId)
                .name("operation").value(operation)
                .name("sender_key_id").value(senderKeyId)
                .name("sender_key_version").value(senderKeyVersion)
                .name("receiver_key_id").value(receiverKeyId)
                .name("receiver_key_version").value(receiverKeyVersion)
                .endObject()
        }
    }

    class OpenedResponse internal constructor(route: Route, body: JsonObject) {
        @JvmField val route: Route = route
        @JvmField val body: JsonObject = body
    }

    /** The grant is supplied by an independently trusted owner, never signed by this device. */
    @JvmStatic
    fun verifyOwnerGrant(
        canonicalGrant: String,
        trustedOwner: PublicIdentity,
        ownerId: String,
        deviceId: String,
        device: PublicIdentity,
        hubId: String,
    ) {
        val value = JsonParser.parseString(canonicalGrant).asJsonObject
        val claims = grantJson(value, false)
        val rebuilt = grantJson(value, true)
        if (rebuilt != canonicalGrant || integer(value, "version") != 1 ||
            ownerId != string(value, "owner_id") ||
            trustedOwner.id != string(value, "owner_key_id") ||
            deviceId != string(value, "device_id") ||
            device.id != string(value, "device_key_id") ||
            device.fingerprint() != string(value, "device_key_fingerprint") ||
            hubId != string(value, "hub_id") ||
            string(value, "purpose") != "CLIENT_CONTROL" ||
            !string(value, "nonce").matches(Regex("[0-9a-f]{64}"))
        ) {
            throw IllegalArgumentException("Owner grant does not match this device and Hub")
        }
        val issued = Instant.parse(string(value, "issued_at"))
        val expires = Instant.parse(string(value, "expires_at"))
        val now = Instant.now()
        if (issued.isAfter(now) || !expires.isAfter(now) || !expires.isAfter(issued)) {
            throw IllegalArgumentException("Owner grant is outside its validity window")
        }
        if (!verify(trustedOwner, join(GRANT_DOMAIN, bytes(claims)), decode(string(value, "signature")))) {
            throw IllegalArgumentException("Owner grant signature is invalid")
        }
    }

    @JvmStatic
    fun sealRequest(
        device: Identity,
        hub: PublicIdentity,
        route: Route,
        plaintextJson: String,
    ): String {
        if (route.version != 1 || route.direction != "REQUEST" || route.sequence <= 0 ||
            device.publicIdentity.id != route.senderKeyId || hub.id != route.receiverKeyId
        ) {
            throw IllegalArgumentException("Invalid Client request route")
        }
        val body = bytes(plaintextJson)
        if (body.isEmpty() || body.size > 64 * 1024) {
            throw IllegalArgumentException("Client request body is too large")
        }
        val routeJson = route.toJson()
        val aad = join(AAD_DOMAIN, bytes(routeJson))
        val encapsulated: SecretWithEncapsulation = MLKEMGenerator(RANDOM).generateEncapsulated(
            MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, hub.kemPublic),
        )
        val secret = encapsulated.secret
        val kemCiphertext = encapsulated.encapsulation
        val nonce = ByteArray(12)
        RANDOM.nextBytes(nonce)
        try {
            val key = deriveKey(secret, route.sequence, aad)
            val header = envelopeHeader(route.sequence, kemCiphertext, nonce, device.publicIdentity)
            val ciphertext = aesGcm(true, key, nonce, join(aad, bytes(header)), body)
            val unsigned = envelope(route.sequence, kemCiphertext, nonce, ciphertext, device.publicIdentity, null)
            val signature = device.sign(bytes(unsigned))
            val encoded = envelope(
                route.sequence,
                kemCiphertext,
                nonce,
                ciphertext,
                device.publicIdentity,
                signature,
            )
            val packet = json { writer ->
                writer.beginObject()
                    .name("route").jsonValue(routeJson)
                    .name("envelope").value(encode(bytes(encoded)))
                    .endObject()
            }
            if (bytes(packet).size > 256 * 1024) throw IllegalArgumentException("Packet too large")
            return packet
        } finally {
            Arrays.fill(secret, 0.toByte())
            try {
                encapsulated.destroy()
            } catch (_: Exception) {
                // Best effort release of the provider's encapsulation buffer.
            }
        }
    }

    /**
     * Seals the raw inner E2EE envelope used by Monitor Broadcast v2. The
     * caller supplies the protocol-specific AAD; KEM, HKDF, GCM, canonical
     * inner header ordering, and the null-signature ML-DSA input stay shared
     * with the Client-Control implementation above.
     */
    internal fun sealRawEnvelope(
        sender: Identity,
        receiver: PublicIdentity,
        sequence: Long,
        aad: ByteArray,
        plaintext: ByteArray,
    ): String {
        require(sequence > 0 && plaintext.isNotEmpty()) { "Invalid raw envelope input" }
        receiver.validate()
        val encapsulated: SecretWithEncapsulation = MLKEMGenerator(RANDOM).generateEncapsulated(
            MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, receiver.kemPublic),
        )
        val secret = encapsulated.secret
        val kemCiphertext = encapsulated.encapsulation
        val nonce = ByteArray(12)
        RANDOM.nextBytes(nonce)
        try {
            val key = deriveKey(secret, sequence, aad)
            val header = envelopeHeader(sequence, kemCiphertext, nonce, sender.publicIdentity)
            val ciphertext = aesGcm(true, key, nonce, join(aad, bytes(header)), plaintext)
            val unsigned = envelope(sequence, kemCiphertext, nonce, ciphertext,
                sender.publicIdentity, null)
            val signature = sender.sign(bytes(unsigned))
            return envelope(sequence, kemCiphertext, nonce, ciphertext,
                sender.publicIdentity, signature)
        } finally {
            Arrays.fill(secret, 0.toByte())
            try {
                encapsulated.destroy()
            } catch (_: Exception) {
                // Best effort release of the provider's encapsulation buffer.
            }
        }
    }

    @JvmStatic
    fun openResponse(
        device: Identity,
        hub: PublicIdentity,
        request: Route,
        packetJson: String,
    ): OpenedResponse {
        val packet = JsonParser.parseString(packetJson).asJsonObject
        val route = Route.parse(packet.getAsJsonObject("route"))
        if (route.version != 1 || route.direction != "RESPONSE" || route.sequence <= 0 ||
            request.hubId != route.hubId || request.ownerId != route.ownerId ||
            request.deviceId != route.deviceId || request.sessionEpoch != route.sessionEpoch ||
            request.operation != route.operation || request.operationId != route.operationId ||
            hub.id != route.senderKeyId || device.publicIdentity.id != route.receiverKeyId ||
            request.receiverKeyVersion != route.senderKeyVersion ||
            request.senderKeyVersion != route.receiverKeyVersion
        ) {
            throw IllegalArgumentException("Response route differs from trusted request")
        }
        val envelope = JsonParser.parseString(
            String(decode(string(packet, "envelope")), StandardCharsets.UTF_8),
        ).asJsonObject
        val sequence = longValue(envelope, "sequence")
        val kem = decode(string(envelope, "kem_ciphertext"))
        val nonce = decode(string(envelope, "nonce"))
        val ciphertext = decode(string(envelope, "ciphertext"))
        val signingPublic = decode(string(envelope, "sender_signing_public"))
        val signature = decode(string(envelope, "signature"))
        if (integer(envelope, "version") != 1 || string(envelope, "algorithm") != ALGORITHM ||
            sequence != route.sequence || kem.size != 1088 || nonce.size != 12 ||
            signature.size != 3309 || string(envelope, "sender_id") != hub.id ||
            !MessageDigest.isEqual(hub.signingPublic, signingPublic) || envelope.size() != 9
        ) {
            throw IllegalArgumentException("Invalid Hub response envelope")
        }
        val unsigned = envelope(sequence, kem, nonce, ciphertext, hub, null)
        if (!verify(hub, bytes(unsigned), signature)) {
            throw IllegalArgumentException("Hub response signature is invalid")
        }
        val aad = join(AAD_DOMAIN, bytes(route.toJson()))
        val secret = device.decapsulate(kem)
        try {
            val key = deriveKey(secret, sequence, aad)
            val header = envelopeHeader(sequence, kem, nonce, hub)
            val plaintext = aesGcm(false, key, nonce, join(aad, bytes(header)), ciphertext)
            val body = JsonParser.parseString(String(plaintext, StandardCharsets.UTF_8)).asJsonObject
            if (request.operationId != string(body, "operation_id")) {
                throw IllegalArgumentException("Response operation ID mismatch")
            }
            return OpenedResponse(route, body)
        } finally {
            Arrays.fill(secret, 0.toByte())
        }
    }

    @JvmStatic
    fun verify(signer: PublicIdentity, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 3309) return false
        val verifier = MLDSASigner()
        verifier.init(
            false,
            MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, signer.signingPublic),
        )
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    @JvmStatic
    fun grantJson(value: JsonObject, includeSignature: Boolean): String = json { writer ->
        writer.beginObject()
            .name("version").value(integer(value, "version"))
            .name("owner_id").value(string(value, "owner_id"))
            .name("owner_key_id").value(string(value, "owner_key_id"))
            .name("device_id").value(string(value, "device_id"))
            .name("device_key_id").value(string(value, "device_key_id"))
            .name("device_key_fingerprint").value(string(value, "device_key_fingerprint"))
            .name("hub_id").value(string(value, "hub_id"))
            .name("purpose").value(string(value, "purpose"))
            .name("issued_at").value(string(value, "issued_at"))
            .name("expires_at").value(string(value, "expires_at"))
            .name("nonce").value(string(value, "nonce"))
        if (includeSignature) writer.name("signature").value(string(value, "signature"))
        writer.endObject()
    }

    private fun envelopeHeader(
        sequence: Long,
        kem: ByteArray,
        nonce: ByteArray,
        sender: PublicIdentity,
    ): String = json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("algorithm").value(ALGORITHM)
            .name("sequence").value(sequence)
            .name("kem_ciphertext").value(encode(kem))
            .name("nonce").value(encode(nonce))
            .name("sender_id").value(sender.id)
            .name("sender_signing_public").value(encode(sender.signingPublic))
            .endObject()
    }

    private fun envelope(
        sequence: Long,
        kem: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        sender: PublicIdentity,
        signature: ByteArray?,
    ): String = json { writer ->
        writer.beginObject()
            .name("version").value(1)
            .name("algorithm").value(ALGORITHM)
            .name("sequence").value(sequence)
            .name("kem_ciphertext").value(encode(kem))
            .name("nonce").value(encode(nonce))
            .name("ciphertext").value(encode(ciphertext))
            .name("sender_id").value(sender.id)
            .name("sender_signing_public").value(encode(sender.signingPublic))
        writer.name("signature")
        if (signature == null) writer.nullValue() else writer.value(encode(signature))
        writer.endObject()
    }

    private fun publicFields(writer: JsonWriter, value: PublicIdentity) {
        writer.beginObject()
            .name("id").value(value.id)
            .name("kem_public").value(encode(value.kemPublic))
            .name("signing_public").value(encode(value.signingPublic))
            .endObject()
    }

    internal fun json(function: (JsonWriter) -> Unit): String {
        try {
            val output = StringWriter()
            val writer = JsonWriter(output)
            writer.setSerializeNulls(true)
            function(writer)
            writer.close()
            return output.toString()
        } catch (error: IOException) {
            throw IllegalStateException("JSON serialization failed", error)
        }
    }

    private fun deriveKey(secret: ByteArray, sequence: Long, aad: ByteArray): ByteArray =
        hkdf(secret, join(KEY_DOMAIN, ByteBuffer.allocate(8).putLong(sequence).array(), aad))

    private fun hkdf(secret: ByteArray, info: ByteArray): ByteArray {
        try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            val prk = mac.doFinal(secret)
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            val output = mac.doFinal(join(info, byteArrayOf(1)))
            Arrays.fill(prk, 0.toByte())
            return output
        } catch (error: Exception) {
            throw IllegalStateException("HKDF failed", error)
        }
    }

    private fun aesGcm(
        encrypt: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        input: ByteArray,
    ): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, nonce),
            )
            cipher.updateAAD(aad)
            return cipher.doFinal(input)
        } catch (error: Exception) {
            throw IllegalArgumentException("Encrypted packet authentication failed", error)
        } finally {
            Arrays.fill(key, 0.toByte())
        }
    }

    @JvmStatic
    fun encode(value: ByteArray): String = Base64.toBase64String(value)

    @JvmStatic
    fun decode(value: String): ByteArray = Base64.decode(value)

    private fun bytes(value: String): ByteArray = value.toByteArray(StandardCharsets.UTF_8)

    private fun join(vararg pieces: ByteArray): ByteArray {
        var size = 0
        for (piece in pieces) size += piece.size
        val output = ByteArray(size)
        var offset = 0
        for (piece in pieces) {
            System.arraycopy(piece, 0, output, offset, piece.size)
            offset += piece.size
        }
        return output
    }

    private fun sha256(value: ByteArray): ByteArray = try {
        MessageDigest.getInstance("SHA-256").digest(value)
    } catch (error: Exception) {
        throw IllegalStateException("SHA-256 unavailable", error)
    }

    private fun hex(value: ByteArray): String {
        val output = StringBuilder(value.size * 2)
        for (byte in value) output.append(String.format(Locale.ROOT, "%02x", byte.toInt() and 255))
        return output.toString()
    }

    private fun string(objectValue: JsonObject, key: String): String {
        if (!objectValue.has(key) || objectValue.get(key).isJsonNull) {
            throw IllegalArgumentException("Missing $key")
        }
        return objectValue.get(key).asString
    }

    private fun integer(objectValue: JsonObject, key: String): Int = objectValue.get(key).asInt

    private fun longValue(objectValue: JsonObject, key: String): Long = objectValue.get(key).asLong
}
