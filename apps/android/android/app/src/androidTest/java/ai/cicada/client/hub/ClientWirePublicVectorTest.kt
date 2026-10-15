package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.stream.JsonWriter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.StringWriter
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Published public synthetic vectors only; this fixture must stay in androidTest assets. */
@RunWith(AndroidJUnit4::class)
class ClientWirePublicVectorTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()

    private data class Fixture(
        val json: JsonObject,
        val hub: ClientWireCrypto.Identity,
        val hubPublic: ClientWireCrypto.PublicIdentity,
        val device: ClientWireCrypto.Identity,
        val devicePublic: ClientWireCrypto.PublicIdentity,
    )

    private data class Opened(
        val route: ClientWireCrypto.Route,
        val plaintext: ByteArray,
    )

    @Test
    fun publishedRequestAndResponseVectorsDecryptAndMatchCanonicalAad() {
        val fixtureBytes = instrumentation.context.assets.open("client-control-v1.json").use {
            it.readBytes()
        }
        assertEquals(
            "f8b7e5d0a547cd1403645f9c3bd0b8f15f0b838ff66b0d5c0ff572c4be0861e0",
            hex(MessageDigest.getInstance("SHA-256").digest(fixtureBytes)),
        )
        val fixture = parseFixture(fixtureBytes)
        val vectors = fixture.json.getAsJsonArray("vectors")
        assertEquals(2, vectors.size())

        var requestRoute: ClientWireCrypto.Route? = null
        for (element in vectors) {
            val vector = element.asJsonObject
            val direction = vector.get("direction").asString
            val packet = vector.get("packet_utf8").asString
            val expectedPlaintext = vector.get("plaintext_utf8").asString
                .toByteArray(StandardCharsets.UTF_8)
            val expectedAad = Base64.getDecoder().decode(vector.get("aad_base64").asString)

            val receiver: ClientWireCrypto.Identity
            val trustedSender: ClientWireCrypto.PublicIdentity
            when (direction) {
                "REQUEST" -> {
                    receiver = fixture.hub
                    trustedSender = fixture.devicePublic
                }
                "RESPONSE" -> {
                    receiver = fixture.device
                    trustedSender = fixture.hubPublic
                }
                else -> error("Unknown vector direction: $direction")
            }

            val opened = openPacket(packet, receiver, trustedSender, expectedAad)
            assertArrayEquals("$direction plaintext UTF-8", expectedPlaintext, opened.plaintext)
            assertTrue("$direction ML-DSA signature", signatureIsValid(packet, trustedSender))
            assertRouteMatchesBinding(fixture, opened.route, direction)
            if (direction == "REQUEST") requestRoute = opened.route
        }

        // The Client production path must also accept the exact published Hub response.
        val response = vectors.map { it.asJsonObject }
            .single { it.get("direction").asString == "RESPONSE" }
        val clientOpened = ClientWireCrypto.openResponse(
            fixture.device,
            fixture.hubPublic,
            checkNotNull(requestRoute),
            response.get("packet_utf8").asString,
        )
        assertEquals("op-one", clientOpened.body.get("operation_id").asString)
        assertEquals("公开合成测试 <>&",
            clientOpened.body.getAsJsonObject("result").get("note").asString)
    }

    @Test
    fun changedEpochAndOperationAreRejectedByAuthenticatedAad() {
        val fixture = fixture()
        for (vector in vectors(fixture)) {
            val packet = JsonParser.parseString(vector.get("packet_utf8").asString).asJsonObject
            val sender = senderFor(fixture, vector.get("direction").asString)

            // Route fields are outside the signed envelope but included in AES-GCM AAD.
            for ((field, changed) in listOf(
                "session_epoch" to (packet.getAsJsonObject("route")
                    .get("session_epoch").asLong + 1),
                "operation" to "status.changes",
            )) {
                val tampered = parsePacket(vector.get("packet_utf8").asString)
                val route = tampered.getAsJsonObject("route")
                when (changed) {
                    is Long -> route.addProperty(field, changed)
                    is String -> route.addProperty(field, changed)
                    else -> error("Unsupported mutation")
                }
                val tamperedText = tampered.toString()
                assertTrue("Signature is independent of route and remains valid",
                    signatureIsValid(tamperedText, sender))
                val failure = captureFailure {
                    openPacket(tamperedText, receiverFor(fixture, vector), sender, null)
                }
                assertTrue("$field must fail GCM authentication, got $failure",
                    failure is AEADBadTagException)

                if (vector.get("direction").asString == "RESPONSE") {
                    val request = vectors(fixture).single {
                        it.get("direction").asString == "REQUEST"
                    }
                    val requestRoute = ClientWireCrypto.Route.parse(
                        parsePacket(request.get("packet_utf8").asString)
                            .getAsJsonObject("route"),
                    )
                    val clientFailure = captureFailure {
                        ClientWireCrypto.openResponse(
                            fixture.device, fixture.hubPublic, requestRoute, tamperedText,
                        )
                    }
                    assertTrue("ClientWireCrypto rejects a response with changed $field",
                        clientFailure is IllegalArgumentException)
                }
            }
        }
    }

    @Test
    fun flippedSignatureBytesAreRejectedInBothDirections() {
        val fixture = fixture()
        for (vector in vectors(fixture)) {
            val sender = senderFor(fixture, vector.get("direction").asString)
            val tampered = mutateEnvelope(vector.get("packet_utf8").asString) { envelope ->
                val signature = decode(envelope.get("signature").asString)
                signature[0] = (signature[0].toInt() xor 1).toByte()
                envelope.addProperty("signature", encode(signature))
            }
            assertFalse(signatureIsValid(tampered, sender))
            val failure = captureFailure {
                openPacket(tampered, receiverFor(fixture, vector), sender, null)
            }
            assertTrue("Flipped signature must fail before decryption: $failure",
                failure is IllegalArgumentException)

            if (vector.get("direction").asString == "RESPONSE") {
                val request = vectors(fixture).single {
                    it.get("direction").asString == "REQUEST"
                }
                val requestRoute = ClientWireCrypto.Route.parse(
                    parsePacket(request.get("packet_utf8").asString).getAsJsonObject("route"),
                )
                val clientFailure = captureFailure {
                    ClientWireCrypto.openResponse(
                        fixture.device, fixture.hubPublic, requestRoute, tampered,
                    )
                }
                assertTrue("ClientWireCrypto must reject the flipped Hub signature",
                    clientFailure is IllegalArgumentException)
            }
        }
    }

    @Test
    fun changedCiphertextTagIsRejectedAfterValidResigningInBothDirections() {
        val fixture = fixture()
        for (vector in vectors(fixture)) {
            val direction = vector.get("direction").asString
            val senderIdentity = if (direction == "REQUEST") fixture.device else fixture.hub
            val senderPublic = senderFor(fixture, direction)
            val tampered = mutateEnvelope(vector.get("packet_utf8").asString) { envelope ->
                val ciphertext = decode(envelope.get("ciphertext").asString)
                ciphertext[ciphertext.lastIndex] =
                    (ciphertext.last().toInt() xor 1).toByte()
                envelope.addProperty("ciphertext", encode(ciphertext))
                val unsigned = canonicalUnsignedEnvelope(envelope)
                envelope.addProperty("signature", encode(senderIdentity.sign(unsigned)))
            }
            assertTrue("Test re-signing keeps the envelope signature valid",
                signatureIsValid(tampered, senderPublic))
            val failure = captureFailure {
                openPacket(tampered, receiverFor(fixture, vector), senderPublic, null)
            }
            assertTrue("Changed GCM tag must fail authentication: $failure",
                failure is AEADBadTagException)

            if (direction == "RESPONSE") {
                val request = vectors(fixture).single {
                    it.get("direction").asString == "REQUEST"
                }
                val requestRoute = ClientWireCrypto.Route.parse(
                    parsePacket(request.get("packet_utf8").asString).getAsJsonObject("route"),
                )
                val clientFailure = captureFailure {
                    ClientWireCrypto.openResponse(
                        fixture.device, fixture.hubPublic, requestRoute, tampered,
                    )
                }
                assertTrue("ClientWireCrypto must reject a validly signed bad GCM tag",
                    clientFailure is IllegalArgumentException)
            }
        }
    }

    @Test
    fun testOnlyPrivateKeysAndContractFixtureAreBoundToExpectedPublicBundle() {
        val fixture = fixture()
        assertTrue(fixture.json.get("warning").asString.contains("PUBLIC SYNTHETIC TEST KEYS"))
        assertEquals(1, fixture.json.get("fixture_version").asInt)
        assertEquals(1, fixture.json.get("wire_version").asInt)
        assertEquals("hub-one", fixture.json.getAsJsonObject("binding").get("HubID").asString)
        assertTrue(fixture.hub.publicIdentity.id == fixture.hubPublic.id)
        assertTrue(fixture.device.publicIdentity.id == fixture.devicePublic.id)
    }

    private fun fixture(): Fixture = parseFixture(
        instrumentation.context.assets.open("client-control-v1.json").use { it.readBytes() },
    )

    private fun parseFixture(bytes: ByteArray): Fixture {
        val json = JsonParser.parseString(String(bytes, StandardCharsets.UTF_8)).asJsonObject
        val hubEntry = json.getAsJsonObject("hub_TEST_ONLY")
        val deviceEntry = json.getAsJsonObject("device_TEST_ONLY")
        val hubPublic = ClientWireCrypto.PublicIdentity.parse(hubEntry.getAsJsonObject("public"))
        val devicePublic = ClientWireCrypto.PublicIdentity.parse(
            deviceEntry.getAsJsonObject("public"),
        )
        val hub = ClientWireCrypto.Identity.fromPrivateJson(
            hubEntry.getAsJsonObject("private_TEST_ONLY").toString(),
        )
        val device = ClientWireCrypto.Identity.fromPrivateJson(
            deviceEntry.getAsJsonObject("private_TEST_ONLY").toString(),
        )
        assertTrue("Hub private vector key matches its public identity",
            hub.publicIdentity.sameAs(hubPublic))
        assertTrue("Device private vector key matches its public identity",
            device.publicIdentity.sameAs(devicePublic))
        return Fixture(json, hub, hubPublic, device, devicePublic)
    }

    private fun vectors(fixture: Fixture) = fixture.json.getAsJsonArray("vectors")
        .map { it.asJsonObject }

    private fun assertRouteMatchesBinding(
        fixture: Fixture,
        route: ClientWireCrypto.Route,
        direction: String,
    ) {
        val binding = fixture.json.getAsJsonObject("binding")
        assertEquals(binding.get("HubID").asString, route.hubId)
        assertEquals(binding.get("OwnerID").asString, route.ownerId)
        assertEquals(binding.get("DeviceID").asString, route.deviceId)
        assertEquals(binding.get("SessionEpoch").asLong, route.sessionEpoch)
        if (direction == "REQUEST") {
            assertEquals(binding.get("DeviceKeyVersion").asLong, route.senderKeyVersion)
            assertEquals(binding.get("HubKeyVersion").asLong, route.receiverKeyVersion)
            assertEquals(fixture.devicePublic.id, route.senderKeyId)
            assertEquals(fixture.hubPublic.id, route.receiverKeyId)
        } else {
            assertEquals(binding.get("HubKeyVersion").asLong, route.senderKeyVersion)
            assertEquals(binding.get("DeviceKeyVersion").asLong, route.receiverKeyVersion)
            assertEquals(fixture.hubPublic.id, route.senderKeyId)
            assertEquals(fixture.devicePublic.id, route.receiverKeyId)
        }
    }

    /** Independent test-side packet opener: it validates route bytes, signature, HKDF and GCM. */
    private fun openPacket(
        packetUtf8: String,
        receiver: ClientWireCrypto.Identity,
        trustedSender: ClientWireCrypto.PublicIdentity,
        publishedAad: ByteArray?,
    ): Opened {
        val packet = parsePacket(packetUtf8)
        val routeJson = packet.getAsJsonObject("route")
        val route = ClientWireCrypto.Route.parse(routeJson)
        val routeCanonical = canonicalRoute(routeJson)
        // Compare our independently ordered route with the production route serializer as well.
        assertEquals(routeCanonical, route.toJson())
        val aad = concat(
            "cicada/client-control/packet/v1\u0000".toByteArray(StandardCharsets.UTF_8),
            routeCanonical.toByteArray(StandardCharsets.UTF_8),
        )
        if (publishedAad != null) assertArrayEquals("published AAD", publishedAad, aad)

        val envelope = JsonParser.parseString(
            String(decode(packet.get("envelope").asString), StandardCharsets.UTF_8),
        ).asJsonObject
        require(envelope.size() == 9) { "Unexpected envelope fields" }
        val sequence = envelope.get("sequence").asLong
        val kem = decode(envelope.get("kem_ciphertext").asString)
        val nonce = decode(envelope.get("nonce").asString)
        val ciphertext = decode(envelope.get("ciphertext").asString)
        val signature = decode(envelope.get("signature").asString)
        require(envelope.get("version").asInt == 1)
        require(envelope.get("algorithm").asString == ALGORITHM)
        require(sequence == route.sequence)
        require(envelope.get("sender_id").asString == trustedSender.id)
        require(MessageDigest.isEqual(
            trustedSender.signingPublic,
            decode(envelope.get("sender_signing_public").asString),
        )) { "Envelope signing key differs from independently trusted sender" }
        require(ClientWireCrypto.verify(
            trustedSender, canonicalUnsignedEnvelope(envelope), signature,
        )) { "Envelope signature verification failed" }

        val header = canonicalHeader(envelope)
        val secret = receiver.decapsulate(kem)
        try {
            val key = deriveKey(secret, sequence, aad)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    GCMParameterSpec(128, nonce),
                )
                cipher.updateAAD(concat(aad, header))
                return Opened(route, cipher.doFinal(ciphertext))
            } finally {
                Arrays.fill(key, 0)
            }
        } finally {
            Arrays.fill(secret, 0)
        }
    }

    private fun signatureIsValid(
        packetUtf8: String,
        trustedSender: ClientWireCrypto.PublicIdentity,
    ): Boolean {
        val packet = parsePacket(packetUtf8)
        val envelope = JsonParser.parseString(
            String(decode(packet.get("envelope").asString), StandardCharsets.UTF_8),
        ).asJsonObject
        return envelope.get("sender_id").asString == trustedSender.id &&
            MessageDigest.isEqual(
                trustedSender.signingPublic,
                decode(envelope.get("sender_signing_public").asString),
            ) && ClientWireCrypto.verify(
                trustedSender,
                canonicalUnsignedEnvelope(envelope),
                decode(envelope.get("signature").asString),
            )
    }

    private fun canonicalRoute(route: JsonObject): String = json { writer ->
        writer.beginObject()
            .name("version").value(route.get("version").asInt)
            .name("direction").value(route.get("direction").asString)
            .name("hub_id").value(route.get("hub_id").asString)
            .name("owner_id").value(route.get("owner_id").asString)
            .name("device_id").value(route.get("device_id").asString)
            .name("session_epoch").value(route.get("session_epoch").asLong)
            .name("sequence").value(route.get("sequence").asLong)
            .name("operation_id").value(route.get("operation_id").asString)
            .name("operation").value(route.get("operation").asString)
            .name("sender_key_id").value(route.get("sender_key_id").asString)
            .name("sender_key_version").value(route.get("sender_key_version").asLong)
            .name("receiver_key_id").value(route.get("receiver_key_id").asString)
            .name("receiver_key_version").value(route.get("receiver_key_version").asLong)
            .endObject()
    }

    private fun canonicalHeader(envelope: JsonObject): ByteArray = json { writer ->
        writer.beginObject()
            .name("version").value(envelope.get("version").asInt)
            .name("algorithm").value(envelope.get("algorithm").asString)
            .name("sequence").value(envelope.get("sequence").asLong)
            .name("kem_ciphertext").value(envelope.get("kem_ciphertext").asString)
            .name("nonce").value(envelope.get("nonce").asString)
            .name("sender_id").value(envelope.get("sender_id").asString)
            .name("sender_signing_public").value(
                envelope.get("sender_signing_public").asString,
            )
            .endObject()
    }.toByteArray(StandardCharsets.UTF_8)

    private fun canonicalUnsignedEnvelope(envelope: JsonObject): ByteArray = json { writer ->
        writer.beginObject()
            .name("version").value(envelope.get("version").asInt)
            .name("algorithm").value(envelope.get("algorithm").asString)
            .name("sequence").value(envelope.get("sequence").asLong)
            .name("kem_ciphertext").value(envelope.get("kem_ciphertext").asString)
            .name("nonce").value(envelope.get("nonce").asString)
            .name("ciphertext").value(envelope.get("ciphertext").asString)
            .name("sender_id").value(envelope.get("sender_id").asString)
            .name("sender_signing_public").value(
                envelope.get("sender_signing_public").asString,
            )
            .name("signature").nullValue()
            .endObject()
    }.toByteArray(StandardCharsets.UTF_8)

    private fun deriveKey(secret: ByteArray, sequence: Long, aad: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
        val prk = mac.doFinal(secret)
        try {
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            val info = concat(
                "cicada/e2ee/v1/key".toByteArray(StandardCharsets.UTF_8),
                ByteBuffer.allocate(8).putLong(sequence).array(),
                aad,
            )
            return mac.doFinal(concat(info, byteArrayOf(1)))
        } finally {
            Arrays.fill(prk, 0)
        }
    }

    private fun mutateEnvelope(packetUtf8: String, change: (JsonObject) -> Unit): String {
        val packet = parsePacket(packetUtf8)
        val envelope = JsonParser.parseString(
            String(decode(packet.get("envelope").asString), StandardCharsets.UTF_8),
        ).asJsonObject
        change(envelope)
        packet.addProperty(
            "envelope",
            encode(envelope.toString().toByteArray(StandardCharsets.UTF_8)),
        )
        return packet.toString()
    }

    private fun parsePacket(packetUtf8: String): JsonObject =
        JsonParser.parseString(packetUtf8).asJsonObject

    private fun senderFor(fixture: Fixture, direction: String) =
        if (direction == "REQUEST") fixture.devicePublic else fixture.hubPublic

    private fun receiverFor(fixture: Fixture, vector: JsonObject) =
        if (vector.get("direction").asString == "REQUEST") fixture.hub else fixture.device

    private fun captureFailure(action: () -> Unit): Throwable? = try {
        action()
        null
    } catch (error: Exception) {
        error
    }

    private fun decode(value: String): ByteArray = Base64.getDecoder().decode(value)

    private fun encode(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

    private fun concat(vararg values: ByteArray): ByteArray {
        val result = ByteArray(values.sumOf { it.size })
        var offset = 0
        for (value in values) {
            System.arraycopy(value, 0, result, offset, value.size)
            offset += value.size
        }
        return result
    }

    private fun hex(value: ByteArray): String = value.joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }

    private fun json(write: (JsonWriter) -> Unit): String {
        val output = StringWriter()
        val writer = JsonWriter(output)
        writer.setSerializeNulls(true)
        write(writer)
        writer.close()
        return output.toString()
    }

    private companion object {
        const val ALGORITHM = "ML-KEM-768+ML-DSA-65/AES-256-GCM"
    }
}
