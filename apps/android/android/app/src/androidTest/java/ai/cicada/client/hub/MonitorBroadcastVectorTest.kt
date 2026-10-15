package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.Locale

private val goRfc3339Seconds = DateTimeFormatter
    .ofPattern("uuuu-MM-dd'T'HH:mm:ss", Locale.ROOT)

/** Go's RFC3339Nano formatter removes trailing fractional zeroes. */
private fun goRfc3339Nano(value: Instant): String {
    val seconds = goRfc3339Seconds.format(value.atOffset(ZoneOffset.UTC))
    if (value.nano == 0) return "${seconds}Z"
    val fraction = value.nano.toString().padStart(9, '0').trimEnd('0')
    return "${seconds}.${fraction}Z"
}

/** Public-vector byte checks plus generated-key verification of the local v2 producer. */
@RunWith(AndroidJUnit4::class)
class MonitorBroadcastVectorTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val manifestClaims = listOf(
        "version", "operation", "hub_id", "owner_id", "principal_id", "group_id",
        "group_revision", "endpoint_id", "node_id", "binding_id", "binding_epoch",
        "membership_revision", "endpoint_join_revision", "candidate_version", "candidate_key_id",
        "candidate_fingerprint", "candidate_proof_digest", "candidate_binding_digest",
        "candidate_public_identity", "owner_key_id", "issued_at", "expires_at",
    )
    private data class PreparedFixture(
        val owner: ClientWireCrypto.Identity,
        val result: JsonObject,
        val trusted: MonitorBroadcastCrypto.TrustedPrepare,
        val body: String,
        val now: Instant,
    )

    @Test fun publishedPublicVectorPinsConsentCanonicalBytesAadAndBothSignatures() {
        val bytes = vectorBytes()
        assertEquals(
            "012a0ed6d36d00e2b7d985e767d7221eb1db04f1eba60565f17c86364600996a",
            sha256(bytes),
        )
        val vector = JsonParser.parseString(String(bytes, StandardCharsets.UTF_8)).asJsonObject
        assertTrue(vector.get("synthetic_fixture").asBoolean)
        assertTrue(vector.get("never_deploy").asBoolean)
        assertTrue(vector.get("warning").asString.contains("PUBLIC SYNTHETIC TEST KEYS"))

        val consent = vector.getAsJsonObject("consent_scope")
        assertEquals(vector.get("consent_sha256").asString,
            MonitorBroadcastCrypto.consentDigestForVector(consent))
        val context = vector.getAsJsonObject("context")
        val envelopeBytes = Base64.getDecoder().decode(vector.get("envelope").asString)
        val envelopeText = String(envelopeBytes, StandardCharsets.UTF_8)
        val envelope = JsonParser.parseString(envelopeText).asJsonObject
        assertEquals(envelopeText, envelope.toString())
        assertEquals(listOf("type", "version", "suite", "context", "sealed", "signature"),
            envelope.entrySet().map { it.key })
        assertEquals("MONITOR_BROADCAST", envelope.get("type").asString)
        assertEquals(2, envelope.get("version").asInt)
        assertEquals("ML-KEM-768+ML-DSA-65/AES-256-GCM", envelope.get("suite").asString)

        val client = ClientWireCrypto.PublicIdentity.parse(
            vector.getAsJsonObject("client_public_identity"),
        )
        val monitor = ClientWireCrypto.PublicIdentity.parse(
            vector.getAsJsonObject("monitor_public_identity"),
        )
        val signedOuter = MonitorBroadcastCrypto.outerSigningBytesForVector(envelope)
        assertEquals(vector.get("outer_signing_bytes_hex").asString, hex(signedOuter))
        val outerSignature = Base64.getDecoder().decode(envelope.get("signature").asString)
        assertEquals(3309, outerSignature.size)
        assertTrue(ClientWireCrypto.verify(client, signedOuter, outerSignature))

        val sealed = envelope.getAsJsonObject("sealed")
        assertEquals(listOf("version", "algorithm", "sequence", "kem_ciphertext", "nonce",
            "ciphertext", "sender_id", "sender_signing_public", "signature"),
            sealed.entrySet().map { it.key })
        val signedInner = MonitorBroadcastCrypto.innerSigningBytesForVector(sealed)
        val innerSignature = Base64.getDecoder().decode(sealed.get("signature").asString)
        assertEquals(3309, innerSignature.size)
        assertTrue(ClientWireCrypto.verify(client, signedInner, innerSignature))

        val aad = MonitorBroadcastCrypto.aadForVector(context)
        assertEquals(vector.get("aad_hex").asString, hex(aad))
        assertArrayEquals(aad, ("cicada/client/monitor-broadcast/aad/v1\u0000" +
            MonitorBroadcastCrypto.canonicalContextForVector(context))
            .toByteArray(StandardCharsets.UTF_8))

        val scopeSource = consent.getAsJsonObject("source")
        assertEquals(context.get("broadcast_id").asString, consent.get("broadcast_id").asString)
        assertEquals(context.get("group_id").asString, consent.get("group_id").asString)
        assertEquals(context.get("monitor_endpoint_id").asString, scopeSource.get("endpoint_id").asString)
        assertEquals(context.get("owner_id").asString, scopeSource.get("owner_id").asString)
        assertEquals(context.get("monitor_binding_id").asString, scopeSource.get("binding_id").asString)
        assertEquals(context.get("monitor_binding_epoch").asLong, scopeSource.get("binding_epoch").asLong)
        assertEquals(context.get("monitor_key_id").asString, scopeSource.get("key_id").asString)
        assertEquals(monitor.id, scopeSource.get("key_id").asString)
        assertEquals(peerFingerprint(monitor), scopeSource.get("key_fingerprint").asString)
        assertEquals(vector.get("consent_sha256").asString, context.get("consent_sha256").asString)
        assertEquals(vector.get("sequence").asLong,
            context.get("confirm_request_sequence").asLong)
        assertEquals(vector.get("sequence").asLong, sealed.get("sequence").asLong)
    }

    @Test fun publicVectorMutationsBreakThePinnedConsentOrSignatures() {
        val vector = JsonParser.parseString(String(vectorBytes(), StandardCharsets.UTF_8)).asJsonObject
        val envelope = JsonParser.parseString(
            String(Base64.getDecoder().decode(vector.get("envelope").asString), StandardCharsets.UTF_8),
        ).asJsonObject
        val client = ClientWireCrypto.PublicIdentity.parse(
            vector.getAsJsonObject("client_public_identity"),
        )
        val originalSignature = Base64.getDecoder().decode(envelope.get("signature").asString)

        val changedContext = envelope.deepCopy()
        changedContext.getAsJsonObject("context").addProperty(
            "monitor_binding_epoch",
            changedContext.getAsJsonObject("context").get("monitor_binding_epoch").asLong + 1,
        )
        assertFalse(ClientWireCrypto.verify(client,
            MonitorBroadcastCrypto.outerSigningBytesForVector(changedContext), originalSignature))

        val changedOuterSignature = envelope.deepCopy()
        val flippedOuter = originalSignature.clone().also { it[0] = (it[0].toInt() xor 1).toByte() }
        changedOuterSignature.addProperty("signature", Base64.getEncoder().encodeToString(flippedOuter))
        assertFalse(ClientWireCrypto.verify(client,
            MonitorBroadcastCrypto.outerSigningBytesForVector(changedOuterSignature), flippedOuter))

        val sealed = envelope.getAsJsonObject("sealed")
        val originalInnerSignature = Base64.getDecoder().decode(sealed.get("signature").asString)
        val flippedInner = originalInnerSignature.clone().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertFalse(ClientWireCrypto.verify(client,
            MonitorBroadcastCrypto.innerSigningBytesForVector(sealed), flippedInner))

        val changedSource = vector.getAsJsonObject("consent_scope").deepCopy()
        val source = changedSource.getAsJsonObject("source")
        source.addProperty("binding_epoch", source.get("binding_epoch").asLong + 1)
        assertFalse(vector.get("consent_sha256").asString ==
            MonitorBroadcastCrypto.consentDigestForVector(changedSource))

        val unsorted = vector.getAsJsonObject("consent_scope").deepCopy()
        val recipients = unsorted.getAsJsonArray("recipients")
        val first = recipients[0].deepCopy()
        recipients.set(0, recipients[1].deepCopy())
        recipients.set(1, first)
        assertRejected("An unsorted consent roster was accepted") {
            MonitorBroadcastCrypto.consentDigestForVector(unsorted)
        }

        val nullRecipients = vector.getAsJsonObject("consent_scope").deepCopy()
        nullRecipients.add("recipients", com.google.gson.JsonNull.INSTANCE)
        assertRejected("A null consent roster was accepted") {
            MonitorBroadcastCrypto.consentDigestForVector(nullRecipients)
        }
    }

    @Test fun prepareVerificationRejectsForeignStaleExpiredAndNoncanonicalEvidence() {
        val fixture = preparedFixture()
        try {
            val verified = MonitorBroadcastCrypto.verifyPrepare(
                fixture.result, fixture.trusted, fixture.owner.publicIdentity, fixture.now,
            )
            assertEquals("PREPARED", verified.status)
            assertTrue(verified.canConfirm)
            assertEquals(2, verified.recipients.size)
            assertEquals("recipient_a", verified.recipients[0].endpointId)

            val reorderedResult = JsonObject()
            for (field in fixture.result.keySet().toList().reversed()) {
                reorderedResult.add(field, fixture.result.get(field).deepCopy())
            }
            assertEquals("PREPARED", verify(reorderedResult, fixture).status)

            val reorderedPreviewResult = fixture.result.deepCopy()
            val originalPreview = reorderedPreviewResult.getAsJsonObject("preview")
            val reorderedPreview = JsonObject()
            for (field in originalPreview.keySet().toList().reversed()) {
                reorderedPreview.add(field, originalPreview.get(field).deepCopy())
            }
            reorderedPreviewResult.add("preview", reorderedPreview)
            assertEquals("PREPARED", verify(reorderedPreviewResult, fixture).status)

            val foreign = fixture.result.deepCopy()
            val foreignPreview = foreign.getAsJsonObject("preview")
            foreignPreview.getAsJsonObject("consent_scope").getAsJsonArray("recipients")[0]
                .asJsonObject.addProperty("owner_id", "owner_foreign")
            assertRejected("A foreign consent recipient was accepted") {
                verify(foreign, fixture)
            }

            val staleGrant = fixture.result.deepCopy()
            val staleManifest = staleGrant.getAsJsonObject("preview")
                .getAsJsonObject("monitor_grant_manifest")
            staleManifest.addProperty("candidate_version", staleManifest.get("candidate_version").asLong + 1)
            assertRejected("A stale Monitor candidate manifest was accepted") {
                verify(staleGrant, fixture)
            }

            val badOwnerProof = fixture.result.deepCopy()
            val badPreview = badOwnerProof.getAsJsonObject("preview")
            val proofBytes = Base64.getDecoder().decode(
                badPreview.get("monitor_grant_signed_proof").asString,
            )
            val proof = JsonParser.parseString(String(proofBytes, StandardCharsets.UTF_8)).asJsonObject
            val proofSignature = Base64.getDecoder().decode(proof.get("signature").asString)
            proofSignature[0] = (proofSignature[0].toInt() xor 1).toByte()
            proof.addProperty("signature", Base64.getEncoder().encodeToString(proofSignature))
            badPreview.addProperty("monitor_grant_signed_proof",
                Base64.getEncoder().encodeToString(proof.toString().toByteArray(StandardCharsets.UTF_8)))
            assertRejected("A changed Owner signature was accepted") { verify(badOwnerProof, fixture) }

            val changedSource = fixture.result.deepCopy()
            val sourcePreview = changedSource.getAsJsonObject("preview")
            val scope = sourcePreview.getAsJsonObject("consent_scope")
            val sourceCard = scope.getAsJsonObject("source")
            sourceCard.addProperty("binding_epoch", sourceCard.get("binding_epoch").asLong + 1)
            sourcePreview.addProperty("consent_sha256",
                MonitorBroadcastCrypto.consentDigestForVector(scope))
            assertRejected("A source card outside the signed Monitor binding was accepted") {
                verify(changedSource, fixture)
            }

            val unsorted = fixture.result.deepCopy()
            val unsortedPreview = unsorted.getAsJsonObject("preview")
            val unsortedScope = unsortedPreview.getAsJsonObject("consent_scope")
            val roster = unsortedScope.getAsJsonArray("recipients")
            val oldFirst = roster[0].deepCopy()
            roster.set(0, roster[1].deepCopy())
            roster.set(1, oldFirst)
            assertRejected("A reversed recipient roster was accepted") { verify(unsorted, fixture) }
            assertRejected("An unsorted consent roster was hashed") {
                MonitorBroadcastCrypto.consentDigestForVector(unsortedScope)
            }

            val expired = fixture.result.deepCopy()
            expired.addProperty("expires_at", goRfc3339Nano(fixture.now.minusSeconds(1)))
            assertRejected("An expired Monitor preview was accepted") { verify(expired, fixture) }

            val wrongBody = fixture.result.deepCopy()
            wrongBody.addProperty("body_sha256", "0".repeat(64))
            assertRejected("A preview for another body was accepted") { verify(wrongBody, fixture) }

            val noncanonicalScope = fixture.result.deepCopy()
            val reorderedScope = JsonObject()
            val originalScope = noncanonicalScope.getAsJsonObject("preview")
                .getAsJsonObject("consent_scope")
            for (field in listOf("broadcast_id", "version", "group_id", "group_revision", "source", "recipients")) {
                reorderedScope.add(field, originalScope.get(field).deepCopy())
            }
            noncanonicalScope.getAsJsonObject("preview").add("consent_scope", reorderedScope)
            assertRejected("A reordered consent scope was accepted") { verify(noncanonicalScope, fixture) }
        } finally {
            fixture.owner.close()
        }
    }

    @Test fun previewExpiryAllowsOnlyFiveSecondsOfLocalClockSkew() {
        val fixture = preparedFixture()
        try {
            fun withExpiry(expiry: Instant): JsonObject = fixture.result.deepCopy().apply {
                addProperty("expires_at", goRfc3339Nano(expiry))
            }

            // A response arriving 180 ms after the server's TTL calculation can
            // appear 300.18 s in the future to the emulator's local clock.
            val slowClientClock = withExpiry(
                fixture.now.plusSeconds(300).plusMillis(180),
            )
            assertTrue("Synthetic timestamp must use Go's canonical .18Z spelling",
                slowClientClock.get("expires_at").asString.endsWith(".18Z"))
            assertEquals("PREPARED", MonitorBroadcastCrypto.verifyPrepare(
                slowClientClock, fixture.trusted, fixture.owner.publicIdentity, fixture.now,
            ).status)

            val exactToleranceBoundary = withExpiry(fixture.now.plusSeconds(305))
            assertEquals("PREPARED", MonitorBroadcastCrypto.verifyPrepare(
                exactToleranceBoundary, fixture.trusted, fixture.owner.publicIdentity, fixture.now,
            ).status)

            assertRejected("A preview beyond the local five-second skew bound was accepted") {
                MonitorBroadcastCrypto.verifyPrepare(
                    withExpiry(fixture.now.plusSeconds(305).plusNanos(1)),
                    fixture.trusted, fixture.owner.publicIdentity, fixture.now,
                )
            }
            assertRejected("An expired preview was accepted") {
                MonitorBroadcastCrypto.verifyPrepare(
                    withExpiry(fixture.now.minusNanos(1)),
                    fixture.trusted, fixture.owner.publicIdentity, fixture.now,
                )
            }
        } finally {
            fixture.owner.close()
        }
    }

    @Test fun grantMayExpireBeforePreviewButBoundsConfirmationAndLedgerRecovery() {
        val fixture = preparedFixture(groupGrantLifetimeSeconds = 120)
        try {
            val verified = MonitorBroadcastCrypto.verifyPrepare(
                fixture.result, fixture.trusted, fixture.owner.publicIdentity, fixture.now,
            )
            val grantExpiry = fixture.now.plusSeconds(120)
            assertEquals(grantExpiry, GroupKeyManifestVerifier.parseCanonicalUtc(verified.grantExpiresAt))
            assertEquals(grantExpiry, verified.validUntil)
            assertTrue(verified.canConfirmAt(fixture.now))
            assertTrue(verified.canConfirmAt(grantExpiry.minusNanos(1)))
            assertFalse(verified.canConfirmAt(grantExpiry))

            assertRejected("An expired Owner Group grant passed current verification") {
                MonitorBroadcastCrypto.verifyPrepare(
                    fixture.result, fixture.trusted, fixture.owner.publicIdentity, grantExpiry,
                )
            }

            val historicalNow = grantExpiry.plusSeconds(1)
            assertTrue(fixture.now.plusSeconds(300).isAfter(historicalNow))
            val historical = MonitorBroadcastCrypto.verifyPrepareForLedger(
                fixture.result, fixture.trusted, fixture.owner.publicIdentity,
                historicalNow,
            )
            assertEquals("PREPARED", historical.status)
            assertEquals(fixture.result.get("expires_at").asString, historical.expiresAt)
            assertEquals(verified.grantExpiresAt, historical.grantExpiresAt)
            assertEquals(grantExpiry, historical.validUntil)
            assertFalse(historical.canConfirm)
            assertFalse(historical.canConfirmAt(fixture.now))
            val client = ClientWireCrypto.Identity.generate()
            try {
                assertRejected("Historical ledger evidence was usable for signing") {
                    MonitorBroadcastCrypto.sealBody(
                        client, historical, "device_synthetic_test", 8, 4, 29, fixture.body,
                    )
                }
            } finally {
                client.close()
            }

            val alteredGrantExpiry = fixture.result.deepCopy()
            val alteredManifest = alteredGrantExpiry.getAsJsonObject("preview")
                .getAsJsonObject("monitor_grant_manifest")
            alteredManifest.addProperty("expires_at", goRfc3339Nano(fixture.now.plusSeconds(121)))
            assertRejected("An altered Owner grant expiry was accepted") {
                MonitorBroadcastCrypto.verifyPrepareForLedger(
                    alteredGrantExpiry, fixture.trusted, fixture.owner.publicIdentity, historicalNow,
                )
            }

            val badOwnerProof = fixture.result.deepCopy()
            val badPreview = badOwnerProof.getAsJsonObject("preview")
            val proofBytes = Base64.getDecoder().decode(
                badPreview.get("monitor_grant_signed_proof").asString,
            )
            val proof = JsonParser.parseString(String(proofBytes, StandardCharsets.UTF_8)).asJsonObject
            val signature = Base64.getDecoder().decode(proof.get("signature").asString)
            signature[0] = (signature[0].toInt() xor 1).toByte()
            proof.addProperty("signature", Base64.getEncoder().encodeToString(signature))
            badPreview.addProperty("monitor_grant_signed_proof",
                Base64.getEncoder().encodeToString(proof.toString().toByteArray(StandardCharsets.UTF_8)))
            assertRejected("Historical verification accepted a changed Owner proof signature") {
                MonitorBroadcastCrypto.verifyPrepareForLedger(
                    badOwnerProof, fixture.trusted, fixture.owner.publicIdentity, historicalNow,
                )
            }
        } finally {
            fixture.owner.close()
        }
    }

    @Test fun generatedEnvelopeUsesExactBodyAndBindsConfirmRouteSequence() {
        val fixture = preparedFixture()
        val client = ClientWireCrypto.Identity.generate()
        try {
            val verified = MonitorBroadcastCrypto.verifyPrepare(
                fixture.result, fixture.trusted, fixture.owner.publicIdentity, fixture.now,
            )
            val sequence = 29L
            val deviceId = "device_synthetic_test"
            val epoch = 8L
            val keyVersion = 4L
            val encoded = MonitorBroadcastCrypto.sealBody(
                client, verified, deviceId, epoch, keyVersion, sequence, fixture.body,
            )
            val wire = Base64.getDecoder().decode(encoded)
            val wireText = String(wire, StandardCharsets.UTF_8)
            val envelope = JsonParser.parseString(wireText).asJsonObject
            assertEquals(wireText, envelope.toString())
            assertEquals("MONITOR_BROADCAST", envelope.get("type").asString)
            assertEquals(2, envelope.get("version").asInt)
            val context = envelope.getAsJsonObject("context")
            assertEquals(verified.previewId, context.get("approval_id").asString)
            assertEquals(deviceId, context.get("client_device_id").asString)
            assertEquals(epoch, context.get("client_session_epoch").asLong)
            assertEquals(keyVersion, context.get("client_key_version").asLong)
            assertEquals(sequence, context.get("confirm_request_sequence").asLong)
            assertEquals(sequence, envelope.getAsJsonObject("sealed").get("sequence").asLong)
            assertEquals(verified.consentSha256, context.get("consent_sha256").asString)
            assertEquals(verified.snapshotDigest, context.get("recipient_snapshot_sha256").asString)
            assertEquals(sha256(fixture.body.toByteArray(StandardCharsets.UTF_8)),
                context.get("body_sha256").asString)
            assertFalse(wireText.contains(fixture.body))

            val inner = envelope.getAsJsonObject("sealed")
            assertTrue(ClientWireCrypto.verify(client.publicIdentity,
                MonitorBroadcastCrypto.innerSigningBytesForVector(inner),
                Base64.getDecoder().decode(inner.get("signature").asString)))
            assertTrue(ClientWireCrypto.verify(client.publicIdentity,
                MonitorBroadcastCrypto.outerSigningBytesForVector(envelope),
                Base64.getDecoder().decode(envelope.get("signature").asString)))
            assertEquals(("cicada/client/monitor-broadcast/aad/v1\u0000" +
                MonitorBroadcastCrypto.canonicalContextForVector(context)).toByteArray(StandardCharsets.UTF_8).toList(),
                MonitorBroadcastCrypto.aadForVector(context).toList())

            assertRejected("A body with changed UTF-8 bytes was sealed") {
                MonitorBroadcastCrypto.sealBody(client, verified, deviceId, epoch, keyVersion,
                    sequence, fixture.body + "x")
            }
            assertRejected("Malformed UTF-16 was silently replaced") {
                MonitorBroadcastCrypto.sealBody(client, verified, deviceId, epoch, keyVersion,
                    sequence, "broken\uD800")
            }
            // The preview does not preselect a route sequence. The caller passes its exact
            // next confirm RPC sequence, and the helper binds that value into both signed layers.
            val nextSequenceEnvelope = JsonParser.parseString(
                String(Base64.getDecoder().decode(MonitorBroadcastCrypto.sealBody(
                    client, verified, deviceId, epoch, keyVersion, sequence + 1, fixture.body,
                )), StandardCharsets.UTF_8),
            ).asJsonObject
            assertEquals(sequence + 1,
                nextSequenceEnvelope.getAsJsonObject("context").get("confirm_request_sequence").asLong)
            assertEquals(sequence + 1,
                nextSequenceEnvelope.getAsJsonObject("sealed").get("sequence").asLong)
        } finally {
            client.close()
            fixture.owner.close()
        }
    }

    private fun preparedFixture(groupGrantLifetimeSeconds: Long = 3600): PreparedFixture {
        val assetManifest = instrumentation.context.assets.open("group-key-manifest-v1.json").use {
            JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject
        }
        val owner = ClientWireCrypto.Identity.generate()
        val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        val issuedAt = goRfc3339Nano(now)
        val manifestExpiry = goRfc3339Nano(now.plusSeconds(groupGrantLifetimeSeconds))
        val manifest = assetManifest.deepCopy().apply {
            addProperty("owner_key_id", owner.publicIdentity.id)
            addProperty("issued_at", issuedAt)
            addProperty("expires_at", manifestExpiry)
            addProperty("digest", "0".repeat(64))
        }
        manifest.addProperty("digest", manifestDigest(manifest))
        val ownerProof = ownerProof(manifest, owner)
        val manifestSource = manifest.getAsJsonObject("candidate_public_identity")
        val source = JsonObject().apply {
            addProperty("endpoint_id", manifest.get("endpoint_id").asString)
            addProperty("principal_id", manifest.get("principal_id").asString)
            addProperty("owner_id", manifest.get("owner_id").asString)
            addProperty("node_id", manifest.get("node_id").asString)
            addProperty("membership_revision", manifest.get("membership_revision").asLong)
            addProperty("group_join_revision", manifest.get("endpoint_join_revision").asLong)
            addProperty("binding_id", manifest.get("binding_id").asString)
            addProperty("binding_epoch", manifest.get("binding_epoch").asLong)
            addProperty("key_id", manifest.get("candidate_key_id").asString)
            addProperty("key_version", manifest.get("candidate_version").asLong)
            addProperty("key_fingerprint", manifest.get("candidate_fingerprint").asString)
            addProperty("key_proof_digest", manifest.get("candidate_proof_digest").asString)
        }
        val recipients = listOf("recipient_a", "recipient_b").map { endpoint ->
            JsonObject().apply {
                addProperty("endpoint_id", endpoint)
                addProperty("principal_id", "principal_synthetic")
                addProperty("owner_id", manifest.get("owner_id").asString)
                addProperty("node_id", "node_recipient")
                addProperty("membership_revision", 4)
                addProperty("group_join_revision", 5)
                addProperty("binding_id", "binding_recipient")
                addProperty("binding_epoch", 3)
                addProperty("key_id", "pq1-recipient-$endpoint")
                addProperty("key_version", 7)
                addProperty("key_fingerprint", "sha256:" + "a".repeat(64))
                addProperty("key_proof_digest", "b".repeat(64))
            }
        }
        val body = " reviewed body with spaces  \n☃"
        val bodySha = sha256(body.toByteArray(StandardCharsets.UTF_8))
        val scope = JsonObject().apply {
            addProperty("version", 1)
            addProperty("broadcast_id", "broadcast_synthetic_test")
            addProperty("group_id", manifest.get("group_id").asString)
            addProperty("group_revision", manifest.get("group_revision").asLong)
            add("source", source)
            add("recipients", com.google.gson.JsonArray().apply { recipients.forEach(::add) })
        }
        val scopeDigest = MonitorBroadcastCrypto.consentDigestForVector(scope)
        val previewExpiry = goRfc3339Nano(now.plusSeconds(300))
        val result = JsonObject().apply {
            addProperty("preview_id", "preview_synthetic_test")
            addProperty("broadcast_id", "broadcast_synthetic_test")
            addProperty("status", "PREPARED")
            addProperty("group_id", manifest.get("group_id").asString)
            addProperty("monitor_endpoint_id", manifest.get("endpoint_id").asString)
            addProperty("body_sha256", bodySha)
            addProperty("snapshot_digest", "c".repeat(64))
            addProperty("expires_at", previewExpiry)
            add("preview", JsonObject().apply {
                add("monitor_grant_manifest", manifest)
                addProperty("monitor_grant_signed_proof", Base64.getEncoder().encodeToString(ownerProof))
                add("consent_scope", scope)
                addProperty("consent_sha256", scopeDigest)
            })
        }
        // Ensure the candidate key used by the cards remains exactly the manifest identity.
        assertEquals(manifestSource.get("id").asString, source.get("key_id").asString)
        return PreparedFixture(owner, result, MonitorBroadcastCrypto.TrustedPrepare(
            hubId = manifest.get("hub_id").asString,
            ownerId = manifest.get("owner_id").asString,
            groupId = manifest.get("group_id").asString,
            monitorEndpointId = manifest.get("endpoint_id").asString,
            bodySha256 = bodySha,
        ), body, now)
    }

    private fun verify(
        result: JsonObject,
        fixture: PreparedFixture,
    ): MonitorBroadcastCrypto.VerifiedPrepare = MonitorBroadcastCrypto.verifyPrepare(
            result, fixture.trusted, fixture.owner.publicIdentity, fixture.now,
        )

    private fun manifestDigest(manifest: JsonObject): String {
        val claims = JsonObject().apply {
            for (field in manifestClaims) add(field, manifest.get(field).deepCopy())
        }
        return sha256(("cicada/group/endpoint-key-grant-manifest/v1\u0000" + claims)
            .toByteArray(StandardCharsets.UTF_8))
    }

    private fun ownerProof(manifest: JsonObject, owner: ClientWireCrypto.Identity): ByteArray {
        val claims = JsonObject().apply {
            addProperty("version", 2)
            addProperty("owner_id", manifest.get("owner_id").asString)
            addProperty("link_id", "group-endpoint-key-grant:v1")
            addProperty("contract_digest", manifest.get("digest").asString)
            addProperty("key_binding_digest", manifest.get("candidate_binding_digest").asString)
            addProperty("expected_link_version", manifest.get("candidate_version").asLong)
            addProperty("side", "SOURCE")
            addProperty("issued_at", manifest.get("issued_at").asString)
            addProperty("expires_at", manifest.get("expires_at").asString)
            addProperty("nonce", "d".repeat(64))
        }
        val signed = ("cicada/communication-link/owner-key-grant/v2\u0000" + claims)
            .toByteArray(StandardCharsets.UTF_8)
        val signature = owner.sign(signed)
        return claims.deepCopy().apply {
            addProperty("signature", Base64.getEncoder().encodeToString(signature))
        }.toString().toByteArray(StandardCharsets.UTF_8)
    }

    private fun vectorBytes(): ByteArray = instrumentation.context.assets
        .open("monitor-broadcast-consent-v2.json").use { it.readBytes() }

    private fun peerFingerprint(public: ClientWireCrypto.PublicIdentity): String = "sha256:" +
        sha256("cicada/nodekeys/peer-key-fingerprint/v1\u0000".toByteArray(StandardCharsets.UTF_8) +
            public.kemPublic + public.signingPublic)

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun hex(value: ByteArray): String = value.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun assertRejected(message: String, block: () -> Unit) {
        try {
            block()
            throw AssertionError(message)
        } catch (_: IllegalArgumentException) { }
    }
}
