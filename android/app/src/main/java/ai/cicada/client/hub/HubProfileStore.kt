package ai.cicada.client.hub

import android.content.Context
import android.util.AtomicFile
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlin.concurrent.withLock

/** Local selection only. Profiles never inherit another Hub's pin, keys or authorization. */
class HubProfileStore(context: Context) {
    private val appContext = context.applicationContext
    private val root = File(appContext.noBackupFilesDir, "client-hub-profiles")
    private val registryFile = AtomicFile(File(root, "profiles.json"))

    data class Scope(val profileId: String, val selectionGeneration: Long) {
        fun toJson(): JsonObject = JsonObject().apply {
            addProperty("profileId", profileId)
            addProperty("selectionGeneration", selectionGeneration)
        }
    }

    private data class Profile(val profileId: String, val label: String)
    private data class Registry(
        var activeProfileId: String,
        var selectionGeneration: Long,
        val profiles: MutableList<Profile>,
    ) {
        fun scope(): Scope = Scope(activeProfileId, selectionGeneration)
    }

    fun listHubProfiles(): JsonObject = ClientHubSession.PROCESS_LOCK.withLock {
        val registry = readRegistry()
        view(registry)
    }

    /** An immutable caller scope is checked before any device-key or network operation. */
    fun <T> withActiveScope(scope: Scope, action: (ClientHubSession) -> T): T =
        ClientHubSession.PROCESS_LOCK.withLock {
            val registry = readRegistry()
            checkScope(registry, scope)
            action(ClientHubSession(appContext, scope.profileId))
        }

    fun createHubProfile(label: String, scope: Scope): JsonObject = ClientHubSession.PROCESS_LOCK.withLock {
        val registry = readRegistry()
        checkScope(registry, scope)
        if (registry.profiles.size >= MAX_PROFILES) {
            throw HubSessionException("PROFILE_LIMIT_REACHED", "Remove an unused profile before adding another Hub")
        }
        registry.profiles.add(Profile(UUID.randomUUID().toString(), validateLabel(label)))
        writeRegistry(registry)
        view(registry)
    }

    fun activateHubProfile(profileId: String, scope: Scope): JsonObject = ClientHubSession.PROCESS_LOCK.withLock {
        val registry = readRegistry()
        checkScope(registry, scope)
        requireProfile(registry, profileId)
        if (registry.selectionGeneration >= MAX_SELECTION_GENERATION) {
            throw HubSessionException("PROFILE_GENERATION_EXHAUSTED", "Hub selection generation cannot advance safely")
        }
        // Advance even when explicitly selecting the same profile: old approval callbacks expire.
        registry.activeProfileId = profileId
        registry.selectionGeneration += 1
        writeRegistry(registry)
        view(registry)
    }

    /** The current scope prevents a stale confirmation from deleting a newly selected profile. */
    fun removeHubProfile(profileId: String, scope: Scope): JsonObject = ClientHubSession.PROCESS_LOCK.withLock {
        val registry = readRegistry()
        checkScope(registry, scope)
        requireProfile(registry, profileId)
        if (registry.activeProfileId == profileId) {
            throw HubSessionException("PROFILE_IS_ACTIVE", "Select another Hub before removing this local profile")
        }
        val session = ClientHubSession(appContext, profileId)
        session.ensureProfileRemovable()
        session.deleteProfileState()
        registry.profiles.removeAll { it.profileId == profileId }
        writeRegistry(registry)
        view(registry)
    }

    fun getStatus(scope: Scope): JsonObject = withActiveScope(scope) { session ->
        session.getStatus().apply { addProperty("selectionGeneration", scope.selectionGeneration) }
    }

    fun setActiveNetwork(networkId: String, scope: Scope): JsonObject = ClientHubSession.PROCESS_LOCK.withLock {
        val registry = readRegistry()
        checkScope(registry, scope)
        if (registry.selectionGeneration >= MAX_SELECTION_GENERATION) {
            throw HubSessionException("PROFILE_GENERATION_EXHAUSTED", "Hub selection generation cannot advance safely")
        }
        ClientHubSession(appContext, scope.profileId).setActiveNetwork(networkId) {
            registry.selectionGeneration += 1
            writeRegistry(registry)
        }
        view(registry)
    }

    private fun view(registry: Registry): JsonObject = JsonObject().apply {
        add("profiles", JsonArray().apply {
            registry.profiles.forEach { profile ->
                add(ClientHubSession(appContext, profile.profileId).getStatus().apply {
                    addProperty("label", profile.label)
                })
            }
        })
        add("activeScope", registry.scope().toJson())
    }

    private fun readRegistry(): Registry {
        if (!root.exists() && !root.mkdirs()) {
            throw HubSessionException("PROFILE_STORAGE_UNAVAILABLE", "Cannot create private Hub profile registry")
        }
        if (!registryFile.baseFile.exists() && !File(root, "profiles.json.bak").exists()) {
            // Adopt the old files in place. Do not copy/unwrap keys, re-pin, reset counters or retry.
            val legacy = ClientHubSession.profileDirectory(appContext, "legacy")
            val existingLegacy = legacy.listFiles()?.any { file ->
                file.name.startsWith("session-state.json") || file.name.startsWith("device-key.wrap.json")
            } == true
            val initial = Profile(if (existingLegacy) "legacy" else UUID.randomUUID().toString(),
                if (existingLegacy) "Existing Hub" else "Hub 1")
            return Registry(initial.profileId, 1, mutableListOf(initial)).also(::writeRegistry)
        }
        try {
            val json = registryFile.openRead().use { input ->
                if (input.channel.size() > MAX_REGISTRY_BYTES) throw IllegalArgumentException()
                JsonParser.parseReader(input.reader(StandardCharsets.UTF_8)).asJsonObject
            }
            require(json.get("version").asInt == 1)
            val activeId = json.get("activeProfileId").asString
            val generation = json.get("selectionGeneration").asLong
            require(generation in 1..MAX_SELECTION_GENERATION)
            val items = json.getAsJsonArray("profiles")
            require(items.size() in 1..MAX_PROFILES)
            val profiles = items.map { item ->
                val value = item.asJsonObject
                val id = value.get("profileId").asString
                ClientHubSession.validateProfileId(id)
                Profile(id, validateLabel(value.get("label").asString))
            }.toMutableList()
            require(profiles.map { it.profileId }.toSet().size == profiles.size)
            require(profiles.any { it.profileId == activeId })
            return Registry(activeId, generation, profiles)
        } catch (_: Exception) {
            // A damaged registry cannot silently create a new identity or reset its replay state.
            throw HubSessionException("PROFILE_REGISTRY_INVALID", "Saved Hub profile registry cannot be read safely")
        }
    }

    private fun writeRegistry(registry: Registry) {
        val json = JsonObject().apply {
            addProperty("version", 1)
            addProperty("activeProfileId", registry.activeProfileId)
            addProperty("selectionGeneration", registry.selectionGeneration)
            add("profiles", JsonArray().apply {
                registry.profiles.forEach { profile -> add(JsonObject().apply {
                    addProperty("profileId", profile.profileId)
                    addProperty("label", profile.label)
                }) }
            })
        }
        val output = registryFile.startWrite()
        try {
            output.write(json.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            registryFile.finishWrite(output)
        } catch (_: Exception) {
            registryFile.failWrite(output)
            throw HubSessionException("PROFILE_STORAGE_FAILED", "Could not persist Hub profile selection")
        }
    }

    private fun checkScope(registry: Registry, scope: Scope) {
        if (registry.scope() != scope) {
            throw HubSessionException("PROFILE_SELECTION_CHANGED", "Hub selection changed; review this operation again in the current profile")
        }
    }

    private fun requireProfile(registry: Registry, profileId: String) {
        ClientHubSession.validateProfileId(profileId)
        if (registry.profiles.none { it.profileId == profileId }) {
            throw HubSessionException("PROFILE_NOT_FOUND", "Hub profile no longer exists")
        }
    }

    private fun validateLabel(label: String): String {
        val value = label.trim()
        if (value.isEmpty() || value.length > 128 || value.any { it.isISOControl() }) {
            throw HubSessionException("INVALID_PROFILE_LABEL", "Enter a Hub profile label of at most 128 characters")
        }
        return value
    }

    companion object {
        private const val MAX_PROFILES = 32
        private const val MAX_REGISTRY_BYTES = 32 * 1024L
        private const val MAX_SELECTION_GENERATION = 9_007_199_254_740_991L
    }
}
