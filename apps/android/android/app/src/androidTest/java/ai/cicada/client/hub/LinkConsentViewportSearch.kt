package ai.cicada.client.hub

internal enum class LinkKeyStatusUiResult {
    WAITING, VERIFIED, READ_FAILED, NOT_ACCEPTED, NOT_BILATERAL, UNEXPECTED_STATUS,
}

private const val verifiedKeyStatusNote = "双方当前证明已独立核验；这不代表消息已投递或模型已消费。"
private const val incompleteKeyStatusNote = "双方当前授权尚未核验完整。"
private val keyStatusStates = "MISSING|ACCEPTED|KEY_BINDING_STALE|OWNER_KEY_REVOKED|PROOF_EXPIRED|INVALID|LEGACY_KEY_UNBOUND"
private val keyStatusUiPattern = Regex("^SOURCE ($keyStatusStates) · TARGET ($keyStatusStates)。(" +
    Regex.escape(verifiedKeyStatusNote) + "|" + Regex.escape(incompleteKeyStatusNote) + ")$")

/** Classifies only the existing product status Text; a returned submit response is still WAITING. */
internal fun classifyLinkKeyStatusUiText(text: String): LinkKeyStatusUiResult {
    if (text == "当前双方证明读取或核验失败，请核对公钥固定与绑定后重读。") {
        return LinkKeyStatusUiResult.READ_FAILED
    }
    val result = keyStatusUiPattern.matchEntire(text)
        ?: return if (text.startsWith("SOURCE ")) LinkKeyStatusUiResult.UNEXPECTED_STATUS
        else LinkKeyStatusUiResult.WAITING
    if (result.groupValues[1] != "ACCEPTED" || result.groupValues[2] != "ACCEPTED") {
        return LinkKeyStatusUiResult.NOT_ACCEPTED
    }
    return if (result.groupValues[3] == verifiedKeyStatusNote) LinkKeyStatusUiResult.VERIFIED
        else LinkKeyStatusUiResult.NOT_BILATERAL
}

/** SDK-independent, bounded backward-then-forward page search planner. */
internal class LinkConsentViewportSearchPlanner(maxActionsPerPass: Int = 12) {
    enum class Direction { BACKWARD, FORWARD }

    private val actionLimit = maxActionsPerPass.also { require(it in 1..12) }
    private var direction = Direction.BACKWARD
    private var actionsInPass = 0
    private var complete = false

    var backwardActions: Int = 0
        private set
    var forwardActions: Int = 0
        private set

    val totalActions: Int get() = backwardActions + forwardActions

    fun nextDirection(contentReady: Boolean = true): Direction? =
        if (!contentReady || complete) null else direction

    /** Records one scroll attempt and changes direction at a boundary or fixed pass cap. */
    fun recordActionResult(moved: Boolean) {
        check(!complete) { "Viewport search is already complete" }
        when (direction) {
            Direction.BACKWARD -> backwardActions += 1
            Direction.FORWARD -> forwardActions += 1
        }
        actionsInPass += 1
        if (!moved || actionsInPass >= actionLimit) switchOrFinish()
    }

    private fun switchOrFinish() {
        if (direction == Direction.BACKWARD) {
            direction = Direction.FORWARD
            actionsInPass = 0
        } else {
            complete = true
        }
    }
}
