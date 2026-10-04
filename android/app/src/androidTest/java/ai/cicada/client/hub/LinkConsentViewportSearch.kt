package ai.cicada.client.hub

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
