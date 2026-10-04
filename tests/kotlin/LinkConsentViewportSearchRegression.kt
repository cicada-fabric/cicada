package ai.cicada.client.hub

private data class SimulatedSearch(
    val found: Boolean,
    val directions: List<LinkConsentViewportSearchPlanner.Direction>,
)

private fun simulateSearch(
    pages: List<Boolean>,
    startPage: Int,
    maxActionsPerPass: Int = 12,
): SimulatedSearch {
    require(pages.isNotEmpty() && startPage in pages.indices)
    val planner = LinkConsentViewportSearchPlanner(maxActionsPerPass)
    val actions = ArrayList<LinkConsentViewportSearchPlanner.Direction>()
    var page = startPage
    while (true) {
        if (pages[page]) return SimulatedSearch(found = true, directions = actions)
        val direction = planner.nextDirection() ?: return SimulatedSearch(found = false, directions = actions)
        val step = if (direction == LinkConsentViewportSearchPlanner.Direction.BACKWARD) -1 else 1
        val nextPage = page + step
        val moved = nextPage in pages.indices
        actions += direction
        if (moved) page = nextPage
        planner.recordActionResult(moved)
    }
}

private fun targetAboveCurrentPageIsFound() {
    val result = simulateSearch(pages = listOf(true, false, false, false), startPage = 2)
    check(result.found)
    check(result.directions == listOf(
        LinkConsentViewportSearchPlanner.Direction.BACKWARD,
        LinkConsentViewportSearchPlanner.Direction.BACKWARD,
    ))
}

private fun targetBelowCurrentPageIsFoundAfterBackwardBoundary() {
    val result = simulateSearch(pages = listOf(false, false, false, false, true), startPage = 2)
    check(result.found)
    check(result.directions.first() == LinkConsentViewportSearchPlanner.Direction.BACKWARD)
    check(result.directions.drop(3).all { it == LinkConsentViewportSearchPlanner.Direction.FORWARD })
}

private fun boundarySwitchesFromBackwardToForward() {
    val planner = LinkConsentViewportSearchPlanner()
    check(planner.nextDirection() == LinkConsentViewportSearchPlanner.Direction.BACKWARD)
    planner.recordActionResult(moved = false)
    check(planner.nextDirection() == LinkConsentViewportSearchPlanner.Direction.FORWARD)
    planner.recordActionResult(moved = false)
    check(planner.nextDirection() == null)
    check(planner.backwardActions == 1 && planner.forwardActions == 1)
}

private fun actionCapsStopRepeatedScrolling() {
    val result = simulateSearch(pages = List(80) { false }, startPage = 40)
    check(!result.found)
    check(result.directions.count { it == LinkConsentViewportSearchPlanner.Direction.BACKWARD } == 12)
    check(result.directions.count { it == LinkConsentViewportSearchPlanner.Direction.FORWARD } == 12)
    check(result.directions.size == 24)

    val planner = LinkConsentViewportSearchPlanner()
    repeat(12) { planner.recordActionResult(moved = true) }
    check(planner.nextDirection() == LinkConsentViewportSearchPlanner.Direction.FORWARD)
    repeat(12) { planner.recordActionResult(moved = true) }
    check(planner.totalActions == 24)
    check(planner.nextDirection() == null)
}

private fun noMatchTerminatesAtBothBoundaries() {
    val result = simulateSearch(pages = listOf(false, false, false), startPage = 1)
    check(!result.found)
    check(result.directions.count { it == LinkConsentViewportSearchPlanner.Direction.BACKWARD } == 2)
    check(result.directions.count { it == LinkConsentViewportSearchPlanner.Direction.FORWARD } == 3)
    check(result.directions.size == 5)
}

private fun delayedContentReadinessPreservesFreshActionBudget() {
    val pages = listOf(true, false, false, false)
    val planner = LinkConsentViewportSearchPlanner()
    repeat(5) {
        check(planner.nextDirection(contentReady = false) == null)
        check(planner.totalActions == 0)
    }

    var page = 2
    var found = false
    while (true) {
        if (pages[page]) {
            found = true
            break
        }
        val direction = planner.nextDirection(contentReady = true) ?: break
        val step = if (direction == LinkConsentViewportSearchPlanner.Direction.BACKWARD) -1 else 1
        val nextPage = page + step
        val moved = nextPage in pages.indices
        if (moved) page = nextPage
        planner.recordActionResult(moved)
    }
    check(found)
    check(planner.backwardActions == 2 && planner.forwardActions == 0)
    check(planner.totalActions == 2)
}

fun main() {
    targetAboveCurrentPageIsFound()
    targetBelowCurrentPageIsFoundAfterBackwardBoundary()
    boundarySwitchesFromBackwardToForward()
    actionCapsStopRepeatedScrolling()
    noMatchTerminatesAtBothBoundaries()
    delayedContentReadinessPreservesFreshActionBudget()
    println("LinkConsentViewportSearchRegression: PASS (6 cases)")
}
