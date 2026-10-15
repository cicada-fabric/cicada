package ai.cicada.client.hub

/** Bounded observations of app-owned UI nodes; never an RPC or authorization result. */
internal class LinkListUiObservation {
    enum class ReadState(val errorClass: String? = null) {
        UNKNOWN, IDLE, LOADING, OK_EMPTY, OK_NONEMPTY,
        ERROR_RPC_REJECTED("RPC_REJECTED"),
        ERROR_INVALID_RESPONSE("INVALID_RESPONSE"),
        ERROR_REQUEST_FAILED("REQUEST_FAILED"),
    }

    enum class ScrollContainer { UNKNOWN, NONE, PAGE, EDIT_TEXT, OTHER }
    enum class WaitOutcome { UNKNOWN, MATCH_FOUND, DEADLINE_EXPIRED }

    data class Snapshot(
        val refreshClickReturned: Boolean,
        val appRootAvailable: Boolean?,
        val readState: ReadState,
        val readStateAmbiguous: Boolean,
        val lastObservedReadState: ReadState,
        val readStatesObserved: List<ReadState>,
        val observedRowCount: Int?,
        val rowCountTruncated: Boolean,
        val targetNodePresent: Boolean?,
        val targetNodeVisible: Boolean?,
        val selectedScrollContainer: ScrollContainer,
        val lastActionScrollContainer: ScrollContainer,
        val scrollActionCount: Int,
        val scrollCountTruncated: Boolean,
        val lastScrollActionReturned: Boolean?,
        val waitOutcome: WaitOutcome,
    )

    private var refreshClickReturned = false
    private var appRootAvailable: Boolean? = null
    private var readState = ReadState.UNKNOWN
    private var readStateAmbiguous = false
    private var lastObservedReadState = ReadState.UNKNOWN
    private val readStatesObserved = LinkedHashSet<ReadState>()
    private var observedRowCount: Int? = null
    private var rowCountTruncated = false
    private var targetNodePresent: Boolean? = null
    private var targetNodeVisible: Boolean? = null
    private var selectedScrollContainer = ScrollContainer.UNKNOWN
    private var lastActionScrollContainer = ScrollContainer.UNKNOWN
    private var scrollActionCount = 0
    private var scrollCountTruncated = false
    private var lastScrollActionReturned: Boolean? = null
    private var waitOutcome = WaitOutcome.UNKNOWN

    fun recordRefreshClickReturned() { refreshClickReturned = true }

    fun recordMissingRoot() {
        appRootAvailable = false
        readState = ReadState.UNKNOWN
        readStateAmbiguous = false
        observedRowCount = null
        rowCountTruncated = false
        targetNodePresent = null
        targetNodeVisible = null
    }

    fun recordRoot(packageName: String, viewIds: List<String>, rows: Int,
        targetPresent: Boolean, targetVisible: Boolean) {
        require(rows >= 0 && (!targetVisible || targetPresent)) { "Invalid UI observation" }
        appRootAvailable = true
        val states = viewIds.mapNotNull { id ->
            ReadState.entries.firstOrNull { state -> state != ReadState.UNKNOWN &&
                (id == "link-list-state-${state.name}" ||
                    id == "$packageName:id/link-list-state-${state.name}") }
        }
        readStateAmbiguous = states.size > 1
        readState = states.singleOrNull() ?: ReadState.UNKNOWN
        if (readState != ReadState.UNKNOWN) {
            lastObservedReadState = readState
            // Retain at most seven distinct states in last-seen order, including revisits.
            readStatesObserved.remove(readState)
            readStatesObserved.add(readState)
        }
        observedRowCount = rows.coerceAtMost(100)
        rowCountTruncated = rows > 100
        targetNodePresent = targetPresent
        targetNodeVisible = targetVisible
    }

    fun recordScrollContainer(className: String?, selected: Boolean = className != null) {
        selectedScrollContainer = when {
            !selected -> ScrollContainer.NONE
            className?.contains("EditText") == true -> ScrollContainer.EDIT_TEXT
            className == "android.widget.ScrollView" -> ScrollContainer.PAGE
            else -> ScrollContainer.OTHER
        }
    }

    fun recordScrollActionStarted() {
        if (scrollActionCount < 80) scrollActionCount += 1 else scrollCountTruncated = true
        lastActionScrollContainer = selectedScrollContainer
        lastScrollActionReturned = null
    }

    fun recordScrollActionReturned(returned: Boolean) {
        lastScrollActionReturned = returned
    }

    fun recordWaitOutcome(outcome: WaitOutcome) { waitOutcome = outcome }

    fun snapshot() = Snapshot(refreshClickReturned, appRootAvailable, readState,
        readStateAmbiguous, lastObservedReadState, readStatesObserved.toList(),
        observedRowCount, rowCountTruncated, targetNodePresent, targetNodeVisible,
        selectedScrollContainer, lastActionScrollContainer, scrollActionCount, scrollCountTruncated,
        lastScrollActionReturned, waitOutcome)
}
