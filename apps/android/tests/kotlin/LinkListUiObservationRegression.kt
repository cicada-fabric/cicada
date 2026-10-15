package ai.cicada.client.hub

/** Synthetic UI-node projections only; this harness never runs Android or a Hub. */
fun main() {
    val packageName = "ai.cicada.client"
    fun state(name: String) = "link-list-state-$name"

    run {
        val value = LinkListUiObservation().snapshot()
        check(!value.refreshClickReturned && value.appRootAvailable == null)
        check(value.readState == LinkListUiObservation.ReadState.UNKNOWN)
        check(value.targetNodePresent == null && value.observedRowCount == null)
        check(value.waitOutcome == LinkListUiObservation.WaitOutcome.UNKNOWN)
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordRefreshClickReturned()
        observer.recordRoot(packageName, listOf(state("LOADING")), 0, false, false)
        observer.recordRoot(packageName, listOf(state("OK_NONEMPTY")), 1, true, false)
        check(observer.snapshot().targetNodePresent == true && observer.snapshot().targetNodeVisible == false)
        observer.recordRoot(packageName, listOf(state("OK_NONEMPTY")), 1, true, true)
        observer.recordWaitOutcome(LinkListUiObservation.WaitOutcome.MATCH_FOUND)
        val value = observer.snapshot()
        check(value.readStatesObserved == listOf(LinkListUiObservation.ReadState.LOADING,
            LinkListUiObservation.ReadState.OK_NONEMPTY))
        check(value.targetNodeVisible == true && value.refreshClickReturned)
        // UI observation preserves the existing wait result; it does not imply authorization.
        check(value.waitOutcome == LinkListUiObservation.WaitOutcome.MATCH_FOUND)
        observer.recordRoot(packageName, listOf(state("LOADING")), 0, false, false)
        check(observer.snapshot().readStatesObserved.last() == observer.snapshot().lastObservedReadState)
        check(observer.snapshot().readStatesObserved.size == 2)
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordRoot(packageName, emptyList(), 1, true, true)
        check(observer.snapshot().readState == LinkListUiObservation.ReadState.UNKNOWN)
        check(observer.snapshot().readStatesObserved.isEmpty())
        check(observer.snapshot().targetNodeVisible == true)
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordRoot(packageName, listOf(state("OK_EMPTY")), 0, false, false)
        observer.recordMissingRoot()
        val value = observer.snapshot()
        check(value.appRootAvailable == false && value.readState == LinkListUiObservation.ReadState.UNKNOWN)
        check(value.lastObservedReadState == LinkListUiObservation.ReadState.OK_EMPTY)
        check(value.targetNodePresent == null && value.targetNodeVisible == null && value.observedRowCount == null)
    }
    run {
        for (error in listOf("RPC_REJECTED", "INVALID_RESPONSE", "REQUEST_FAILED")) {
            val observer = LinkListUiObservation()
            observer.recordRoot(packageName, listOf(state("ERROR_$error")), 0, false, false)
            check(observer.snapshot().lastObservedReadState.errorClass == error)
        }
        val observer = LinkListUiObservation()
        observer.recordRoot(packageName, listOf(state("ERROR_private-proof-content")), 0, false, false)
        check(observer.snapshot().lastObservedReadState.errorClass == null)
        check(observer.snapshot().readState == LinkListUiObservation.ReadState.UNKNOWN)
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordRoot(packageName, listOf(state("LOADING"), state("OK_EMPTY")), 0, false, false)
        check(observer.snapshot().readStateAmbiguous)
        check(observer.snapshot().readState == LinkListUiObservation.ReadState.UNKNOWN)
        check(observer.snapshot().readStatesObserved.isEmpty())
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordRoot(packageName, listOf(state("OK_NONEMPTY")), 1_000, false, false)
        observer.recordScrollContainer("android.widget.ScrollView")
        repeat(81) {
            observer.recordScrollActionStarted()
            observer.recordScrollActionReturned(it % 2 == 0)
        }
        val value = observer.snapshot()
        check(value.observedRowCount == 100 && value.rowCountTruncated)
        check(value.scrollActionCount == 80 && value.scrollCountTruncated)
        check(value.lastScrollActionReturned == true)
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordScrollContainer("android.widget.EditText")
        check(observer.snapshot().selectedScrollContainer == LinkListUiObservation.ScrollContainer.EDIT_TEXT)
        observer.recordScrollContainer("android.widget.ScrollView")
        check(observer.snapshot().selectedScrollContainer == LinkListUiObservation.ScrollContainer.PAGE)
        observer.recordScrollActionStarted()
        check(observer.snapshot().lastScrollActionReturned == null)
        observer.recordScrollActionReturned(false)
        observer.recordScrollContainer("private-unknown-class")
        check(observer.snapshot().selectedScrollContainer == LinkListUiObservation.ScrollContainer.OTHER)
        observer.recordScrollContainer(null)
        check(observer.snapshot().selectedScrollContainer == LinkListUiObservation.ScrollContainer.NONE)
        check(observer.snapshot().lastActionScrollContainer == LinkListUiObservation.ScrollContainer.PAGE)
        observer.recordScrollContainer(null, selected = true)
        check(observer.snapshot().selectedScrollContainer == LinkListUiObservation.ScrollContainer.OTHER)
    }
    run {
        val observer = LinkListUiObservation()
        observer.recordRoot(packageName, listOf("$packageName:id/${state("OK_EMPTY")}"), 0, false, false)
        check(observer.snapshot().readState == LinkListUiObservation.ReadState.OK_EMPTY)
        observer.recordRoot(packageName, listOf("another.app:id/${state("LOADING")}"), 0, false, false)
        check(observer.snapshot().readState == LinkListUiObservation.ReadState.UNKNOWN)
        check(runCatching { observer.recordRoot(packageName, emptyList(), -1, false, false) }.isFailure)
        check(runCatching { observer.recordRoot(packageName, emptyList(), 1, false, true) }.isFailure)
    }
    println("LinkListUiObservationRegression: PASS (9 cases)")
}
