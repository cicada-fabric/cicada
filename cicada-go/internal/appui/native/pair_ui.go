//go:build windows

package native

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) pairSection(s appcore.Snapshot) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		flow := appui.PairFlow(s, time.Now())
		if !flow.Visible {
			return layout.Dimensions{}
		}
		if v.pairReviewID != s.Pair.ReviewID {
			v.pairReviewID = s.Pair.ReviewID
			v.pairBootstrapConsent.Value, v.pairSlotAConsent.Value, v.pairSlotBConsent.Value = false, false, false
		}
		if v.pairStateReviewID != s.Pair.StateReviewID {
			v.pairStateReviewID = s.Pair.StateReviewID
			v.pairRevokeConsent.Value = false
		}
		rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "pair.title")))}
		if s.Pair.ErrorCode != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.ErrorText(v.locale, s.Pair.ErrorCode))))
		}
		if flow.Recover {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "setup.private_recovery_body"))),
				layout.Rigid(v.pairButton(s, appcore.ActionRecoverPair, "", appui.Text(v.locale, "operation.recover_connection"), true)))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}
		if flow.Prepare {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "pair.intro"))),
				layout.Rigid(v.editorRow(&v.pairLabel, appui.Text(v.locale, "pair.label"), false)),
				layout.Rigid(v.pairButton(s, appcore.ActionPreparePair, "", appui.Text(v.locale, "pair.prepare"), validPairLabel(v.pairLabel.Text()))))
		}
		if s.Pair.PairID != "" {
			rows = append(rows, v.publicFieldRows("pair/", appui.PairPublicFields(s, time.Now()))...)
			for _, field := range []struct{ key, value string }{
				{"pair.label", safeDisplay(s.Pair.Label, 128)},
				{"pair.join_until", displayNodeTime(s.Pair.JoinUntil)}, {"pair.until", displayNodeTime(s.Pair.PeerExpiresAt)},
			} {
				if field.value != "" {
					rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, field.key)+": "+field.value)))
				}
			}
			key := map[string]string{"PREPARED": "pair.state.prepared", "WAITING_JOIN": "pair.state.waiting_join", "WAITING_CONSENT": "pair.state.waiting_consent",
				"ACTIVE": "pair.state.active", "EXPIRED": "pair.state.expired", "REVOKED": "pair.state.revoked"}[s.Pair.State]
			if key != "" {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, key))))
			}
			if !s.Pair.Current {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "pair.saved"))))
			}
		}
		if flow.BootstrapConsent {
			rows = append(rows, layout.Rigid(v.headingRow(appui.Text(v.locale, "pair.bootstrap_review"))),
				layout.Rigid(v.pairCheckbox(&v.pairBootstrapConsent, "pair.bootstrap_consent")),
				layout.Rigid(v.pairButton(s, appcore.ActionCompletePair, "", appui.Text(v.locale, "pair.complete"), v.pairBootstrapConsent.Value)))
		}
		if s.Pair.PairID != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "pair.policy"))))
			for index, slot := range s.Pair.Slots {
				if slot.NativeSessionID == "" {
					continue
				}
				letter := "A"
				consent, allowed := &v.pairSlotAConsent, flow.SlotAConsent
				if index == 1 {
					letter, consent, allowed = "B", &v.pairSlotBConsent, flow.SlotBConsent
				}
				rows = append(rows, layout.Rigid(v.headingRow(appui.Text(v.locale, "pair.slot")+" "+letter)))
				rows = append(rows, v.publicFieldRows("pair/"+letter+"/", appui.PairSlotPublicFields(s, index, allowed, time.Now()))...)
				if slot.ConsentRecorded && s.Pair.State != "ACTIVE" {
					rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "pair.recorded"))))
				}
				if allowed {
					for detailIndex, detail := range appui.PairSlotReviewDetails(v.locale, slot) {
						rows = append(rows, layout.Rigid(v.publicFieldRow("pair/"+letter+"/detail/"+strconv.Itoa(detailIndex), appui.PublicField{Value: detail})))
					}
					rows = append(rows, layout.Rigid(v.pairCheckbox(consent, "pair.slot_consent")),
						layout.Rigid(v.pairButton(s, appcore.ActionApprovePairSlot, letter, appui.Text(v.locale, "pair.approve_slot"), consent.Value)))
				}
				if hasAction(s, appcore.ActionRejectPairSlot) {
					rows = append(rows, layout.Rigid(v.pairButton(s, appcore.ActionRejectPairSlot, letter, appui.Text(v.locale, "pair.reject_slot"), true)))
				}
			}
		}
		if flow.ReviewSlots {
			rows = append(rows, layout.Rigid(v.pairButton(s, appcore.ActionPreparePairConsent, "", appui.Text(v.locale, "pair.review_slots"), true)))
		}
		if flow.Refresh {
			rows = append(rows, layout.Rigid(v.pairButton(s, appcore.ActionRefreshPair, "", appui.Text(v.locale, "pair.refresh"), true)))
		}
		if flow.Revoke {
			rows = append(rows, layout.Rigid(v.pairCheckbox(&v.pairRevokeConsent, "pair.revoke_consent")),
				layout.Rigid(v.pairButton(s, appcore.ActionRevokePair, "", appui.Text(v.locale, "pair.revoke"), v.pairRevokeConsent.Value)))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	}
}

func validPairLabel(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 128 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (v *view) pairCheckbox(value *widget.Bool, key string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if v.busy.Load() {
			gtx = gtx.Disabled()
		}
		return material.CheckBox(v.theme, value, appui.Text(v.locale, key)).Layout(gtx)
	}
}

func (v *view) pairButton(s appcore.Snapshot, kind appcore.ActionKind, slot, label string, consent bool) layout.Widget {
	key := string(kind) + "/" + slot
	button := v.pairButtons[key]
	if button == nil {
		button = new(widget.Clickable)
		v.pairButtons[key] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := consent && !v.busy.Load() && hasAction(s, kind)
		if button.Clicked(gtx) && enabled {
			input := appcore.PairAction{Label: strings.TrimSpace(v.pairLabel.Text()), PairID: s.Pair.PairID, ReviewID: s.Pair.ReviewID, Slot: slot,
				ConfirmBootstrap: v.pairBootstrapConsent.Value, ConfirmRevoke: v.pairRevokeConsent.Value}
			if kind == appcore.ActionRejectPairSlot || kind == appcore.ActionRevokePair {
				input.ReviewID = s.Pair.StateReviewID
			}
			if slot == "A" {
				input.ConfirmSlot = v.pairSlotAConsent.Value
				v.pairSlotAConsent.Value = false
			} else if slot == "B" {
				input.ConfirmSlot = v.pairSlotBConsent.Value
				v.pairSlotBConsent.Value = false
			}
			v.pairBootstrapConsent.Value, v.pairRevokeConsent.Value = false, false
			v.startDispatch(appcore.Action{Kind: kind, Pair: input})
		}
		return v.button(gtx, button, label, enabled)
	}
}
