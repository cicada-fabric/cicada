//go:build windows

package native

import (
	"image/color"
	"io"
	"strings"
	"time"

	"gioui.org/io/clipboard"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appui"
)

type publicFieldState struct {
	value       string
	selection   widget.Selectable
	copy        widget.Clickable
	copiedUntil time.Time
}

func (v *view) publicFieldRows(prefix string, fields []appui.PublicField) []layout.FlexChild {
	rows := make([]layout.FlexChild, 0, len(fields))
	for _, field := range fields {
		rows = append(rows, layout.Rigid(v.publicFieldRow(prefix+field.Key, field)))
	}
	return rows
}

func (v *view) publicFieldRow(id string, field appui.PublicField) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		state := v.publicFields[id]
		if state == nil || state.value != field.Value {
			// A replacement value gets new event tags as well as empty selection
			// and feedback. Queued clicks on the previous value cannot copy it.
			state = &publicFieldState{value: field.Value}
			v.publicFields[id] = state
		}
		if state.copy.Clicked(gtx) {
			gtx.Execute(clipboard.WriteCmd{Type: "application/text", Data: io.NopCloser(strings.NewReader(field.Value))})
			state.copiedUntil = gtx.Now.Add(2 * time.Second)
		}
		copied := gtx.Now.Before(state.copiedUntil)
		if copied {
			gtx.Execute(op.InvalidateCmd{At: state.copiedUntil})
		}
		return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			var rows []layout.FlexChild
			if field.Key != "" {
				rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, field.Key))))
			}
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						value := material.Body1(v.theme, field.Value)
						value.State, value.WrapPolicy = &state.selection, text.WrapGraphemes
						return value.Layout(gtx)
					}),
					layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						key := "common.copy"
						if copied {
							key = "common.copied"
						}
						button := material.Button(v.theme, &state.copy, appui.Text(v.locale, key))
						button.Background = color.NRGBA{R: 42, G: 56, B: 72, A: 255}
						button.Color, button.TextSize = v.theme.ContrastBg, unit.Sp(13)
						button.Inset = layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
						return button.Layout(gtx)
					}),
				)
			}))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		})
	}
}
