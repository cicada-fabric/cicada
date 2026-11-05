package native

import (
	"image"
	"image/color"
	"strings"

	"gioui.org/font"
	"gioui.org/io/semantic"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	"golang.org/x/exp/shiny/materialdesign/icons"
)

var (
	appSurface         = color.NRGBA{R: 250, G: 249, B: 247, A: 255}
	sidebarSurface     = color.NRGBA{R: 243, G: 242, B: 239, A: 255}
	appInk             = color.NRGBA{R: 32, G: 33, B: 36, A: 255}
	mutedInk           = color.NRGBA{R: 109, G: 110, B: 112, A: 255}
	appLine            = color.NRGBA{R: 229, G: 228, B: 224, A: 255}
	selectedSurface    = color.NRGBA{R: 230, G: 229, B: 225, A: 255}
	navigationIconData = map[string][]byte{
		"overview": icons.ActionHome,
		"devices":  icons.HardwareComputer,
		"sessions": icons.CommunicationChatBubbleOutline,
		"identity": icons.ActionPermIdentity,
		"settings": icons.ActionSettings,
		"hub":      icons.ActionSettingsEthernet,
		"dropdown": icons.NavigationArrowDropDown,
	}
)

func (v *view) navigationIcon(gtx layout.Context, page string) layout.Dimensions {
	if v.navigationIcons == nil {
		v.navigationIcons = make(map[string]*widget.Icon)
	}
	icon := v.navigationIcons[page]
	if icon == nil {
		var err error
		icon, err = widget.NewIcon(navigationIconData[page])
		if err != nil {
			panic(err)
		}
		v.navigationIcons[page] = icon
	}
	gtx.Constraints = layout.Exact(image.Pt(gtx.Dp(18), gtx.Dp(18)))
	return icon.Layout(gtx, appInk)
}

func (v *view) shellLayout(gtx layout.Context, s appcore.Snapshot, visible bool, flow appui.SetupFlow) layout.Dimensions {
	if v.workspaceButtons == nil {
		v.workspaceButtons = make(map[string]*widget.Clickable)
	}
	if v.workspacePage == "" {
		v.workspacePage = "overview"
	}
	compact := gtx.Constraints.Max.X < gtx.Dp(800)
	return layout.Flex{}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			width := unit.Dp(220)
			if compact {
				width = 60
			}
			gtx.Constraints.Min.X, gtx.Constraints.Max.X = gtx.Dp(width), gtx.Dp(width)
			paint.FillShape(gtx.Ops, sidebarSurface, clip.Rect{Max: gtx.Constraints.Max}.Op())
			return layout.UniformInset(8).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						label := "Cicada"
						if compact {
							label = "C"
						}
						style := material.Label(v.theme, unit.Sp(18), label)
						style.Font.Weight = font.SemiBold
						return layout.Inset{Top: 12, Bottom: 16, Left: 12}.Layout(gtx, style.Layout)
					}),
					layout.Rigid(v.hubPickerRow(s, compact)),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						v.navigationList.Axis = layout.Vertical
						return material.List(v.theme, &v.navigationList).Layout(gtx, len(workspacePages), func(gtx layout.Context, i int) layout.Dimensions {
							return v.navigationRow(gtx, workspacePages[i], compact, visible)
						})
					}),
					layout.Rigid(v.languageRow(compact)),
				)
			})
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			paint.FillShape(gtx.Ops, appLine, clip.Rect{Max: image.Pt(1, gtx.Constraints.Max.Y)}.Op())
			return layout.Inset{Left: 1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				if visible {
					return v.workspaceLayout(gtx, s, flow)
				}
				return v.accountLayout(gtx, s, flow)
			})
		}),
	)
}

func (v *view) navigationRow(gtx layout.Context, page string, compact, enabled bool) layout.Dimensions {
	button := v.workspaceButtons[page]
	if button == nil {
		button = new(widget.Clickable)
		v.workspaceButtons[page] = button
	}
	if button.Clicked(gtx) && enabled {
		v.workspacePage = page
		v.hubConnections = false
		v.contentList.Position = layout.Position{}
		v.window.Invalidate()
	}
	background := color.NRGBA{}
	if v.workspacePage == page && !v.hubConnections && enabled {
		background = selectedSurface
	}
	if !enabled {
		gtx = gtx.Disabled()
	}
	return layout.Inset{Top: 2, Bottom: 2}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return material.ButtonLayoutStyle{Button: button, Background: background, CornerRadius: 8}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			semantic.DescriptionOp(appui.Text(v.locale, "workspace."+page)).Add(gtx.Ops)
			return layout.Inset{Top: 10, Bottom: 10, Left: 12, Right: 12}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return v.navigationIcon(gtx, page) }),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						if compact {
							return layout.Dimensions{}
						}
						style := material.Label(v.theme, 14, appui.Text(v.locale, "workspace."+page))
						style.MaxLines = 1
						return layout.Inset{Left: 10}.Layout(gtx, style.Layout)
					}),
				)
			})
		})
	})
}

func (v *view) hubPickerRow(s appcore.Snapshot, compact bool) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if v.hubPicker.Clicked(gtx) && !v.busy.Load() {
			v.hubConnections = !v.hubConnections
			v.contentList.Position = layout.Position{}
			v.window.Invalidate()
		}
		if v.busy.Load() {
			gtx = gtx.Disabled()
		}
		return layout.Inset{Bottom: 16}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return material.ButtonLayoutStyle{Button: &v.hubPicker, Background: selectedSurface, CornerRadius: 8}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				semantic.DescriptionOp(appui.Text(v.locale, "connection.manage_hubs")).Add(gtx.Ops)
				return layout.Inset{Top: 10, Bottom: 10, Left: 12, Right: 12}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					if compact {
						return v.navigationIcon(gtx, "hub")
					}
					label := strings.TrimSpace(s.Hub.Address)
					if label == "" {
						label = appui.Text(v.locale, "connection.hubs")
					}
					return layout.Flex{Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
							style := material.Label(v.theme, 13, safeDisplay(label, 128))
							style.MaxLines = 1
							return style.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions { return v.navigationIcon(gtx, "dropdown") }),
					)
				})
			})
		})
	}
}

func (v *view) secondaryButton(gtx layout.Context, button *widget.Clickable, label string, enabled bool) layout.Dimensions {
	// Read/navigation controls take their text's natural width rather than
	// inheriting a full-width vertical row's minimum constraint.
	gtx.Constraints.Min.X = 0
	style := material.Button(v.theme, button, label)
	style.TextSize, style.Background, style.Color = 14, sidebarSurface, appInk
	style.CornerRadius = 8
	style.Inset = layout.Inset{Top: 8, Bottom: 8, Left: 12, Right: 12}
	if !enabled {
		gtx = gtx.Disabled()
		style.Color = mutedInk
	}
	return style.Layout(gtx)
}

func (v *view) languageRow(compact bool) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		items := []struct {
			button *widget.Clickable
			locale appui.Locale
			label  string
		}{{&v.langEN, appui.English, "EN"}, {&v.langZH, appui.Chinese, "中"}}
		children := make([]layout.FlexChild, 0, 2)
		for _, item := range items {
			children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				if item.button.Clicked(gtx) {
					v.locale = item.locale
					v.window.Invalidate()
				}
				style := material.Button(v.theme, item.button, item.label)
				style.TextSize = 12
				style.Inset = layout.Inset{Top: 8, Bottom: 8}
				style.Background = color.NRGBA{}
				style.Color = mutedInk
				if v.locale == item.locale {
					style.Color = appInk
				}
				return style.Layout(gtx)
			}))
		}
		return layout.Flex{}.Layout(gtx, children...)
	}
}

func (v *view) pageHeading(title string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		style := material.Label(v.theme, 22, title)
		style.Font.Weight = font.SemiBold
		return layout.Inset{Left: 20, Right: 20, Top: 20, Bottom: 12}.Layout(gtx, style.Layout)
	}
}

// The action area receives its measured natural height before the scrollable
// body. Text may wrap at narrow widths; no fixed footer height clips an action.
func (v *view) dockedPage(gtx layout.Context, title string, rows, actions []layout.Widget) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(v.pageHeading(title)),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Inset{Left: 20, Right: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return material.List(v.theme, &v.contentList).Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
					return layout.Inset{Top: 4, Bottom: 12, Right: 8}.Layout(gtx, rows[i])
				})
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if len(actions) == 0 {
				return layout.Dimensions{}
			}
			paint.FillShape(gtx.Ops, appLine, clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, 1)}.Op())
			return layout.Inset{Top: 12, Bottom: 12, Left: 20, Right: 20}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				children := make([]layout.FlexChild, 0, len(actions))
				for i, row := range actions {
					bottom := unit.Dp(0)
					if i < len(actions)-1 {
						bottom = 8
					}
					children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Inset{Bottom: bottom}.Layout(gtx, row) }))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
			})
		}),
	)
}

func (v *view) accountLayout(gtx layout.Context, s appcore.Snapshot, flow appui.SetupFlow) layout.Dimensions {
	if v.hubConnections {
		return v.dockedPage(gtx, appui.Text(v.locale, "connection.hubs"), v.hubConnectionRows(s), nil)
	}
	rows := v.publicStatusRows(s)
	rows = append(rows, v.contentRows(s, flow, false, false, nil, false, false)...)
	return v.dockedPage(gtx, appui.Text(v.locale, "shell.account"), rows, v.setupActionRows(s, flow, false))
}
