package appui

import "math"

// CanvasRect and CanvasObject are display-only values. They never become Hub
// authorization requests; live objects must come from an appcore snapshot.
type CanvasRect struct {
	X, Y, Width, Height float64
}

type CanvasObject struct {
	ID     string
	Label  string
	Bounds CanvasRect
}

type CanvasTransform struct {
	OffsetX float64
	OffsetY float64
	Scale   float64
}

type CanvasViewport struct {
	Width  float64
	Height float64
}

func (t CanvasTransform) normalized() CanvasTransform {
	if !finite(t.OffsetX) {
		t.OffsetX = 0
	}
	if !finite(t.OffsetY) {
		t.OffsetY = 0
	}
	if !finite(t.Scale) {
		t.Scale = 1
	}
	if t.Scale < 0.2 {
		t.Scale = 0.2
	}
	if t.Scale > 3 {
		t.Scale = 3
	}
	return t
}

func (t CanvasTransform) ScreenBounds(rect CanvasRect) CanvasRect {
	t = t.normalized()
	if !validRect(rect) {
		return CanvasRect{}
	}
	return CanvasRect{
		X:      rect.X*t.Scale + t.OffsetX,
		Y:      rect.Y*t.Scale + t.OffsetY,
		Width:  rect.Width * t.Scale,
		Height: rect.Height * t.Scale,
	}
}

// VisibleCanvasObjects returns only objects intersecting the current viewport.
// The caller should still clip painting to the viewport rectangle.
func VisibleCanvasObjects(objects []CanvasObject, viewport CanvasViewport, transform CanvasTransform) []CanvasObject {
	if !finite(viewport.Width) || !finite(viewport.Height) || viewport.Width <= 0 || viewport.Height <= 0 {
		return nil
	}
	capacity := min(len(objects), 16)
	visible := make([]CanvasObject, 0, capacity)
	for _, object := range objects {
		if !validRect(object.Bounds) {
			continue
		}
		bounds := transform.ScreenBounds(object.Bounds)
		if !validRect(bounds) || bounds.Width <= 0 || bounds.Height <= 0 {
			continue
		}
		if bounds.X+bounds.Width <= 0 || bounds.Y+bounds.Height <= 0 ||
			bounds.X >= viewport.Width || bounds.Y >= viewport.Height {
			continue
		}
		visible = append(visible, object)
	}
	return visible
}

// HitTestCanvas applies the same world-to-screen transform as rendering and
// returns the last painted object at a point, matching visual stacking order.
func HitTestCanvas(objects []CanvasObject, screenX, screenY float64, transform CanvasTransform) (CanvasObject, bool) {
	if !finite(screenX) || !finite(screenY) {
		return CanvasObject{}, false
	}
	for i := len(objects) - 1; i >= 0; i-- {
		object := objects[i]
		if !validRect(object.Bounds) {
			continue
		}
		bounds := transform.ScreenBounds(object.Bounds)
		if !validRect(bounds) || bounds.Width <= 0 || bounds.Height <= 0 {
			continue
		}
		if screenX >= bounds.X && screenX < bounds.X+bounds.Width &&
			screenY >= bounds.Y && screenY < bounds.Y+bounds.Height {
			return object, true
		}
	}
	return CanvasObject{}, false
}

func validRect(rect CanvasRect) bool {
	return finite(rect.X) && finite(rect.Y) && finite(rect.Width) && finite(rect.Height) &&
		rect.Width > 0 && rect.Height > 0
}

func finite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func PreviewCanvasObjects() []CanvasObject {
	return []CanvasObject{
		{ID: "preview-thread-a", Label: "Preview Thread A", Bounds: CanvasRect{X: 64, Y: 72, Width: 210, Height: 92}},
		{ID: "preview-thread-b", Label: "Preview Thread B", Bounds: CanvasRect{X: 358, Y: 232, Width: 210, Height: 92}},
		{ID: "preview-group", Label: "Preview Group", Bounds: CanvasRect{X: 196, Y: 390, Width: 238, Height: 92}},
	}
}
