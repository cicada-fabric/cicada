package appui

import (
	"math"
	"testing"
)

func TestVisibleCanvasObjectsCullOffscreenAndInvalidBounds(t *testing.T) {
	objects := []CanvasObject{
		{ID: "visible", Bounds: CanvasRect{X: 12, Y: 10, Width: 20, Height: 20}},
		{ID: "partial", Bounds: CanvasRect{X: -8, Y: 5, Width: 16, Height: 16}},
		{ID: "right", Bounds: CanvasRect{X: 101, Y: 5, Width: 10, Height: 10}},
		{ID: "zero", Bounds: CanvasRect{X: 5, Y: 5, Width: 0, Height: 10}},
	}
	got := VisibleCanvasObjects(objects, CanvasViewport{Width: 100, Height: 80}, CanvasTransform{Scale: 1})
	if len(got) != 2 || got[0].ID != "visible" || got[1].ID != "partial" {
		t.Fatalf("visible objects = %#v", got)
	}
}

func TestCanvasTransformAndScaleBounds(t *testing.T) {
	transform := CanvasTransform{OffsetX: 7, OffsetY: -3, Scale: 8}
	got := transform.ScreenBounds(CanvasRect{X: 10, Y: 20, Width: 30, Height: 40})
	if got.X != 37 || got.Y != 57 || got.Width != 90 || got.Height != 120 {
		t.Fatalf("clamped transform = %#v", got)
	}
	transform.Scale = 0
	got = transform.ScreenBounds(CanvasRect{Width: 10, Height: 10})
	if got.Width != 2 || got.Height != 2 {
		t.Fatalf("minimum scale = %#v", got)
	}
}

func TestCanvasCullBoundsAllocationForLargeOffscreenInput(t *testing.T) {
	objects := make([]CanvasObject, 100_000)
	for i := range objects {
		objects[i] = CanvasObject{ID: "offscreen", Bounds: CanvasRect{X: 1_000_000 + float64(i), Y: 1_000_000, Width: 10, Height: 10}}
	}
	got := VisibleCanvasObjects(objects, CanvasViewport{Width: 800, Height: 600}, CanvasTransform{Scale: 1})
	if len(got) != 0 || cap(got) > 16 {
		t.Fatalf("offscreen cull len/cap = %d/%d", len(got), cap(got))
	}
}

func TestCanvasRejectsNonFiniteMetadataAndZeroViewport(t *testing.T) {
	objects := []CanvasObject{
		{ID: "nan", Bounds: CanvasRect{X: 0, Y: 0, Width: 10, Height: 10}},
		{ID: "infinite", Bounds: CanvasRect{X: 0, Y: 0, Width: 10, Height: 10}},
	}
	objects[0].Bounds.X = math.NaN()
	objects[1].Bounds.Width = math.Inf(1)
	if got := VisibleCanvasObjects(objects, CanvasViewport{Width: 800, Height: 600}, CanvasTransform{Scale: 1}); len(got) != 0 {
		t.Fatalf("non-finite objects visible: %#v", got)
	}
	if got := VisibleCanvasObjects(objects, CanvasViewport{Width: 0, Height: 600}, CanvasTransform{Scale: 1}); got != nil {
		t.Fatalf("zero viewport returned %#v", got)
	}
}

func TestHitTestUsesSameTransformAndLastPaintedWins(t *testing.T) {
	objects := []CanvasObject{
		{ID: "bottom", Bounds: CanvasRect{X: 10, Y: 10, Width: 30, Height: 30}},
		{ID: "top", Bounds: CanvasRect{X: 20, Y: 20, Width: 30, Height: 30}},
	}
	transform := CanvasTransform{OffsetX: 7, OffsetY: -3, Scale: 2}
	selected, ok := HitTestCanvas(objects, 62, 42, transform)
	if !ok || selected.ID != "top" {
		t.Fatalf("selected %#v, ok=%v", selected, ok)
	}
	if _, ok := HitTestCanvas(objects, 1, 1, transform); ok {
		t.Fatal("hit test selected outside the transformed geometry")
	}
}

func BenchmarkVisibleCanvasObjectsCull(b *testing.B) {
	objects := make([]CanvasObject, 100_000)
	for i := range objects {
		objects[i] = CanvasObject{ID: "offscreen", Bounds: CanvasRect{X: 1_000_000 + float64(i), Y: 1_000_000, Width: 10, Height: 10}}
	}
	viewport := CanvasViewport{Width: 800, Height: 600}
	transform := CanvasTransform{Scale: 1}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VisibleCanvasObjects(objects, viewport, transform)
	}
}

func TestPreviewObjectsAreExplicitlyLocalFixture(t *testing.T) {
	items := PreviewCanvasObjects()
	if len(items) != 3 {
		t.Fatalf("preview count = %d", len(items))
	}
	for _, item := range items {
		if len(item.ID) < len("preview-") || item.ID[:len("preview-")] != "preview-" {
			t.Fatalf("fixture identifier is not visibly marked: %q", item.ID)
		}
	}
}
