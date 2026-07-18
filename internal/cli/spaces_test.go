package cli

import "testing"

// formatSpaceEvent must render each event kind on one readable line: a message
// shows its text, join/leave are terse, and a file offer exposes the full
// sha256 (so an operator can copy it straight into `space-pull`).
func TestFormatSpaceEvent(t *testing.T) {
	cases := []struct {
		name string
		in   spaceEvent
		want string
	}{
		{"message", spaceEvent{Seq: 1, Actor: "a@x", Kind: "message", Text: "hi there"}, "#1 a@x: hi there"},
		{"join", spaceEvent{Seq: 2, Actor: "b@x", Kind: "join"}, "#2 b@x joined"},
		{"leave", spaceEvent{Seq: 3, Actor: "c@x", Kind: "leave"}, "#3 c@x left"},
		{"file", spaceEvent{Seq: 4, Actor: "d@x", Kind: "file", Name: "plan.pdf", Size: 42, SHA256: "abc123"},
			"#4 d@x offered plan.pdf (42 bytes) sha256:abc123"},
		{"file with caption", spaceEvent{Seq: 5, Actor: "e@x", Kind: "file", Name: "q3.csv", Size: 7, SHA256: "def", Text: "latest numbers"},
			"#5 e@x offered q3.csv (7 bytes) sha256:def — latest numbers"},
	}
	for _, c := range cases {
		if got := formatSpaceEvent(c.in); got != c.want {
			t.Errorf("%s: formatSpaceEvent() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFormatSpaceAddDistinguishesIdempotentReplay(t *testing.T) {
	if got := formatSpaceAdd("bob", true); got != "✓ added bob to the space" {
		t.Fatalf("new member output = %q", got)
	}
	if got := formatSpaceAdd("bob", false); got != "✓ bob is already a member (no change)" {
		t.Fatalf("existing member output = %q", got)
	}
	if !spaceAddWasAdded(nil) {
		t.Fatal("legacy response without added field was treated as a no-op")
	}
}
