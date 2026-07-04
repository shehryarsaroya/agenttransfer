package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/shehryarsaroya/agenttransfer/internal/store"
)

// Spaces: a fleet coordinates through shared membership and one event stream.
// Alice opens a space and adds bob; alice offers a file into it; bob reads the
// stream and pulls the file by membership alone (no public link); a non-member
// can't see the space at all; bob replies and alice picks it up via the cursor.
func TestSpaces(t *testing.T) {
	e := newEnv(t)
	_, aliceKey := e.createAgent("alice")
	_, bobKey := e.createAgent("bob")
	_, carolKey := e.createAgent("carol")

	// Alice opens a space (she becomes its owner + first member).
	var created struct {
		Space store.Space `json:"space"`
	}
	code := e.doJSON("POST", "/v1/spaces", aliceKey, map[string]any{"name": "launch-crew"}, &created)
	if code != 201 || created.Space.ID == "" || created.Space.Name != "launch-crew" {
		t.Fatalf("create space: HTTP %d %+v", code, created.Space)
	}
	spaceID := created.Space.ID

	// It shows up in her space list.
	var mine struct {
		Spaces []store.Space `json:"spaces"`
		Count  int           `json:"count"`
	}
	if code = e.doJSON("GET", "/v1/spaces", aliceKey, nil, &mine); code != 200 || mine.Count != 1 {
		t.Fatalf("list spaces: HTTP %d count=%d", code, mine.Count)
	}

	// Alice adds bob (by name@instance — same-instance resolution).
	code = e.doJSON("POST", "/v1/spaces/"+spaceID+"/members", aliceKey, map[string]any{"agent": "bob@local"}, nil)
	if code != 201 {
		t.Fatalf("add member: HTTP %d", code)
	}

	// Alice uploads a file, then offers it into the space with a caption.
	payload := make([]byte, 64*1024)
	rand.Read(payload)
	sum := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(sum[:])
	e.upload(aliceKey, "plan.bin", payload, "")

	var posted struct {
		Event store.SpaceEvent `json:"event"`
	}
	code = e.doJSON("POST", "/v1/spaces/"+spaceID+"/events", aliceKey,
		map[string]any{"file": "plan.bin", "text": "here's the plan"}, &posted)
	if code != 201 || posted.Event.Kind != "file" || posted.Event.SHA256 != wantHex || posted.Event.Text != "here's the plan" {
		t.Fatalf("post file event: HTTP %d %+v", code, posted.Event)
	}

	// Bob reads the stream: bob's join, then alice's file offer.
	var list struct {
		Events []store.SpaceEvent `json:"events"`
		Cursor int64              `json:"cursor"`
	}
	code = e.doJSON("GET", "/v1/spaces/"+spaceID+"/events", bobKey, nil, &list)
	if code != 200 || len(list.Events) != 2 {
		t.Fatalf("bob events: HTTP %d %+v", code, list.Events)
	}
	if list.Events[0].Kind != "join" || list.Events[1].Kind != "file" {
		t.Fatalf("event kinds wrong: %+v", list.Events)
	}
	if list.Cursor != list.Events[1].Seq {
		t.Fatalf("cursor %d != last seq %d", list.Cursor, list.Events[1].Seq)
	}

	// Bob pulls the shared file through the space endpoint; bytes + hash match.
	resp, data := e.do("GET", "/v1/spaces/"+spaceID+"/files/"+wantHex+"/content", bobKey, nil, "")
	if resp.StatusCode != 200 || !bytes.Equal(data, payload) {
		t.Fatalf("bob file pull: HTTP %d, %d bytes", resp.StatusCode, len(data))
	}
	if resp.Header.Get("X-Sha256") != wantHex {
		t.Fatalf("X-Sha256 header: %q", resp.Header.Get("X-Sha256"))
	}

	// Carol is not a member: the space 404s (existence not revealed) and she
	// cannot pull the file either.
	if c, _ := e.do("GET", "/v1/spaces/"+spaceID, carolKey, nil, ""); c.StatusCode != 404 {
		t.Fatalf("carol get space: want 404 got %d", c.StatusCode)
	}
	if c, _ := e.do("GET", "/v1/spaces/"+spaceID+"/files/"+wantHex+"/content", carolKey, nil, ""); c.StatusCode != 404 {
		t.Fatalf("carol file pull: want 404 got %d", c.StatusCode)
	}
	if c := e.doJSON("POST", "/v1/spaces/"+spaceID+"/events", carolKey, map[string]any{"text": "let me in"}, nil); c != 404 {
		t.Fatalf("carol post: want 404 got %d", c)
	}

	// A plain member cannot widen membership — only the owner adds members, so
	// one member can't pull in an accomplice and expose the shared history.
	if c := e.doJSON("POST", "/v1/spaces/"+spaceID+"/members", bobKey, map[string]any{"agent": "carol@local"}, nil); c != 403 {
		t.Fatalf("non-owner add member: want 403 got %d", c)
	}

	// Bob replies with a message; alice picks it up from the cursor.
	if code = e.doJSON("POST", "/v1/spaces/"+spaceID+"/events", bobKey, map[string]any{"text": "on it"}, nil); code != 201 {
		t.Fatalf("bob message: HTTP %d", code)
	}
	var since struct {
		Events []store.SpaceEvent `json:"events"`
		Cursor int64              `json:"cursor"`
	}
	code = e.doJSON("GET", fmt.Sprintf("/v1/spaces/%s/events?since=%d", spaceID, list.Cursor), aliceKey, nil, &since)
	if code != 200 || len(since.Events) != 1 {
		t.Fatalf("alice since-cursor: HTTP %d %+v", code, since.Events)
	}
	if since.Events[0].Kind != "message" || since.Events[0].Text != "on it" {
		t.Fatalf("wrong event after cursor: %+v", since.Events[0])
	}

	// The space now has both members.
	var got struct {
		Space   store.Space         `json:"space"`
		Members []store.SpaceMember `json:"members"`
	}
	code = e.doJSON("GET", "/v1/spaces/"+spaceID, aliceKey, nil, &got)
	if code != 200 || len(got.Members) != 2 {
		t.Fatalf("get space: HTTP %d members=%+v", code, got.Members)
	}
}
