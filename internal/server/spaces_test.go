package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
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
	var readded struct {
		Member string            `json:"member"`
		Added  bool              `json:"added"`
		Event  *store.SpaceEvent `json:"event"`
	}
	code = e.doJSON("POST", "/v1/spaces/"+spaceID+"/members", aliceKey,
		map[string]any{"agent": "bob"}, &readded)
	if code != http.StatusOK || readded.Member != "bob" || readded.Added || readded.Event != nil {
		t.Fatalf("idempotent re-add: HTTP %d response=%+v", code, readded)
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

func TestConcurrentSpaceMemberAddsStayIdempotentAndOwnerOnly(t *testing.T) {
	e := newEnv(t)
	_, ownerKey := e.createAgent("member-race-owner")
	_, targetKey := e.createAgent("member-race-target")
	e.createAgent("member-race-outsider")

	var created struct {
		Space store.Space `json:"space"`
	}
	if code := e.doJSON("POST", "/v1/spaces", ownerKey, map[string]any{"name": "membership race"}, &created); code != http.StatusCreated {
		t.Fatalf("create space: HTTP %d", code)
	}

	const attempts = 12
	start := make(chan struct{})
	statuses := make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			statuses <- e.doJSON("POST", "/v1/spaces/"+created.Space.ID+"/members", ownerKey,
				map[string]any{"agent": "member-race-target"}, nil)
		}()
	}
	close(start)
	counts := map[int]int{}
	for i := 0; i < attempts; i++ {
		counts[<-statuses]++
	}
	if counts[http.StatusCreated] != 1 || counts[http.StatusOK] != attempts-1 || len(counts) != 2 {
		t.Fatalf("concurrent add statuses=%v, want one 201 and %d idempotent 200s", counts, attempts-1)
	}

	start = make(chan struct{})
	statuses = make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			statuses <- e.doJSON("POST", "/v1/spaces/"+created.Space.ID+"/members", targetKey,
				map[string]any{"agent": "member-race-outsider"}, nil)
		}()
	}
	close(start)
	for i := 0; i < attempts; i++ {
		if status := <-statuses; status != http.StatusForbidden {
			t.Fatalf("concurrent non-owner add: HTTP %d, want 403", status)
		}
	}
	outsider, err := e.srv.st.AgentByName("member-race-outsider")
	if err != nil {
		t.Fatal(err)
	}
	if _, member := e.srv.st.SpaceMemberRole(created.Space.ID, outsider.ID); member {
		t.Fatal("non-owner concurrent requests added the outsider")
	}
	var joins int
	if err := e.srv.st.DB.QueryRow(`SELECT COUNT(*) FROM space_events WHERE space_id=? AND kind='join'`, created.Space.ID).Scan(&joins); err != nil {
		t.Fatal(err)
	}
	if joins != 1 {
		t.Fatalf("join events=%d, want exactly one", joins)
	}
}

func TestConcurrentMemberPostsCannotOversubscribeSpaceOwnerQuota(t *testing.T) {
	e := newEnvCfg(t, Config{StorageQuota: 50, MaxFileSize: 1024})
	_, ownerKey := e.createAgent("quota-owner")
	_, bobKey := e.createAgent("quota-bob")
	_, carolKey := e.createAgent("quota-carol")

	var created struct {
		Space store.Space `json:"space"`
	}
	if code := e.doJSON("POST", "/v1/spaces", ownerKey, map[string]any{"name": "quota"}, &created); code != 201 {
		t.Fatalf("create space: %d", code)
	}
	for _, member := range []string{"quota-bob", "quota-carol"} {
		if code := e.doJSON("POST", "/v1/spaces/"+created.Space.ID+"/members", ownerKey,
			map[string]any{"agent": member}, nil); code != 201 {
			t.Fatalf("add %s: %d", member, code)
		}
	}
	e.upload(bobKey, "bob.bin", bytes.Repeat([]byte("b"), 30), "")
	e.upload(carolKey, "carol.bin", bytes.Repeat([]byte("c"), 30), "")

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for _, tc := range []struct {
		key, file string
	}{{bobKey, "bob.bin"}, {carolKey, "carol.bin"}} {
		wg.Add(1)
		go func(key, file string) {
			defer wg.Done()
			<-start
			statuses <- e.doJSON("POST", "/v1/spaces/"+created.Space.ID+"/events", key,
				map[string]any{"file": file}, nil)
		}(tc.key, tc.file)
	}
	close(start)
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusCreated] != 1 || counts[http.StatusInsufficientStorage] != 1 {
		t.Fatalf("concurrent post statuses=%v, want one 201 and one 507", counts)
	}
	owner, err := e.srv.st.AgentByName("quota-owner")
	if err != nil {
		t.Fatal(err)
	}
	if used, err := e.srv.st.StorageUsed(owner.ID); err != nil || used != 30 {
		t.Fatalf("owner usage=%d err=%v, want 30", used, err)
	}
}

func TestSpaceMemberCapacityReturns429(t *testing.T) {
	e := newEnv(t)
	_, ownerKey := e.createAgent("member-limit-owner")
	e.createAgent("member-limit-candidate")
	owner, err := e.srv.st.AgentByName("member-limit-owner")
	if err != nil {
		t.Fatal(err)
	}
	sp, err := e.srv.st.CreateSpace(owner.ID, "full membership")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := e.srv.st.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.MaxMembersPerSpace-1; i++ {
		id := fmt.Sprintf("http-member-id-%03d", i)
		name := fmt.Sprintf("http-member-%03d", i)
		if _, err := tx.Exec(`INSERT INTO agents(id,name,email,key_hash,created_at) VALUES(?,?,?,?,?)`,
			id, name, name+"@local", "key-"+name, i+1); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO space_members(space_id,agent_id,role,joined_at)
			VALUES(?,?,'member',?)`, sp.ID, id, i+1); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if code := e.doJSON("POST", "/v1/spaces/"+sp.ID+"/members", ownerKey,
		map[string]any{"agent": "member-limit-candidate"}, nil); code != http.StatusTooManyRequests {
		t.Fatalf("add member at capacity: HTTP %d, want 429", code)
	}
}
