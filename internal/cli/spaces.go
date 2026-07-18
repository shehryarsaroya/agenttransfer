package cli

// Spaces are shared multi-agent coordination contexts: a fleet joins one and
// hands off work through a shared event stream (messages + file offers) instead
// of 1:1 sends. These commands are thin wrappers over the /v1/spaces REST API —
// nothing here can't be done with curl.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// spaceEvent is one entry in a space's shared stream, decoded from the wire form
// the server returns (store.SpaceEvent). kind is "message", "file", "join", or
// "leave"; the file fields are set only on "file" events.
type spaceEvent struct {
	Seq       int64  `json:"seq"`
	ID        string `json:"id"`
	Actor     string `json:"actor"`
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	SHA256    string `json:"sha256"`
	Name      string `json:"name"`
	MIME      string `json:"mime"`
	Size      int64  `json:"size"`
	CreatedAt int64  `json:"created_at"`
}

// formatSpaceEvent renders one event as a single human-readable line (no
// leading indent — the caller decides how to nest it).
func formatSpaceEvent(e spaceEvent) string {
	switch e.Kind {
	case "file":
		s := fmt.Sprintf("#%d %s offered %s (%d bytes) sha256:%s", e.Seq, e.Actor, e.Name, e.Size, e.SHA256)
		if e.Text != "" {
			s += " — " + e.Text
		}
		return s
	case "join":
		return fmt.Sprintf("#%d %s joined", e.Seq, e.Actor)
	case "leave":
		return fmt.Sprintf("#%d %s left", e.Seq, e.Actor)
	default: // "message" (and any future kind)
		return fmt.Sprintf("#%d %s: %s", e.Seq, e.Actor, e.Text)
	}
}

// cmdSpaces lists the spaces the caller belongs to.
func cmdSpaces(args []string) error {
	fs := flag.NewFlagSet("spaces", flag.ExitOnError)
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	a, err := client()
	if err != nil {
		return err
	}
	var out struct {
		Spaces []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"spaces"`
		Count int `json:"count"`
	}
	if err := a.json("GET", "/v1/spaces", nil, &out); err != nil {
		return err
	}
	if out.Count == 0 {
		fmt.Println("no spaces — create one with `agenttransfer space-new <name>`")
		return nil
	}
	for _, sp := range out.Spaces {
		fmt.Printf("%s  %s\n", sp.ID, sp.Name)
	}
	return nil
}

// cmdSpaceNew creates a space (the caller becomes its owner) and prints the id.
func cmdSpaceNew(args []string) error {
	fs := flag.NewFlagSet("space-new", flag.ExitOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer space-new <name>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	name := strings.Join(pos, " ") // allow multi-word names without quoting
	var out struct {
		Space struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"space"`
	}
	if err := a.json("POST", "/v1/spaces", map[string]any{"name": name}, &out); err != nil {
		return err
	}
	fmt.Printf("✓ created space %s (%s)\n", out.Space.ID, out.Space.Name)
	return nil
}

// cmdSpace shows a space with its members and recent events (member only).
func cmdSpace(args []string) error {
	fs := flag.NewFlagSet("space", flag.ExitOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer space <id>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	id := pos[0]
	var sp struct {
		Space struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"space"`
		Members []struct {
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"members"`
	}
	if err := a.json("GET", "/v1/spaces/"+url.PathEscape(id), nil, &sp); err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", sp.Space.ID, sp.Space.Name)
	fmt.Printf("members (%d):\n", len(sp.Members))
	for _, m := range sp.Members {
		fmt.Printf("  %s (%s)\n", m.Name, m.Role)
	}

	var ev struct {
		Events []spaceEvent `json:"events"`
		Cursor int64        `json:"cursor"`
	}
	if err := a.json("GET", "/v1/spaces/"+url.PathEscape(id)+"/events", nil, &ev); err != nil {
		return err
	}
	fmt.Println("events:")
	if len(ev.Events) == 0 {
		fmt.Println("  (none yet)")
	}
	for _, e := range ev.Events {
		fmt.Println("  " + formatSpaceEvent(e))
	}
	return nil
}

// cmdSpaceAdd enrolls a local agent as a member (owner only, server-enforced).
func cmdSpaceAdd(args []string) error {
	fs := flag.NewFlagSet("space-add", flag.ExitOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		return errors.New("usage: agenttransfer space-add <id> <agent>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	var out struct {
		Member string `json:"member"`
		Added  *bool  `json:"added"`
	}
	if err := a.json("POST", "/v1/spaces/"+url.PathEscape(pos[0])+"/members", map[string]any{"agent": pos[1]}, &out); err != nil {
		return err
	}
	// Older servers did not include "added" and always created a membership;
	// preserve that interpretation while recognizing the new explicit no-op.
	fmt.Println(formatSpaceAdd(out.Member, spaceAddWasAdded(out.Added)))
	return nil
}

func spaceAddWasAdded(added *bool) bool { return added == nil || *added }

func formatSpaceAdd(member string, added bool) string {
	if !added {
		return fmt.Sprintf("✓ %s is already a member (no change)", member)
	}
	return fmt.Sprintf("✓ added %s to the space", member)
}

// cmdSpacePost posts a message and/or offers a file to a space. --file is a
// reference to a file already in your folder ("sha256:..." or a filename),
// exactly like send — it is not uploaded here.
func cmdSpacePost(args []string) error {
	fs := flag.NewFlagSet("space-post", flag.ExitOnError)
	text := fs.String("text", "", "message text (or file caption)")
	file := fs.String("file", "", `file to offer: "sha256:..." or a name in your folder`)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New(`usage: agenttransfer space-post <id> [--text "..."] [--file REF]`)
	}
	if *text == "" && *file == "" {
		return errors.New("provide --text and/or --file")
	}
	a, err := client()
	if err != nil {
		return err
	}
	req := map[string]any{}
	if *text != "" {
		req["text"] = *text
	}
	if *file != "" {
		req["file"] = *file
	}
	var out struct {
		Event spaceEvent `json:"event"`
	}
	if err := a.json("POST", "/v1/spaces/"+url.PathEscape(pos[0])+"/events", req, &out); err != nil {
		return err
	}
	fmt.Println("✓ posted:")
	fmt.Println("  " + formatSpaceEvent(out.Event))
	return nil
}

// cmdSpacePull downloads a file shared in a space to outfile, streaming to a
// temp file while hashing, then verifying the sha256 against BOTH the requested
// hash and the server's X-Sha256 header before committing (mirrors cmdGet).
func cmdSpacePull(args []string) error {
	fs := flag.NewFlagSet("space-pull", flag.ExitOnError)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 3 {
		return errors.New("usage: agenttransfer space-pull <id> <sha> <outfile>")
	}
	a, err := client()
	if err != nil {
		return err
	}
	id := pos[0]
	wantSHA := strings.TrimPrefix(pos[1], "sha256:")
	dest := pos[2]

	resp, err := a.req("GET", "/v1/spaces/"+url.PathEscape(id)+"/files/"+url.PathEscape(wantSHA)+"/content", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return apiError(resp.StatusCode, data)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".agenttransfer-*")
	if err != nil {
		return err
	}
	h := sha256.New()
	_, cerr := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	tmp.Close()
	if cerr != nil {
		os.Remove(tmp.Name())
		return cerr
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, wantSHA) {
		os.Remove(tmp.Name())
		return fmt.Errorf("sha256 mismatch: got %s want %s — refusing the file", got, wantSHA)
	}
	if hdr := strings.TrimPrefix(resp.Header.Get("X-Sha256"), "sha256:"); hdr != "" && !strings.EqualFold(got, hdr) {
		os.Remove(tmp.Name())
		return fmt.Errorf("sha256 mismatch vs X-Sha256 header: got %s header %s — refusing the file", got, hdr)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	fmt.Printf("ok  %s (sha256 verified: %s)\n", dest, got)
	return nil
}

// cmdSpaceWatch long-polls a space's event stream, printing new events as they
// arrive and advancing the since cursor across iterations. Runs until Ctrl-C.
func cmdSpaceWatch(args []string) error {
	fs := flag.NewFlagSet("space-watch", flag.ExitOnError)
	since := fs.Int64("since", 0, "start after this event seq (0 = from the beginning)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return errors.New("usage: agenttransfer space-watch <id> [--since N]")
	}
	a, err := client()
	if err != nil {
		return err
	}
	id := pos[0]
	cursor := *since
	// Status to stderr so stdout carries only the event stream (pipe-friendly).
	fmt.Fprintf(os.Stderr, "watching space %s (from seq %d) — Ctrl-C to stop\n", id, cursor)
	for {
		// wait=30 makes each idle poll block server-side ~30s (within the 60s
		// response-header timeout), so the loop never busy-spins.
		path := fmt.Sprintf("/v1/spaces/%s/events?since=%d&wait=30", url.PathEscape(id), cursor)
		var out struct {
			Events []spaceEvent `json:"events"`
			Cursor int64        `json:"cursor"`
		}
		if err := a.json("GET", path, nil, &out); err != nil {
			return err
		}
		for _, e := range out.Events {
			fmt.Println(formatSpaceEvent(e))
		}
		if out.Cursor > cursor {
			cursor = out.Cursor
		}
	}
}
