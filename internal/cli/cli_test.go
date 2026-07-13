package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDeleteSelfWithEnvAuthPreservesSavedLogin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))

	saved := []byte(`{"url":"https://saved.example","api_key":"at_live_saved","identity":"AGE-SECRET-KEY-SAVED"}`)
	p, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/agents/self" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer at_live_temporary" {
			t.Errorf("authorization = %q", got)
		}
		writeTestJSON(w, map[string]any{"deleted": "temporary@agents.test"})
	}))
	defer srv.Close()
	t.Setenv("AGENTTRANSFER_URL", srv.URL)
	t.Setenv("AGENTTRANSFER_KEY", "at_live_temporary")

	if err := cmdDeleteSelf(nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("saved login was removed: %v", err)
	}
	if string(got) != string(saved) {
		t.Fatalf("saved login changed: got %q", got)
	}
}
