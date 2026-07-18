package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStorageReadEndpointsFailClosedOnAccountingError(t *testing.T) {
	e := newEnv(t)
	_, key := e.createAgent("storage-read-error")
	if _, err := e.srv.st.DB.Exec(`ALTER TABLE blobs RENAME TO broken_blobs`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/whoami", "/v1/files"} {
		resp, body := e.do(http.MethodGet, path, key, nil, "")
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("GET %s: HTTP %d body=%s, want 500", path, resp.StatusCode, body)
		}
	}
}

func TestDecodeBodyRejectsTrailingValuesAndOversize(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "second value", body: `{"ok":true} {"extra":true}`},
		{name: "trailing garbage", body: `{"ok":true} garbage`},
		{name: "oversize", body: `{"value":"` + strings.Repeat("x", (1<<20)+1) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", strings.NewReader(tt.body))
			var got map[string]any
			if err := decodeBody(r, &got); err == nil {
				t.Fatal("decodeBody accepted invalid body")
			}
		})
	}
}

func TestDecodeBodyAcceptsOneValueWithWhitespace(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("  {\"ok\":true}\n\t"))
	var got struct {
		OK bool `json:"ok"`
	}
	if err := decodeBody(r, &got); err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	if !got.OK {
		t.Fatal("decoded value missing")
	}
}

func TestAppendReceiptFailureIsCounted(t *testing.T) {
	e := newEnv(t)
	if err := e.srv.st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	e.srv.appendReceipt("agent@local", "sent", "", 0, "target", "")
	if got := e.srv.metrics.receiptAppendFailures.Load(); got != 1 {
		t.Fatalf("receipt failure metric = %d, want 1", got)
	}
}
