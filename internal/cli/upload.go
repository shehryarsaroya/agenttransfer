package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// uploadResult is the server's answer for a filed upload (both upload paths).
type uploadResult struct {
	SHA256 string `json:"sha256"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Link   *struct {
		URL       string `json:"url"`
		ExpiresAt string `json:"expires_at"`
		Once      bool   `json:"once"`
	} `json:"link"`
}

// directUploads reports (once per process) whether the server accepts
// direct-to-storage uploads (POST /v1/uploads).
func (a *api) directUploads() bool {
	a.capOnce.Do(func() {
		var wk struct {
			Uploads struct {
				Direct bool `json:"direct"`
			} `json:"uploads"`
		}
		if err := a.json("GET", "/.well-known/agenttransfer", nil, &wk); err == nil {
			a.direct = wk.Uploads.Direct
		}
	})
	return a.direct
}

// uploadBody files body under name. With direct uploads the bytes go
// straight to object storage — a single presigned PUT, or resumable parallel
// parts for large files — and the server verifies their sha256 before filing.
// Otherwise the body streams through PUT /v1/files/{name}. progress, when
// non-nil, receives human-readable status lines.
func (a *api) uploadBody(name string, body io.Reader, share bool, ttl string, once bool, progress io.Writer) (uploadResult, error) {
	if !a.directUploads() {
		return a.uploadThroughServer(name, body, share, ttl, once)
	}
	// Direct uploads need a known size and random access for parts: use the
	// file itself when we have one, otherwise spool (e.g. an encrypting reader).
	f, ok := body.(*os.File)
	if !ok || !isRegular(f) {
		tmp, err := os.CreateTemp("", "agenttransfer-upload-*")
		if err != nil {
			return uploadResult{}, err
		}
		defer os.Remove(tmp.Name())
		defer tmp.Close()
		if _, err := io.Copy(tmp, body); err != nil {
			return uploadResult{}, fmt.Errorf("prepare upload: %w", err)
		}
		f = tmp
	}
	info, err := f.Stat()
	if err != nil {
		return uploadResult{}, err
	}
	size := info.Size()
	if progress != nil && size > 256<<20 {
		fmt.Fprintf(progress, "hashing %s (%s)…\n", name, humanBytes(size))
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, size)); err != nil {
		return uploadResult{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	var sess struct {
		UploadID     string `json:"upload_id"`
		Mode         string `json:"mode"`
		PutURL       string `json:"put_url"`
		PartSize     int64  `json:"part_size"`
		Parts        int    `json:"parts"`
		Deduplicated bool   `json:"deduplicated"`
		File         uploadResult
		PartURLs     []struct {
			Number int    `json:"part_number"`
			URL    string `json:"url"`
		} `json:"part_urls"`
	}
	req := map[string]any{"name": name, "size": size, "sha256": sum, "share": share, "ttl": ttl, "once": once}
	if err := a.json("POST", "/v1/uploads", req, &sess); err != nil {
		return uploadResult{}, err
	}
	if sess.Deduplicated {
		return sess.File, nil
	}
	start := time.Now()
	var sent atomic.Int64
	stop := make(chan struct{})
	if progress != nil && size > 32<<20 {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					n := sent.Load()
					rate := float64(n) / time.Since(start).Seconds()
					fmt.Fprintf(progress, "  %s %d%% (%s of %s, %s/s)\n", name, n*100/max(size, 1),
						humanBytes(n), humanBytes(size), humanBytes(int64(rate)))
				}
			}
		}()
	}
	var parts []map[string]any
	if sess.Mode == "multipart" {
		parts, err = a.uploadParts(sess.UploadID, f, size, sess.PartSize, sess.Parts, sess.PartURLs, &sent)
	} else {
		err = putPresigned(sess.PutURL, io.NewSectionReader(f, 0, size), size, &sent)
	}
	close(stop)
	if err != nil {
		return uploadResult{}, err
	}
	var done struct {
		Status string       `json:"status"`
		Error  string       `json:"error"`
		File   uploadResult `json:"file"`
	}
	var complete any
	if parts != nil {
		complete = map[string]any{"parts": parts}
	}
	if err := a.jsonLong("POST", "/v1/uploads/"+sess.UploadID+"/complete", complete, &done); err != nil {
		return uploadResult{}, err
	}
	for i := 0; done.Status == "verifying" && i < 1800; i++ {
		if progress != nil && i%5 == 0 {
			fmt.Fprintf(progress, "  verifying sha256 on the server…\n")
		}
		time.Sleep(2 * time.Second)
		if err := a.json("GET", "/v1/uploads/"+sess.UploadID, nil, &done); err != nil {
			return uploadResult{}, err
		}
	}
	if done.Status != "done" {
		return uploadResult{}, fmt.Errorf("upload %s: %s %s", sess.UploadID, done.Status, done.Error)
	}
	if done.File.SHA256 != "" && done.File.SHA256 != sum {
		return uploadResult{}, fmt.Errorf("server recorded sha256 %s, local file is %s", done.File.SHA256, sum)
	}
	if done.File.SHA256 == "" {
		done.File = uploadResult{SHA256: sum, Name: name, Size: size}
	}
	return done.File, nil
}

func isRegular(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode().IsRegular()
}

// uploadParts sends every part with four workers, retrying each up to three
// times, and fetches presigned URLs in batches as needed.
func (a *api) uploadParts(id string, f *os.File, size, partSize int64, total int, first []struct {
	Number int    `json:"part_number"`
	URL    string `json:"url"`
}, sent *atomic.Int64) ([]map[string]any, error) {
	var mu sync.Mutex
	urls := map[int]string{}
	for _, p := range first {
		urls[p.Number] = p.URL
	}
	urlFor := func(n int) (string, error) {
		mu.Lock()
		u, ok := urls[n]
		mu.Unlock()
		if ok {
			return u, nil
		}
		var want []int
		for k := n; k <= total && len(want) < 100; k++ {
			want = append(want, k)
		}
		var more struct {
			PartURLs []struct {
				Number int    `json:"part_number"`
				URL    string `json:"url"`
			} `json:"part_urls"`
		}
		if err := a.json("POST", "/v1/uploads/"+id+"/parts", map[string]any{"part_numbers": want}, &more); err != nil {
			return "", err
		}
		mu.Lock()
		for _, p := range more.PartURLs {
			urls[p.Number] = p.URL
		}
		u = urls[n]
		mu.Unlock()
		if u == "" {
			return "", fmt.Errorf("no upload URL for part %d", n)
		}
		return u, nil
	}
	jobs := make(chan int)
	errs := make(chan error, 1)
	var results []map[string]any
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range jobs {
				off := int64(n-1) * partSize
				length := min(partSize, size-off)
				var etag string
				var err error
				for attempt := 1; attempt <= 3; attempt++ {
					var u string
					if u, err = urlFor(n); err == nil {
						var partSent atomic.Int64
						etag, err = putPart(u, io.NewSectionReader(f, off, length), length, &partSent)
						if err == nil {
							sent.Add(length)
							break
						}
					}
					time.Sleep(time.Duration(attempt) * time.Second)
				}
				if err != nil {
					select {
					case errs <- fmt.Errorf("part %d: %w", n, err):
					default:
					}
					return
				}
				mu.Lock()
				results = append(results, map[string]any{"part_number": n, "etag": etag})
				mu.Unlock()
			}
		}()
	}
	go func() {
		defer close(jobs)
		for n := 1; n <= total; n++ {
			select {
			case jobs <- n:
			case <-errs:
				return
			}
		}
	}()
	wg.Wait()
	select {
	case err := <-errs:
		return nil, err
	default:
	}
	if len(results) != total {
		return nil, errors.New("upload interrupted; run the command again to retry")
	}
	sort.Slice(results, func(i, j int) bool { return results[i]["part_number"].(int) < results[j]["part_number"].(int) })
	return results, nil
}

var presignedClient = &http.Client{Timeout: 0}

func putPresigned(u string, body io.Reader, size int64, sent *atomic.Int64) error {
	_, err := putPart(u, body, size, sent)
	if err == nil {
		sent.Store(size)
	}
	return err
}

func putPart(u string, body io.Reader, size int64, _ *atomic.Int64) (string, error) {
	req, err := http.NewRequest(http.MethodPut, u, body)
	if err != nil {
		return "", err
	}
	req.ContentLength = size
	resp, err := presignedClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("storage returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return resp.Header.Get("ETag"), nil
}

func (a *api) uploadThroughServer(name string, body io.Reader, share bool, ttl string, once bool) (uploadResult, error) {
	q := url.Values{}
	if share || ttl != "" || once {
		q.Set("share", "1")
	}
	if ttl != "" {
		q.Set("ttl", ttl)
	}
	if once {
		q.Set("once", "1")
	}
	p := "/v1/files/" + url.PathEscape(name)
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	resp, err := a.req("PUT", p, body, "application/octet-stream")
	if err != nil {
		return uploadResult{}, err
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return uploadResult{}, apiError(resp.StatusCode, data)
	}
	var up uploadResult
	if err := json.Unmarshal(data, &up); err != nil {
		return uploadResult{}, err
	}
	return up, nil
}
