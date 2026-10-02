// Package s3test is an in-memory, path-style S3 server covering the subset the
// s3 package uses (objects, ranges, multipart, presigned query auth). It checks
// that every request is signed and that presigned URLs have not expired, but
// it does not recompute signatures — the s3 package's AWS test vectors cover
// signing correctness.
package s3test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type object struct {
	data        []byte
	contentType string
	etag        string
}

type upload struct {
	key   string
	parts map[int][]byte
}

// Fake is an http.Handler implementing a single-account S3 store.
type Fake struct {
	mu      sync.Mutex
	objects map[string]object // "bucket/key"
	uploads map[string]*upload
	seq     int
	// Now is overridable to test presigned expiry.
	Now func() time.Time
	// Requests counts handled requests by method.
	Requests map[string]int
}

// New returns an empty fake.
func New() *Fake {
	return &Fake{objects: map[string]object{}, uploads: map[string]*upload{}, Requests: map[string]int{}}
}

// Objects reports how many objects exist (across buckets).
func (f *Fake) Objects() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

// Keys lists stored object paths ("bucket/key"), sorted.
func (f *Fake) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Put stores an object directly (test setup).
func (f *Fake) Put(path string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[strings.TrimPrefix(path, "/")] = object{data: append([]byte(nil), data...), etag: etagOf(data)}
}

// Corrupt replaces an object's bytes (simulates a client uploading the wrong data).
func (f *Fake) Corrupt(path string, data []byte) { f.Put(path, data) }

func etagOf(b []byte) string {
	h := md5.Sum(b)
	return `"` + hex.EncodeToString(h[:]) + `"`
}

func (f *Fake) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", code, code)
}

func (f *Fake) authorized(r *http.Request) (bool, string) {
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		return true, ""
	}
	q := r.URL.Query()
	if q.Get("X-Amz-Signature") == "" {
		return false, "AccessDenied"
	}
	signedAt, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		return false, "AuthorizationQueryParametersError"
	}
	secs, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil {
		return false, "AuthorizationQueryParametersError"
	}
	if f.now().After(signedAt.Add(time.Duration(secs) * time.Second)) {
		return false, "AccessDenied" // S3 says "Request has expired"
	}
	return true, ""
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ok, code := f.authorized(r)
	if !ok {
		writeErr(w, http.StatusForbidden, code)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if !strings.Contains(path, "/") {
		writeErr(w, http.StatusBadRequest, "InvalidRequest")
		return
	}
	q := r.URL.Query()
	f.mu.Lock()
	f.Requests[r.Method]++
	f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && q.Has("uploads"):
		f.mu.Lock()
		f.seq++
		id := fmt.Sprintf("up-%d", f.seq)
		f.uploads[id] = &upload{key: path, parts: map[int][]byte{}}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)

	case r.Method == http.MethodPut && q.Get("uploadId") != "":
		n, err := strconv.Atoi(q.Get("partNumber"))
		if err != nil || n < 1 || n > 10000 {
			writeErr(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		data, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		u := f.uploads[q.Get("uploadId")]
		if u == nil || u.key != path {
			f.mu.Unlock()
			writeErr(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		u.parts[n] = data
		f.mu.Unlock()
		w.Header().Set("ETag", etagOf(data))

	case r.Method == http.MethodGet && q.Get("uploadId") != "":
		f.mu.Lock()
		u := f.uploads[q.Get("uploadId")]
		if u == nil || u.key != path {
			f.mu.Unlock()
			writeErr(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		nums := make([]int, 0, len(u.parts))
		for n := range u.parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		var b strings.Builder
		b.WriteString("<ListPartsResult><IsTruncated>false</IsTruncated>")
		for _, n := range nums {
			fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag><Size>%d</Size></Part>", n, etagOf(u.parts[n]), len(u.parts[n]))
		}
		b.WriteString("</ListPartsResult>")
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, b.String())

	case r.Method == http.MethodPost && q.Get("uploadId") != "":
		var body struct {
			Parts []struct {
				PartNumber int    `xml:"PartNumber"`
				ETag       string `xml:"ETag"`
			} `xml:"Part"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := xml.Unmarshal(raw, &body); err != nil || len(body.Parts) == 0 {
			writeErr(w, http.StatusBadRequest, "MalformedXML")
			return
		}
		f.mu.Lock()
		u := f.uploads[q.Get("uploadId")]
		if u == nil || u.key != path {
			f.mu.Unlock()
			writeErr(w, http.StatusNotFound, "NoSuchUpload")
			return
		}
		var all bytes.Buffer
		last := 0
		for _, p := range body.Parts {
			data, ok := u.parts[p.PartNumber]
			if !ok || p.PartNumber <= last || etagOf(data) != p.ETag {
				f.mu.Unlock()
				writeErr(w, http.StatusBadRequest, "InvalidPart")
				return
			}
			last = p.PartNumber
			all.Write(data)
		}
		f.objects[path] = object{data: all.Bytes(), etag: etagOf(all.Bytes())}
		delete(f.uploads, q.Get("uploadId"))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, "<CompleteMultipartUploadResult><ETag>x</ETag></CompleteMultipartUploadResult>")

	case r.Method == http.MethodDelete && q.Get("uploadId") != "":
		f.mu.Lock()
		delete(f.uploads, q.Get("uploadId"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPut:
		if r.Header.Get("If-None-Match") == "*" {
			f.mu.Lock()
			_, exists := f.objects[path]
			f.mu.Unlock()
			if exists {
				writeErr(w, http.StatusPreconditionFailed, "PreconditionFailed")
				return
			}
		}
		data, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.objects[path] = object{data: data, contentType: r.Header.Get("Content-Type"), etag: etagOf(data)}
		f.mu.Unlock()
		w.Header().Set("ETag", etagOf(data))

	case r.Method == http.MethodDelete:
		f.mu.Lock()
		delete(f.objects, path)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		f.mu.Lock()
		obj, exists := f.objects[path]
		f.mu.Unlock()
		if !exists {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeErr(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		data := obj.data
		ct := obj.contentType
		if v := q.Get("response-content-type"); v != "" {
			ct = v
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		w.Header().Set("Content-Type", ct)
		if v := q.Get("response-content-disposition"); v != "" {
			w.Header().Set("Content-Disposition", v)
		}
		w.Header().Set("ETag", obj.etag)
		status := http.StatusOK
		if rg := r.Header.Get("Range"); strings.HasPrefix(rg, "bytes=") {
			a, b, _ := strings.Cut(strings.TrimPrefix(rg, "bytes="), "-")
			start, err1 := strconv.Atoi(a)
			end, err2 := strconv.Atoi(b)
			if err1 == nil && err2 == nil && start <= end && start < len(data) {
				if end >= len(data) {
					end = len(data) - 1
				}
				data = data[start : end+1]
				status = http.StatusPartialContent
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(status)
		if r.Method == http.MethodGet {
			w.Write(data)
		}

	default:
		writeErr(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}
