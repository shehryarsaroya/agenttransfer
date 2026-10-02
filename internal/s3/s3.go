// Package s3 is a small S3-compatible object client: AWS Signature Version 4
// (header and presigned query forms) plus the handful of operations
// AgentTransfer's blob store needs — put, get, head, delete, multipart upload,
// and presigned GET/PUT/UploadPart URLs. It targets Cloudflare R2 (region
// "auto", path-style addressing) but speaks plain S3, so MinIO or AWS work too.
//
// Payloads are sent as UNSIGNED-PAYLOAD (allowed over HTTPS) so a streamed body
// is hashed once, by the caller that needs the sha256 anyway.
package s3

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound is returned when an object (or multipart upload) does not exist.
var ErrNotFound = errors.New("s3: not found")

// ErrPreconditionFailed is returned when a conditional write lost (412).
var ErrPreconditionFailed = errors.New("s3: precondition failed")

const (
	unsignedPayload = "UNSIGNED-PAYLOAD"
	emptySHA256     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	maxPresign      = 7 * 24 * time.Hour
)

// Client talks to one bucket.
type Client struct {
	// Endpoint is the service origin, e.g. https://<account>.r2.cloudflarestorage.com.
	Endpoint string
	// Region is "auto" for R2.
	Region    string
	AccessKey string
	SecretKey string
	Bucket    string
	// HTTP is the transport; nil uses a client without a global timeout
	// (object bodies may stream for a long time — use contexts instead).
	HTTP *http.Client
	// now is overridable in tests.
	now func() time.Time
}

// Part identifies one uploaded part for CompleteMultipartUpload.
type Part struct {
	Number int    `json:"part_number"`
	ETag   string `json:"etag"`
}

// Error is a non-success S3 response.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("s3: %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("s3: HTTP %d", e.Status)
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) region() string {
	if c.Region == "" {
		return "auto"
	}
	return c.Region
}

// ObjectURL is the path-style URL of key (no query, no signature).
func (c *Client) ObjectURL(key string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(c.Endpoint, "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("s3: endpoint %q must be an absolute URL", c.Endpoint)
	}
	u.Path = "/" + c.Bucket + "/" + key
	u.RawPath = ""
	return u, nil
}

// ---- Signature Version 4 ----

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// uriEncode implements SigV4 URI encoding: every byte except the unreserved
// set is percent-encoded; '/' is kept when encodeSlash is false (object paths).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' || (ch == '/' && !encodeSlash) {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k, true)+"="+uriEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

func (c *Client) signingKey(date string) []byte {
	k := hmacSHA256([]byte("AWS4"+c.SecretKey), date)
	k = hmacSHA256(k, c.region())
	k = hmacSHA256(k, "s3")
	return hmacSHA256(k, "aws4_request")
}

// signature computes the SigV4 signature over a canonical request built from
// method, URL path, query (without X-Amz-Signature), the given lowercase
// header map, and the payload hash.
func (c *Client) signature(method string, u *url.URL, query url.Values, headers map[string]string, payloadHash string, t time.Time) (sig, signedHeaders string) {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k)
		ch.WriteByte(':')
		ch.WriteString(strings.Join(strings.Fields(headers[k]), " "))
		ch.WriteByte('\n')
	}
	signedHeaders = strings.Join(names, ";")
	path := u.Path
	if path == "" {
		path = "/"
	}
	creq := strings.Join([]string{
		method,
		uriEncode(path, false),
		canonicalQuery(query),
		ch.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	date := t.Format("20060102")
	scope := date + "/" + c.region() + "/s3/aws4_request"
	sts := strings.Join([]string{"AWS4-HMAC-SHA256", t.Format("20060102T150405Z"), scope, sha256Hex([]byte(creq))}, "\n")
	return hex.EncodeToString(hmacSHA256(c.signingKey(date), sts)), signedHeaders
}

// signRequest adds header-based SigV4 auth to req. extra headers already on
// req that start with x-amz- (and Content-Type/Range/If-* when present) are
// signed too.
func (c *Client) signRequest(req *http.Request, payloadHash string) {
	t := c.clock()
	amzDate := t.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	headers := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "content-type" || lk == "content-md5" ||
			lk == "range" || strings.HasPrefix(lk, "if-") {
			headers[lk] = strings.Join(v, ",")
		}
	}
	sig, signed := c.signature(req.Method, req.URL, req.URL.Query(), headers, payloadHash, t)
	scope := t.Format("20060102") + "/" + c.region() + "/s3/aws4_request"
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, scope, signed, sig))
}

// Presign returns a query-signed URL for method on key, valid for expires
// (clamped to S3's 7-day maximum). params are extra query parameters to sign
// (e.g. partNumber/uploadId, response-content-disposition). signedHeaders are
// headers the eventual caller MUST send with exactly these values (lowercase
// names); host is always signed.
func (c *Client) Presign(method, key string, expires time.Duration, params url.Values, signedHeaders map[string]string) (string, error) {
	if expires <= 0 {
		return "", errors.New("s3: presign expiry must be positive")
	}
	if expires > maxPresign {
		expires = maxPresign
	}
	u, err := c.ObjectURL(key)
	if err != nil {
		return "", err
	}
	t := c.clock()
	q := url.Values{}
	for k, v := range params {
		q[k] = append([]string(nil), v...)
	}
	headers := map[string]string{"host": u.Host}
	for k, v := range signedHeaders {
		headers[strings.ToLower(k)] = v
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", c.AccessKey+"/"+t.Format("20060102")+"/"+c.region()+"/s3/aws4_request")
	q.Set("X-Amz-Date", t.Format("20060102T150405Z"))
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires/time.Second)))
	q.Set("X-Amz-SignedHeaders", strings.Join(names, ";"))
	sig, _ := c.signature(method, u, q, headers, unsignedPayload, t)
	u.RawQuery = canonicalQuery(q) + "&X-Amz-Signature=" + sig
	return u.String(), nil
}

// ---- operations ----

func (c *Client) do(ctx context.Context, method, key string, query url.Values, body io.Reader, size int64, hdr http.Header) (*http.Response, error) {
	u, err := c.ObjectURL(key)
	if err != nil {
		return nil, err
	}
	if len(query) > 0 {
		u.RawQuery = canonicalQuery(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.ContentLength = size
	}
	payloadHash := unsignedPayload
	if body == nil {
		payloadHash = emptySHA256
	}
	c.signRequest(req, payloadHash)
	return c.httpClient().Do(req)
}

func readError(resp *http.Response) error {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var x struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	_ = xml.Unmarshal(raw, &x)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return fmt.Errorf("%w (%s)", ErrNotFound, strings.TrimSpace(x.Code))
	case http.StatusPreconditionFailed:
		return ErrPreconditionFailed
	}
	return &Error{Status: resp.StatusCode, Code: x.Code, Message: x.Message}
}

// PutObject uploads size bytes from body to key in one request.
func (c *Client) PutObject(ctx context.Context, key string, body io.Reader, size int64, contentType string) (etag string, err error) {
	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}
	if body == nil {
		body = bytes.NewReader(nil)
	}
	resp, err := c.do(ctx, http.MethodPut, key, nil, body, size, hdr)
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", readError(resp)
	}
	resp.Body.Close()
	return resp.Header.Get("ETag"), nil
}

// ObjectInfo is what HEAD reports.
type ObjectInfo struct {
	Size        int64
	ETag        string
	ContentType string
}

// HeadObject returns the object's size and ETag, or ErrNotFound.
func (c *Client) HeadObject(ctx context.Context, key string) (ObjectInfo, error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, nil, 0, nil)
	if err != nil {
		return ObjectInfo{}, err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ObjectInfo{}, ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		return ObjectInfo{}, &Error{Status: resp.StatusCode}
	}
	return ObjectInfo{Size: resp.ContentLength, ETag: resp.Header.Get("ETag"), ContentType: resp.Header.Get("Content-Type")}, nil
}

// GetObject streams the object (optionally a "bytes=a-b" range). The caller
// closes the body.
func (c *Client) GetObject(ctx context.Context, key, rangeSpec string) (io.ReadCloser, int64, error) {
	hdr := http.Header{}
	if rangeSpec != "" {
		hdr.Set("Range", rangeSpec)
	}
	resp, err := c.do(ctx, http.MethodGet, key, nil, nil, 0, hdr)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, 0, readError(resp)
	}
	return resp.Body, resp.ContentLength, nil
}

// DeleteObject removes key. Deleting a missing key succeeds (S3 semantics).
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, nil, 0, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return readError(resp)
	}
	resp.Body.Close()
	return nil
}

// CreateMultipartUpload starts a multipart upload and returns its id.
func (c *Client) CreateMultipartUpload(ctx context.Context, key, contentType string) (string, error) {
	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}
	resp, err := c.do(ctx, http.MethodPost, key, url.Values{"uploads": {""}}, nil, 0, hdr)
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", readError(resp)
	}
	defer resp.Body.Close()
	var x struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&x); err != nil {
		return "", fmt.Errorf("s3: decode CreateMultipartUpload: %w", err)
	}
	if x.UploadID == "" {
		return "", errors.New("s3: CreateMultipartUpload returned no UploadId")
	}
	return x.UploadID, nil
}

// UploadPart uploads one part (1-based) and returns its ETag.
func (c *Client) UploadPart(ctx context.Context, key, uploadID string, number int, body io.Reader, size int64) (string, error) {
	q := url.Values{"partNumber": {strconv.Itoa(number)}, "uploadId": {uploadID}}
	resp, err := c.do(ctx, http.MethodPut, key, q, body, size, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", readError(resp)
	}
	resp.Body.Close()
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return "", errors.New("s3: UploadPart returned no ETag")
	}
	return etag, nil
}

type completePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

type completeBody struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []completePart `xml:"Part"`
}

// CompleteMultipartUpload assembles the parts (sorted by number).
func (c *Client) CompleteMultipartUpload(ctx context.Context, key, uploadID string, parts []Part) error {
	if len(parts) == 0 {
		return errors.New("s3: complete needs at least one part")
	}
	sorted := append([]Part(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Number < sorted[j].Number })
	body := completeBody{}
	for _, p := range sorted {
		etag := p.ETag
		if !strings.HasPrefix(etag, `"`) {
			etag = `"` + etag + `"`
		}
		body.Parts = append(body.Parts, completePart{PartNumber: p.Number, ETag: etag})
	}
	raw, err := xml.Marshal(body)
	if err != nil {
		return err
	}
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/xml")
	resp, err := c.do(ctx, http.MethodPost, key, url.Values{"uploadId": {uploadID}}, bytes.NewReader(raw), int64(len(raw)), hdr)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return readError(resp)
	}
	defer resp.Body.Close()
	// S3 can report an error inside a 200 body for Complete.
	raw, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var e struct {
		XMLName xml.Name
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(raw, &e) == nil && e.XMLName.Local == "Error" {
		return &Error{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
	}
	return nil
}

// AbortMultipartUpload discards an unfinished upload. A missing upload is not
// an error.
func (c *Client) AbortMultipartUpload(ctx context.Context, key, uploadID string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, url.Values{"uploadId": {uploadID}}, nil, 0, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return readError(resp)
	}
	resp.Body.Close()
	return nil
}

// UploadedPart is one part reported by ListParts.
type UploadedPart struct {
	Number int    `json:"part_number"`
	ETag   string `json:"etag"`
	Size   int64  `json:"size"`
}

// ListParts lists the parts already uploaded for uploadID (so clients can
// resume). It follows pagination.
func (c *Client) ListParts(ctx context.Context, key, uploadID string) ([]UploadedPart, error) {
	var out []UploadedPart
	marker := ""
	for page := 0; page < 20; page++ {
		q := url.Values{"uploadId": {uploadID}, "max-parts": {"1000"}}
		if marker != "" {
			q.Set("part-number-marker", marker)
		}
		resp, err := c.do(ctx, http.MethodGet, key, q, nil, 0, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 != 2 {
			return nil, readError(resp)
		}
		var x struct {
			IsTruncated          bool   `xml:"IsTruncated"`
			NextPartNumberMarker string `xml:"NextPartNumberMarker"`
			Parts                []struct {
				PartNumber int    `xml:"PartNumber"`
				ETag       string `xml:"ETag"`
				Size       int64  `xml:"Size"`
			} `xml:"Part"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&x)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("s3: decode ListParts: %w", err)
		}
		for _, p := range x.Parts {
			out = append(out, UploadedPart{Number: p.PartNumber, ETag: p.ETag, Size: p.Size})
		}
		if !x.IsTruncated || x.NextPartNumberMarker == "" {
			return out, nil
		}
		marker = x.NextPartNumberMarker
	}
	return out, nil
}

// PresignGet returns a short-lived download URL. disposition/contentType, when
// set, are applied by the store via response-content-* overrides so the
// browser saves the file under its folder name.
func (c *Client) PresignGet(key string, expires time.Duration, disposition, contentType string) (string, error) {
	q := url.Values{}
	if disposition != "" {
		q.Set("response-content-disposition", disposition)
	}
	if contentType != "" {
		q.Set("response-content-type", contentType)
	}
	return c.Presign(http.MethodGet, key, expires, q, nil)
}

// PresignPut returns a URL that accepts one PUT of the object body.
func (c *Client) PresignPut(key string, expires time.Duration) (string, error) {
	return c.Presign(http.MethodPut, key, expires, nil, nil)
}

// PresignUploadPart returns a URL that accepts one PUT of part number.
func (c *Client) PresignUploadPart(key, uploadID string, number int, expires time.Duration) (string, error) {
	q := url.Values{"partNumber": {strconv.Itoa(number)}, "uploadId": {uploadID}}
	return c.Presign(http.MethodPut, key, expires, q, nil)
}
