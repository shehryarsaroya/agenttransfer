// Package proto defines the AgentTransfer wire manifest — the machine-readable
// MIME part attached to every email an agent sends.
//
// Parts are deliberately shaped for a mechanical mapping to A2A TextPart and
// URI-backed FilePart values. The enclosing email manifest is AgentTransfer's
// own protocol; consuming it as A2A still requires an adapter. Extensions live
// under namespaced "agenttransfer.*" metadata keys.
package proto

// Filename is the attachment filename of the manifest part, for mail
// providers that only expose attachments by name.
const Filename = "agenttransfer.json"

// Version is the manifest schema version.
const Version = 1

// Manifest is the machine-parseable envelope carried alongside the
// human-readable email body.
type Manifest struct {
	V         int    `json:"v"`
	From      string `json:"from"`
	MessageID string `json:"message_id,omitempty"`
	InReplyTo string `json:"in_reply_to,omitempty"`
	Parts     []Part `json:"parts"`
}

// Part is an AgentTransfer text or URI-file part with an A2A-mappable shape.
type Part struct {
	Kind     string         `json:"kind"`
	Text     string         `json:"text,omitempty"`
	File     *FileRef       `json:"file,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// FileRef describes bytes by URI rather than embedding them in the manifest.
type FileRef struct {
	Name     string `json:"name,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
	URI      string `json:"uri"`
}

// Metadata keys for AgentTransfer extensions on file parts.
const (
	MetaSHA256    = "agenttransfer.sha256"
	MetaSize      = "agenttransfer.size"
	MetaExpiresAt = "agenttransfer.expiresAt"
	MetaOnce      = "agenttransfer.once"
	// MetaEncMode marks a client-encrypted file so a receiver knows to
	// decrypt: "symmetric" (needs the out-of-band key) or "sealed" (needs the
	// recipient's own identity). Absent/empty means plaintext. The bytes are
	// encrypted client-side; the server only relays this hint and never holds
	// a key. sha256 above is over the CIPHERTEXT, so integrity is verifiable
	// without the key.
	MetaEncMode = "agenttransfer.encMode"
)

// Encryption modes for MetaEncMode.
const (
	EncSymmetric = "symmetric"
	EncSealed    = "sealed"
)

// TextPart builds an AgentTransfer text part.
func TextPart(text string) Part { return Part{Kind: "text", Text: text} }

// FilePart builds an AgentTransfer URI-file part carrying a share link and
// integrity metadata. encMode is "" for plaintext, or proto.EncSymmetric /
// proto.EncSealed for a client-encrypted file.
func FilePart(name, mimeType, uri, sha256 string, size int64, expiresAt string, once bool, encMode string) Part {
	meta := map[string]any{
		MetaSHA256:    sha256,
		MetaSize:      size,
		MetaExpiresAt: expiresAt,
		MetaOnce:      once,
	}
	if encMode != "" {
		meta[MetaEncMode] = encMode
	}
	return Part{
		Kind:     "file",
		File:     &FileRef{Name: name, MIMEType: mimeType, URI: uri},
		Metadata: meta,
	}
}

// FirstFile returns the first file part, or nil.
func (m *Manifest) FirstFile() *Part {
	for i := range m.Parts {
		if m.Parts[i].Kind == "file" && m.Parts[i].File != nil {
			return &m.Parts[i]
		}
	}
	return nil
}

// MetaString reads a string metadata value from a part.
func (p *Part) MetaString(key string) string {
	if p.Metadata == nil {
		return ""
	}
	if v, ok := p.Metadata[key].(string); ok {
		return v
	}
	return ""
}

// MetaInt64 reads an integer metadata value from a part. JSON numbers decode
// as float64, so both are accepted.
func (p *Part) MetaInt64(key string) int64 {
	if p.Metadata == nil {
		return 0
	}
	switch v := p.Metadata[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

// MetaBool reads a boolean metadata value from a part.
func (p *Part) MetaBool(key string) bool {
	if p.Metadata == nil {
		return false
	}
	v, _ := p.Metadata[key].(bool)
	return v
}
