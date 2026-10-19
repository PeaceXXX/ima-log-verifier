package imalog

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ParseError describes a malformed log line, always carrying the line number.
type ParseError struct {
	Line   int
	Reason string
	Text   string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line %d: %s: %q", e.Line, e.Reason, e.Text)
}

// DecodeHexBytes decodes a hex string and requires an exact byte length.
func DecodeHexBytes(s string, want int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("expected %d bytes, got %d", want, len(b))
	}
	return b, nil
}

// ParseLine parses one IMA ASCII log line:
//
//	PCRindex template-hash-hex template filedata-hash filename-hint
//
// Blank lines and lines starting with '#' are skipped (return ok=false).
func ParseLine(line string, lineno int) (e Entry, ok bool, err error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return Entry{}, false, nil
	}
	fields := strings.Fields(trimmed)
	if len(fields) != 5 {
		return Entry{}, false, &ParseError{lineno, fmt.Sprintf("expected 5 fields, got %d", len(fields)), trimmed}
	}

	pcr, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return Entry{}, false, &ParseError{lineno, "invalid PCR index: " + err.Error(), trimmed}
	}
	tmplHash, err := DecodeHexBytes(fields[1], 32)
	if err != nil {
		return Entry{}, false, &ParseError{lineno, "invalid template hash: " + err.Error(), trimmed}
	}
	fileDigest := fields[3]
	if !strings.HasPrefix(fileDigest, "sha256:") {
		return Entry{}, false, &ParseError{lineno, "file-data hash must start with 'sha256:'", trimmed}
	}
	if _, err := DecodeHexBytes(strings.TrimPrefix(fileDigest, "sha256:"), 32); err != nil {
		return Entry{}, false, &ParseError{lineno, "invalid file-data digest: " + err.Error(), trimmed}
	}

	return Entry{
		PCRIndex:     uint(pcr),
		TemplateHash: tmplHash,
		Template:     fields[2],
		FileDigest:   fileDigest,
		Path:         fields[4],
	}, true, nil
}

// Parse reads a full IMA ASCII log, skipping blanks and '#' comments.
// The first malformed line aborts parsing with its line number.
func Parse(data []byte) (Log, error) {
	var log Log
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		entry, ok, err := ParseLine(line, i+1)
		if err != nil {
			return Log{}, err
		}
		if ok {
			log.Entries = append(log.Entries, entry)
		}
	}
	return log, nil
}
