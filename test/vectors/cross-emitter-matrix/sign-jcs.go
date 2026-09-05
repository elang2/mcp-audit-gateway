// Cross-emitter matrix — Go signer (JCS RFC 8785 variant).
// Reads a record (JSON) from stdin; writes {canonical, signature_hex} to stdout.
// Uses RFC 8785 JCS canonical form instead of the tuple-array construction.
//
// JCS library: github.com/gowebpki/jcs v1.0.1
// (RFC 8785 reference-vector conformant; source: https://github.com/gowebpki/jcs).
//
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
// Daemon protocol: DAEMON_MODE=1 → newline-delimited id-envelope requests
// {"id":"<opaque>","record":<object>} on stdin; one JSON response per line on
// stdout — {"id":..., "ok":true, "canonical":..., "signature_hex":...} on
// success, {"id":..., "ok":false, "error":"..."} on failure — one response per
// request line, always. Keeps process warm across records.
//
// Build+run:  go run sign-jcs.go                     (one-shot, reads JSON on stdin)
//             DAEMON_MODE=1 go run sign-jcs.go       (newline-delimited streaming)

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/gowebpki/jcs"
)

// Fallback id-extraction regex used only when json.Unmarshal on the envelope
// fails, so the caller can still correlate the {"ok":false} rejection line.
var idRegex = regexp.MustCompile(`"id"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))`)

func signOne(raw []byte, priv ed25519.PrivateKey) (string, string, error) {
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", "", fmt.Errorf("jcs transform: %w", err)
	}
	sig := ed25519.Sign(priv, canonical)
	return string(canonical), hex.EncodeToString(sig), nil
}

func extractIDFallback(line []byte) interface{} {
	m := idRegex.FindSubmatch(line)
	if m == nil {
		return nil
	}
	if m[1] != nil {
		// Quoted string branch — round-trip through json.Unmarshal to unescape.
		var s string
		buf := make([]byte, 0, len(m[1])+2)
		buf = append(buf, '"')
		buf = append(buf, m[1]...)
		buf = append(buf, '"')
		if err := json.Unmarshal(buf, &s); err == nil {
			return s
		}
		return string(m[1])
	}
	if m[2] != nil {
		var n interface{}
		if err := json.Unmarshal(m[2], &n); err == nil {
			return n
		}
		return string(m[2])
	}
	return nil
}

func loadPrivKey() (ed25519.PrivateKey, error) {
	keyHex := os.Getenv("SIGNING_KEY_HEX")
	if keyHex == "" {
		return nil, fmt.Errorf("SIGNING_KEY_HEX required")
	}
	seed, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func pinEnv() {
	// Only set if missing — don't override the driver's choices.
	if os.Getenv("LC_ALL") == "" {
		os.Setenv("LC_ALL", "C.UTF-8")
	}
	if os.Getenv("PYTHONIOENCODING") == "" {
		os.Setenv("PYTHONIOENCODING", "utf-8")
	}
}

func runOneShot(priv ed25519.PrivateKey) {
	// One-shot mode: single record on stdin, single JSON object on stdout (no trailing newline).
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	canonical, sigHex, err := signOne(raw, priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, _ := json.Marshal(map[string]string{
		"canonical":     canonical,
		"signature_hex": sigHex,
	})
	os.Stdout.Write(b)
}

func runDaemon(priv ed25519.PrivateKey) {
	pinEnv()

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	writeResp := func(resp map[string]interface{}) {
		b, err := json.Marshal(resp)
		if err != nil {
			// Last-resort minimal error line so the caller always sees exactly one response.
			b, _ = json.Marshal(map[string]interface{}{
				"id":    resp["id"],
				"ok":    false,
				"error": "marshal_failed",
			})
		}
		writer.Write(b)
		writer.WriteByte('\n')
		writer.Flush()
	}

	for {
		line, err := reader.ReadBytes('\n')
		trimmed := bytes.TrimRight(line, "\r\n")

		if len(trimmed) > 0 {
			// Parse the id-envelope; keep `record` as raw JSON bytes so we can
			// feed them straight to jcs.Transform (byte-identical to one-shot).
			var req struct {
				ID     json.RawMessage `json:"id"`
				Record json.RawMessage `json:"record"`
			}
			var reqID interface{}
			if uerr := json.Unmarshal(trimmed, &req); uerr != nil {
				reqID = extractIDFallback(trimmed)
				writeResp(map[string]interface{}{
					"id":    reqID,
					"ok":    false,
					"error": "parse_error: " + uerr.Error(),
				})
			} else {
				if len(req.ID) > 0 {
					_ = json.Unmarshal(req.ID, &reqID)
				}
				if len(req.Record) == 0 {
					writeResp(map[string]interface{}{
						"id":    reqID,
						"ok":    false,
						"error": "missing record",
					})
				} else {
					canonical, sigHex, cerr := signOne(req.Record, priv)
					if cerr != nil {
						writeResp(map[string]interface{}{
							"id":    reqID,
							"ok":    false,
							"error": cerr.Error(),
						})
					} else {
						writeResp(map[string]interface{}{
							"id":            reqID,
							"ok":            true,
							"canonical":     canonical,
							"signature_hex": sigHex,
						})
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				return
			}
			fmt.Fprintln(os.Stderr, "read error:", err)
			return
		}
	}
}

func main() {
	priv, err := loadPrivKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if os.Getenv("DAEMON_MODE") == "1" {
		runDaemon(priv)
		return
	}
	runOneShot(priv)
}
