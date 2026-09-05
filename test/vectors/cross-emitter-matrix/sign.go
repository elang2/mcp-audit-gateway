// Cross-emitter matrix — Go signer.
// Reads a record (JSON) from stdin; writes {canonical, signature_hex} to stdout.
// Uses tuple-array canonical form matching ../verify.mjs, ../verify.py.
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
//
// Build+run:  go run sign.go   (reads JSON on stdin)

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
	"unicode/utf16"
)

var fieldOrder = []string{
	"id", "timestamp", "method", "toolName", "namespace", "upstream",
	"principal", "durationMs", "success", "errorCode", "previousHash",
}

func assertWellFormed(s string) error {
	for i, r := range s {
		if r == 0xFFFD {
			return fmt.Errorf("replacement character at index %d", i)
		}
	}
	return nil
}

func canonicalizeValue(v interface{}) (interface{}, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case string:
		if err := assertWellFormed(x); err != nil {
			return nil, err
		}
		return x, nil
	case bool:
		return x, nil
	case float64:
		// Unsafe integer check
		i := int64(x)
		if float64(i) != x {
			return nil, fmt.Errorf("unsafe number %v (not an integer)", x)
		}
		if i > (1<<53)-1 || i < -(1<<53)+1 {
			return nil, fmt.Errorf("unsafe number %d (out of safe integer range)", i)
		}
		return i, nil
	case []interface{}:
		result := make([]interface{}, len(x))
		for idx, item := range x {
			cv, err := canonicalizeValue(item)
			if err != nil {
				return nil, err
			}
			result[idx] = cv
		}
		return []interface{}{"L", result}, nil
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Sort by UTF-16 BE code units to match JS
		sortKeysUTF16(keys)
		pairs := make([][]interface{}, 0, len(keys))
		for _, k := range keys {
			cv, err := canonicalizeValue(x[k])
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, []interface{}{k, cv})
		}
		return []interface{}{"M", pairs}, nil
	}
	return nil, fmt.Errorf("unsupported type %T", v)
}

func sortKeysUTF16(keys []string) {
	// Simple bubble sort by UTF-16 BE bytes (small N)
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			a := utf16BE(keys[i])
			b := utf16BE(keys[j])
			if bytes.Compare(a, b) > 0 {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
}

func utf16BE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		buf = append(buf, byte(r>>8), byte(r&0xff))
	}
	return buf
}

func canonicalize(record map[string]interface{}) (string, error) {
	ordered := make([][]interface{}, 0, len(fieldOrder))
	for _, k := range fieldOrder {
		v, ok := record[k]
		if !ok {
			v = nil
		}
		cv, err := canonicalizeValue(v)
		if err != nil {
			return "", err
		}
		ordered = append(ordered, []interface{}{k, cv})
	}
	for _, opt := range []string{"decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"} {
		if v, ok := record[opt]; ok && v != nil {
			cv, err := canonicalizeValue(v)
			if err != nil {
				return "", err
			}
			ordered = append(ordered, []interface{}{opt, cv})
		}
	}
	b, err := json.Marshal(ordered)
	if err != nil {
		return "", err
	}
	return string(b), nil
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
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var record map[string]interface{}
	if err := json.Unmarshal(raw, &record); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	canonical, err := canonicalize(record)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sig := ed25519.Sign(priv, []byte(canonical))

	out := map[string]string{
		"canonical":     canonical,
		"signature_hex": hex.EncodeToString(sig),
	}
	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
}

func runDaemon(priv ed25519.PrivateKey) {
	pinEnv()

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	writeResp := func(resp map[string]interface{}) {
		b, err := json.Marshal(resp)
		if err != nil {
			// Fallback: emit a minimal error line for this id.
			id, _ := resp["id"].(string)
			b, _ = json.Marshal(map[string]interface{}{
				"id":    id,
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
			var req struct {
				ID     string                 `json:"id"`
				Record map[string]interface{} `json:"record"`
			}
			if uerr := json.Unmarshal(trimmed, &req); uerr != nil {
				writeResp(map[string]interface{}{
					"id":    "",
					"ok":    false,
					"error": "parse_error: " + uerr.Error(),
				})
			} else {
				canonical, cerr := canonicalize(req.Record)
				if cerr != nil {
					writeResp(map[string]interface{}{
						"id":    req.ID,
						"ok":    false,
						"error": cerr.Error(),
					})
				} else {
					sig := ed25519.Sign(priv, []byte(canonical))
					writeResp(map[string]interface{}{
						"id":            req.ID,
						"ok":            true,
						"canonical":     canonical,
						"signature_hex": hex.EncodeToString(sig),
					})
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
