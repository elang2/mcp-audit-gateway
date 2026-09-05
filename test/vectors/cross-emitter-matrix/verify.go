// Cross-emitter matrix — Go verifier.
// Reads {record, signature_hex, public_key_hex} JSON from stdin.
// Locally recomputes canonical form from record, verifies signature against it.
// Writes {verified: bool, local_canonical, sig_hex} to stdout.

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

func canonicalizeValue(v interface{}) (interface{}, error) {
	if v == nil {
		return nil, nil
	}
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return x, nil
	case float64:
		i := int64(x)
		if float64(i) != x {
			return nil, fmt.Errorf("unsafe number %v", x)
		}
		if i > (1<<53)-1 || i < -(1<<53)+1 {
			return nil, fmt.Errorf("unsafe number %d", i)
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
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Compare(utf16BE(keys[i]), utf16BE(keys[j])) > 0 {
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

func pinEnv() {
	// Only set if missing — don't override the driver's choices.
	if os.Getenv("LC_ALL") == "" {
		os.Setenv("LC_ALL", "C.UTF-8")
	}
	if os.Getenv("PYTHONIOENCODING") == "" {
		os.Setenv("PYTHONIOENCODING", "utf-8")
	}
}

func runOneShot() {
	raw, _ := io.ReadAll(os.Stdin)
	var payload struct {
		Record       map[string]interface{} `json:"record"`
		SignatureHex string                 `json:"signature_hex"`
		PublicKeyHex string                 `json:"public_key_hex"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pubBytes, err := hex.DecodeString(payload.PublicKeyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sigBytes, err := hex.DecodeString(payload.SignatureHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pub := ed25519.PublicKey(pubBytes)

	canonical, err := canonicalize(payload.Record)
	verified := false
	if err == nil {
		verified = ed25519.Verify(pub, []byte(canonical), sigBytes)
	}

	out := map[string]interface{}{
		"verified":        verified,
		"local_canonical": canonical,
		"sig_hex":         payload.SignatureHex,
	}
	b, _ := json.Marshal(out)
	os.Stdout.Write(b)
}

func runDaemon() {
	pinEnv()

	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	// Cache public keys by hex string — verify.go accepts a distinct
	// public_key_hex per record so callers CAN rotate it, but in practice
	// the matrix driver reuses one key across the whole run.
	pubCache := make(map[string]ed25519.PublicKey)
	getPub := func(hexStr string) (ed25519.PublicKey, error) {
		if pub, ok := pubCache[hexStr]; ok {
			return pub, nil
		}
		pubBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, err
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad public key length %d", len(pubBytes))
		}
		pub := ed25519.PublicKey(pubBytes)
		pubCache[hexStr] = pub
		return pub, nil
	}

	writeResp := func(resp map[string]interface{}) {
		b, err := json.Marshal(resp)
		if err != nil {
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
				ID           string                 `json:"id"`
				Record       map[string]interface{} `json:"record"`
				SignatureHex string                 `json:"signature_hex"`
				PublicKeyHex string                 `json:"public_key_hex"`
			}
			if uerr := json.Unmarshal(trimmed, &req); uerr != nil {
				writeResp(map[string]interface{}{
					"id":    "",
					"ok":    false,
					"error": "parse_error: " + uerr.Error(),
				})
			} else {
				pub, perr := getPub(req.PublicKeyHex)
				if perr != nil {
					writeResp(map[string]interface{}{
						"id":    req.ID,
						"ok":    false,
						"error": "pubkey: " + perr.Error(),
					})
				} else {
					sigBytes, serr := hex.DecodeString(req.SignatureHex)
					if serr != nil {
						writeResp(map[string]interface{}{
							"id":    req.ID,
							"ok":    false,
							"error": "sig_hex: " + serr.Error(),
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
							verified := ed25519.Verify(pub, []byte(canonical), sigBytes)
							writeResp(map[string]interface{}{
								"id":              req.ID,
								"ok":              true,
								"verified":        verified,
								"local_canonical": canonical,
								"sig_hex":         req.SignatureHex,
							})
						}
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
	if os.Getenv("DAEMON_MODE") == "1" {
		runDaemon()
		return
	}
	runOneShot()
}
