#!/usr/bin/env ruby
# Cross-emitter matrix — Ruby JCS (RFC 8785) signer.
#
# Uses the `json-canonicalization` gem (dryruby/json-canonicalization, RubyGems).
# The gem's `to_json_c14n` is byte-identical to the cyberphone RFC 8785 reference
# vectors across all 6 testdata files (arrays, french, structures, unicode,
# values, weird) — verified by the byte-identity check in the return summary
# of the runner-dispatch change that introduced this file.
#
# This variant emits RFC 8785 canonical bytes rather than the tuple-array form.
# Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
#
# ---------------------------------------------------------------------------
# Daemon protocol (must match the wire contract in fuzzing/fuzz-runner.mjs):
# ---------------------------------------------------------------------------
#   Startup env: DAEMON_MODE=1
#                CANONICAL_FORM=jcs           (informational; algorithm is fixed)
#                SIGNING_KEY_HEX=<64 hex chars>
#
#   Request  (one NDJSON line per record on stdin):
#       {"id": "<opaque-string>", "record": <object>}
#
#   Response (one NDJSON line per request on stdout, flushed):
#       {"id": "<same-id>", "ok": true,  "canonical": "<str>", "signature_hex": "<hex>"}
#     — or —
#       {"id": "<same-id>", "ok": false, "error": "<short-string>"}
#
# One-shot mode (DAEMON_MODE unset): reads a single record on stdin, writes
# a single JSON object (canonical + signature_hex) to stdout.

# User-installed gems (Ruby 2.6 system interpreter on macOS).
$LOAD_PATH.unshift(File.join(Dir.home, '.gem/ruby/2.6.0/gems/ed25519-1.3.0/lib'))
$LOAD_PATH.unshift(File.join(Dir.home, '.gem/ruby/2.6.0/gems/json-canonicalization-0.4.0/lib'))
require 'ed25519'
require 'json'
require 'json/canonicalization'

# We keep the same "drop null optionals" convention that the tuple-array signer
# uses so the JCS variant is semantically comparable on the same record. JCS
# then re-orders all keys itself (lexicographic by UTF-16 code units), so
# FIELD_REQUIRED order below is *not* relied on for canonical bytes — only for
# the "which optional keys to omit if null" decision.
FIELD_REQUIRED = %w[
  id timestamp method toolName namespace upstream
  principal durationMs success errorCode previousHash
].freeze
FIELD_OPTIONAL = %w[decisionContextDigest extensionsDigest aiInvocation parties].freeze

def build_record(record)
  out = {}
  FIELD_REQUIRED.each { |k| out[k] = record[k] }
  FIELD_OPTIONAL.each { |k| out[k] = record[k] unless record[k].nil? }
  out
end

def canonicalize(record)
  build_record(record).to_json_c14n
end

key_hex = ENV['SIGNING_KEY_HEX']
abort 'SIGNING_KEY_HEX required' if key_hex.nil? || key_hex.empty?
signing_key = Ed25519::SigningKey.new([key_hex].pack('H*'))

if ENV['DAEMON_MODE'] == '1'
  # Env pinning: fall back to UTF-8 where the driver did not already set it.
  ENV['LC_ALL'] ||= 'C.UTF-8'
  ENV['PYTHONIOENCODING'] ||= 'utf-8'
  STDIN.set_encoding('UTF-8')
  STDOUT.set_encoding('UTF-8')

  STDIN.each_line do |line|
    line = line.strip
    next if line.empty?

    # Extract id via regex on the RAW line BEFORE JSON.parse. The line may
    # contain lone surrogates (or other pathological bytes) that break
    # JSON.parse itself, in which case req['id'] would be unreachable and
    # the response would either drop entirely (breaking
    # response_count == request_count) or emit id:null (breaking id
    # correlation). The regex fallback preserves correlation even when the
    # JSON is unparseable. Note: String#match itself raises on invalid
    # UTF-8 bytes, so scrub a copy first — we still leave `line` untouched
    # for JSON.parse so it can fail authentically on the bad input.
    id_from_regex = nil
    begin
      safe_line = line.dup.force_encoding('UTF-8').scrub('?')
      id_match = safe_line.match(/"id"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))/)
      id_from_regex = id_match ? (id_match[1] || id_match[2]) : nil
    rescue
      id_from_regex = nil
    end

    begin
      req = JSON.parse(line)
      id = req['id']
      record = req['record']
      canonical = canonicalize(record)
      sig = signing_key.sign(canonical)
      STDOUT.puts JSON.generate({
        'id' => id,
        'ok' => true,
        'canonical' => canonical,
        'signature_hex' => sig.unpack('H*').first
      })
      STDOUT.flush
    rescue Exception => e
      # Paranoid catch: any Exception subclass (StandardError, ScriptError,
      # and SystemExit-family) is normalized into a single well-formed
      # response line so the driver's response_count == request_count
      # invariant holds. The fact-of-rejection (ok:false) is the scientific
      # signal — preserve it; only the message bytes are sanitized.
      raw_msg = (e.message rescue 'unknown').to_s
      sanitized_msg = begin
        raw_msg.dup.force_encoding('UTF-8').scrub('?')
      rescue
        begin
          raw_msg.dup.force_encoding('UTF-8')
                 .encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
        rescue
          'unencodable_error'
        end
      end
      begin
        STDOUT.puts JSON.generate({
          'id' => id_from_regex,
          'ok' => false,
          'error' => sanitized_msg
        })
      rescue => _nested
        # Absolute last resort: hand-built JSON line so the driver still
        # sees the rejection tag and id correlation for this request.
        STDOUT.puts %Q({"id":#{id_from_regex.to_json},"ok":false,"error":"internal_encode_failure"})
      end
      STDOUT.flush
      next
    end
  end
else
  record = JSON.parse(STDIN.read)
  canonical = canonicalize(record)
  sig = signing_key.sign(canonical)
  puts JSON.generate({ 'canonical' => canonical, 'signature_hex' => sig.unpack('H*').first })
end
