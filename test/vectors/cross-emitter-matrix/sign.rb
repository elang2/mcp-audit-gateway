#!/usr/bin/env ruby
# Cross-emitter matrix — Ruby signer.
# Uses tuple-array canonical form matching ../verify.mjs, ../verify.py.
# Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.

# Point Ruby at the user-installed ed25519 gem
$LOAD_PATH.unshift(File.join(Dir.home, '.gem/ruby/2.6.0/gems/ed25519-1.3.0/lib'))
require 'ed25519'
require 'json'

FIELD_ORDER = %w[
  id timestamp method toolName namespace upstream
  principal durationMs success errorCode previousHash
].freeze

def assert_well_formed(str)
  str.each_char.with_index do |ch, i|
    code = ch.ord
    if code >= 0xD800 && code <= 0xDFFF
      raise "unpaired surrogate at index #{i}"
    end
  end
end

def canonicalize_value(v)
  return nil if v.nil?
  case v
  when String
    assert_well_formed(v)
    v
  when TrueClass, FalseClass
    v
  when Integer
    raise "unsafe number #{v}" if v.abs > (2**53 - 1)
    v
  when Float
    raise "unsafe number #{v}"
  when Array
    ['L', v.map { |item| canonicalize_value(item) }]
  when Hash
    keys = v.keys.sort_by { |k| k.encode('UTF-16BE').bytes }
    ['M', keys.map { |k| [k, canonicalize_value(v[k])] }]
  else
    raise "unsupported type #{v.class}"
  end
end

def canonicalize(record)
  ordered = FIELD_ORDER.map { |k| [k, canonicalize_value(record[k])] }
  %w[decisionContextDigest extensionsDigest aiInvocation parties].each do |opt|
    ordered << [opt, canonicalize_value(record[opt])] unless record[opt].nil?
  end
  JSON.generate(ordered)
end

key_hex = ENV['SIGNING_KEY_HEX']
abort 'SIGNING_KEY_HEX required' if key_hex.nil? || key_hex.empty?

# Signing key is initialized once and reused across records in daemon mode.
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
