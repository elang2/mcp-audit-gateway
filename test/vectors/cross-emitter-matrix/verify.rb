#!/usr/bin/env ruby
# Cross-emitter matrix — Ruby verifier.

$LOAD_PATH.unshift(File.join(Dir.home, '.gem/ruby/2.6.0/gems/ed25519-1.3.0/lib'))
require 'ed25519'
require 'json'

FIELD_ORDER = %w[
  id timestamp method toolName namespace upstream
  principal durationMs success errorCode previousHash
].freeze

def canonicalize_value(v)
  return nil if v.nil?
  case v
  when String then v
  when TrueClass, FalseClass then v
  when Integer
    raise "unsafe #{v}" if v.abs > (2**53 - 1)
    v
  when Array then ['L', v.map { |x| canonicalize_value(x) }]
  when Hash
    keys = v.keys.sort_by { |k| k.encode('UTF-16BE').bytes }
    ['M', keys.map { |k| [k, canonicalize_value(v[k])] }]
  else raise "unsupported #{v.class}"
  end
end

def canonicalize(record)
  ordered = FIELD_ORDER.map { |k| [k, canonicalize_value(record[k])] }
  %w[decisionContextDigest extensionsDigest aiInvocation parties].each do |opt|
    ordered << [opt, canonicalize_value(record[opt])] unless record[opt].nil?
  end
  JSON.generate(ordered)
end

if ENV['DAEMON_MODE'] == '1'
  # Env pinning: fall back to UTF-8 where the driver did not already set it.
  ENV['LC_ALL'] ||= 'C.UTF-8'
  ENV['PYTHONIOENCODING'] ||= 'utf-8'
  STDIN.set_encoding('UTF-8')
  STDOUT.set_encoding('UTF-8')

  # Reuse VerifyKey instances across records keyed by hex string.
  verify_key_cache = {}

  STDIN.each_line do |line|
    line = line.strip
    next if line.empty?

    # Extract id via regex on the RAW line BEFORE JSON.parse. If the line
    # contains bytes that break JSON.parse (lone surrogates, malformed
    # escapes), req['id'] is unreachable, so id would end up nil and either
    # collide with other nil-id responses or drop entirely. The regex
    # fallback preserves correlation for the driver's
    # response_count == request_count invariant. Note: String#match itself
    # raises on invalid UTF-8 bytes, so scrub a copy first — we leave
    # `line` untouched for JSON.parse so it fails authentically on the bad
    # input.
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
      payload = req['record']
      pk_hex = payload['public_key_hex']
      verify_key = (verify_key_cache[pk_hex] ||= Ed25519::VerifyKey.new([pk_hex].pack('H*')))

      verified = false
      canonical = nil
      begin
        canonical = canonicalize(payload['record'])
        sig_bytes = [payload['signature_hex']].pack('H*')
        verified = verify_key.verify(sig_bytes, canonical)
      rescue Ed25519::VerifyError
        verified = false
      end

      STDOUT.puts JSON.generate({
        'id' => id,
        'ok' => verified,
        'verified' => verified,
        'local_canonical' => canonical,
        'sig_hex' => payload['signature_hex']
      })
      STDOUT.flush
    rescue Exception => e
      # Paranoid catch: any Exception subclass is normalized into a single
      # well-formed response line so the driver's
      # response_count == request_count invariant holds. The fact-of-
      # rejection (ok:false) is the scientific signal — preserve it; only
      # sanitize the message bytes.
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
        STDOUT.puts JSON.generate({ 'id' => id_from_regex, 'ok' => false, 'error' => sanitized_msg })
      rescue => _nested
        # Last-resort hand-built JSON so the driver still sees the rejection.
        STDOUT.puts %Q({"id":#{id_from_regex.to_json},"ok":false,"error":"internal_encode_failure"})
      end
      STDOUT.flush
      next
    end
  end
else
  payload = JSON.parse(STDIN.read)
  verify_key = Ed25519::VerifyKey.new([payload['public_key_hex']].pack('H*'))

  verified = false
  canonical = nil
  begin
    canonical = canonicalize(payload['record'])
    sig_bytes = [payload['signature_hex']].pack('H*')
    verified = verify_key.verify(sig_bytes, canonical)
  rescue Ed25519::VerifyError
    verified = false
  rescue => e
    verified = false
    canonical = "ERROR: #{e.message}"
  end

  puts JSON.generate({ 'verified' => verified, 'local_canonical' => canonical, 'sig_hex' => payload['signature_hex'] })
end
