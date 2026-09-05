// Cross-emitter matrix — Swift signer.
// Uses stdlib CryptoKit for Ed25519.
// Uses tuple-array canonical form matching ../verify.mjs, ../verify.py.
// Signing key: hex-encoded 32-byte Ed25519 seed from SIGNING_KEY_HEX env var.
//
// Run: SIGNING_KEY_HEX=... swift sign.swift  (reads JSON on stdin)

import Foundation
import CryptoKit

let FIELD_ORDER = [
  "id","timestamp","method","toolName","namespace","upstream",
  "principal","durationMs","success","errorCode","previousHash"
]

func hex2bytes(_ s: String) -> Data {
    var d = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let end = s.index(i, offsetBy: 2)
        d.append(UInt8(s[i..<end], radix: 16)!)
        i = end
    }
    return d
}

func bytes2hex(_ d: Data) -> String {
    return d.map { String(format: "%02x", $0) }.joined()
}

// Sort keys lexicographically by their UTF-16BE byte representation to match JS/Java/Ruby.
func sortKeysUTF16(_ keys: [String]) -> [String] {
    return keys.sorted { a, b in
        let ua = Array(a.utf16)
        let ub = Array(b.utf16)
        let len = min(ua.count, ub.count)
        for k in 0..<len {
            if ua[k] < ub[k] { return true }
            if ua[k] > ub[k] { return false }
        }
        return ua.count < ub.count
    }
}

// Canonicalize an Any value into the tuple-array form.
// NOTE: NSNumber Bool disambiguation must come BEFORE any Bool cast, because
// Swift's ObjC bridge makes `NSNumber(0) as? Bool == false` succeed silently.
// We check CFGetTypeID first, then dispatch integer/float paths.
func canonicalizeValue(_ v: Any?) -> Any {
    if v == nil { return NSNull() }
    if let n = v as? NSNull { return n }
    if let s = v as? String { return s }
    if let n = v as? NSNumber {
        if CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue }
        let objType = String(cString: n.objCType)
        if objType == "d" || objType == "f" { fatalError("unsafe number (float) \(n)") }
        let i = n.int64Value
        precondition(abs(i) <= (1 << 53) - 1, "unsafe integer \(i)")
        return i
    }
    if let a = v as? [Any] {
        return ["L", a.map { canonicalizeValue($0) }]
    }
    if let m = v as? [String: Any] {
        let keys = sortKeysUTF16(Array(m.keys))
        let pairs: [Any] = keys.map { k in [k, canonicalizeValue(m[k] as Any)] }
        return ["M", pairs]
    }
    fatalError("unsupported type \(type(of: v!))")
}

// Serialize an Any value the way JS's JSON.stringify does (compact, no whitespace).
// JSONSerialization by default in Swift produces `[]` `{}` with no whitespace when
// no options are set, and preserves array ordering. Foundation's default matches JS.
func compactJSON(_ v: Any) -> String {
    let d = try! JSONSerialization.data(withJSONObject: v, options: [.withoutEscapingSlashes])
    return String(data: d, encoding: .utf8)!
}

func canonicalize(_ record: [String: Any]) -> String {
    var ordered: [[Any]] = FIELD_ORDER.map { k -> [Any] in
        let v = record[k] ?? NSNull()
        return [k, canonicalizeValue(v)]
    }
    for opt in ["decisionContextDigest", "extensionsDigest", "aiInvocation", "parties"] {
        if let v = record[opt], !(v is NSNull) {
            ordered.append([opt, canonicalizeValue(v)])
        }
    }
    return compactJSON(ordered)
}

// Main
guard let keyHex = ProcessInfo.processInfo.environment["SIGNING_KEY_HEX"] else {
    FileHandle.standardError.write("SIGNING_KEY_HEX required\n".data(using: .utf8)!)
    exit(1)
}
let seedData = hex2bytes(keyHex)
let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedData)

let inputData = FileHandle.standardInput.readDataToEndOfFile()
let record = try JSONSerialization.jsonObject(with: inputData) as! [String: Any]

let canonical = canonicalize(record)
let sig = try privateKey.signature(for: canonical.data(using: .utf8)!)

let out: [String: Any] = ["canonical": canonical, "signature_hex": bytes2hex(sig)]
let outData = try JSONSerialization.data(withJSONObject: out)
FileHandle.standardOutput.write(outData)
