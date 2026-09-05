// Cross-emitter matrix — Swift verifier.
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

func compactJSON(_ v: Any) -> String {
    let d = try! JSONSerialization.data(withJSONObject: v, options: [.withoutEscapingSlashes])
    return String(data: d, encoding: .utf8)!
}

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

func canonicalizeValue(_ v: Any?) -> Any {
    if v == nil { return NSNull() }
    if let n = v as? NSNull { return n }
    if let s = v as? String { return s }
    if let n = v as? NSNumber {
        if CFGetTypeID(n) == CFBooleanGetTypeID() { return n.boolValue }
        let objType = String(cString: n.objCType)
        if objType == "d" || objType == "f" { fatalError("unsafe float \(n)") }
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

let inputData = FileHandle.standardInput.readDataToEndOfFile()
let payload = try JSONSerialization.jsonObject(with: inputData) as! [String: Any]
let record = payload["record"] as! [String: Any]
let sigHex = payload["signature_hex"] as! String
let pubHex = payload["public_key_hex"] as! String

let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: hex2bytes(pubHex))
let sig = hex2bytes(sigHex)

var verified = false
var canonical: String? = nil
do {
    canonical = canonicalize(record)
    verified = pubKey.isValidSignature(sig, for: canonical!.data(using: .utf8)!)
} catch {
    canonical = "ERROR: \(error)"
}

let out: [String: Any] = [
    "verified": verified,
    "local_canonical": canonical ?? "null",
    "sig_hex": sigHex,
]
let outData = try JSONSerialization.data(withJSONObject: out)
FileHandle.standardOutput.write(outData)
