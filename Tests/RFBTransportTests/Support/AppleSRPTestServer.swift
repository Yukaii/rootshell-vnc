import Foundation
import BigInt
import CryptoKit
@testable import RFBTransport

func hexData(_ string: String) -> Data {
    var data = Data()
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        data.append(UInt8(string[index..<next], radix: 16)!)
        index = next
    }
    return data
}

func srpSHA512(_ parts: Data...) -> Data {
    var hasher = SHA512()
    for part in parts { hasher.update(data: part) }
    return Data(hasher.finalize())
}

/// Server half of the type 36 SRP-6a profile (RFC 5054 2048-bit group, g = 2).
struct TestSRPServer: Sendable {
    static let modulus = BigUInt(
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13D"
            + "D52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
            + "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481"
            + "F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
            + "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F5475"
            + "9B65E372FCD68EF20FA7111F9E4AFF73",
        radix: 16)!
    static let generator = BigUInt(2)

    let salt: Data
    let iterations: UInt64
    let verifier: BigUInt
    let b: BigUInt
    let publicKey: BigUInt

    static func exponent(salt: Data, stretchedPassword: Data) -> BigUInt {
        BigUInt(srpSHA512(salt, srpSHA512(Data([0x3A]), stretchedPassword)))
    }

    static func pad(_ value: BigUInt) -> Data {
        let bytes = value.serialize()
        return Data(count: 256 - bytes.count) + bytes
    }

    init(salt: Data, x: BigUInt, b: Data, iterations: UInt64 = 1) {
        let n = Self.modulus
        self.salt = salt
        self.iterations = iterations
        self.verifier = Self.generator.power(x, modulus: n)
        self.b = BigUInt(b)
        let k = BigUInt(srpSHA512(n.serialize(), Self.pad(Self.generator)))
        self.publicKey = (k * verifier + Self.generator.power(self.b, modulus: n)) % n
    }

    init(password: String, iterations: UInt32) throws {
        let salt = Data((0..<16).map { UInt8($0 * 7) })
        let stretched = try AppleSRPClient.pbkdf2HMACSHA512(
            key: Data(password.utf8), salt: salt, iterations: iterations, keyLength: 128)
        self.init(
            salt: salt,
            x: Self.exponent(salt: salt, stretchedPassword: stretched),
            b: Data((0..<64).map { UInt8(255 - $0) }),
            iterations: UInt64(iterations))
    }

    func verify(a aBytes: Data, m1: Data) -> (key: Data, m2: Data)? {
        let n = Self.modulus
        let a = BigUInt(aBytes)
        let paddedA = Self.pad(a)
        let paddedB = Self.pad(publicKey)
        let u = BigUInt(srpSHA512(paddedA, paddedB))
        let s = (a * verifier.power(u, modulus: n)).power(b, modulus: n)
        let key = srpSHA512(Self.pad(s))
        let hn = srpSHA512(n.serialize())
        let hg = srpSHA512(Self.pad(Self.generator))
        let hng = Data(zip(hn, hg).map { $0 ^ $1 })
        let expected = srpSHA512(hng, srpSHA512(Data()), salt, paddedA, paddedB, key)
        guard expected == m1 else { return nil }
        return (key, srpSHA512(paddedA, m1, key))
    }
}

struct SRPWireFields {
    private let data: Data
    private var offset: Int

    /// Strips the outer and inner length words of a client message.
    init(unwrapping message: Data) {
        data = Data(message)
        offset = 8
    }

    mutating func take(_ count: Int) -> Data {
        defer { offset += count }
        return data.subdata(in: offset..<offset + count)
    }

    mutating func u16() -> Int {
        let bytes = take(2)
        return Int(bytes[0]) << 8 | Int(bytes[1])
    }

    mutating func string() -> String { String(decoding: take(u16()), as: UTF8.self) }
    mutating func mpi() -> Data { take(u16()) }
    mutating func opaque() -> Data { take(Int(take(1)[0])) }

    static func mpi(_ value: Data) -> Data { uint16(value.count) + value }
    static func opaque(_ value: Data) -> Data { Data([UInt8(value.count)]) + value }
    static func string(_ value: String) -> Data { mpi(Data(value.utf8)) }
    static func uint16(_ value: Int) -> Data { Data([UInt8(value >> 8), UInt8(value & 0xFF)]) }
    static func uint32(_ value: UInt32) -> Data { Data((0..<4).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }) }
    static func uint64(_ value: UInt64) -> Data { Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }) }

    /// `u32 outer` + `u32 inner` + fields.
    static func message(_ fields: Data) -> Data {
        uint32(UInt32(fields.count + 4)) + uint32(UInt32(fields.count)) + fields
    }
}

extension TestSRPServer {
    var challengeMessage: Data {
        var challenge = Data([0])
        challenge += SRPWireFields.mpi(Self.modulus.serialize())
        challenge += SRPWireFields.mpi(Data([2]))
        challenge += SRPWireFields.opaque(salt)
        challenge += SRPWireFields.mpi(Self.pad(publicKey))
        challenge += SRPWireFields.uint64(iterations)
        challenge += SRPWireFields.string("mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305")
        return SRPWireFields.message(challenge)
    }

    static func confirmationMessage(m2: Data) -> Data {
        var reply = SRPWireFields.opaque(m2)
        reply += SRPWireFields.opaque(Data(count: 16))
        reply += SRPWireFields.string("")
        reply += SRPWireFields.uint32(0)
        return SRPWireFields.message(reply)
    }
}
