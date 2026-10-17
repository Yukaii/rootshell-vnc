import Foundation
import RFBProtocol

struct AppleSRPServerChallenge: Sendable, Equatable {
    let step: UInt8
    let prime: Data
    let generator: Data
    let serverPublicKey: Data
    let salt: Data
    let iterations: UInt64
    let options: String
}

struct AppleSRPServerConfirmation: Sendable, Equatable {
    let step: UInt32
    let serverProof: Data
    let serverIV: Data
    let options: String
    let maxBufferSize: UInt32
}

enum AppleSRPBuffer {
    static func clientInitialRequest(
        username: String,
        options: String,
        digest: String = "sha512",
        group: String = "rfc5054_4096"
    ) throws -> Data {
        var fields = Data()
        try appendUTF8(digest, to: &fields)
        try appendUTF8(group, to: &fields)
        try appendUTF8(username, to: &fields)
        try appendOpaque(Data(options.utf8), to: &fields)
        return wrapped(fields)
    }

    static func clientEvidence(
        publicKey: Data,
        proof: Data,
        options: String,
        clientSalt: Data
    ) throws -> Data {
        var fields = Data()
        try appendMPI(publicKey, to: &fields)
        try appendOpaque(proof, to: &fields)
        try appendUTF8(options, to: &fields)
        try appendOpaque(clientSalt, to: &fields)
        return wrapped(fields)
    }

    /// Type 36 step 1: `s(authid) s(userid) s(sid) o(client nonce)`.
    static func securityType36Request(username: String, clientNonce: Data) throws -> Data {
        var fields = Data()
        try appendUTF8(username, to: &fields)
        try appendUTF8("", to: &fields)
        try appendUTF8("", to: &fields)
        try appendOpaque(clientNonce, to: &fields)
        return wrapped(fields)
    }

    static func parseServerChallenge(_ data: Data) throws -> AppleSRPServerChallenge {
        var reader = Reader(data)
        let stepCode = try reader.readUInt32()
        var sectionReader = Reader(try reader.readSection())
        return try readChallengeFields(&sectionReader, stepCode: stepCode)
    }

    /// Type 36 challenge: a length-wrapped buffer with no step code or section.
    static func parseSecurityType36Challenge(_ data: Data) throws -> AppleSRPServerChallenge {
        var reader = Reader(try unwrapped(data))
        return try readChallengeFields(&reader, stepCode: 0)
    }

    static func parseServerConfirmation(_ data: Data) throws -> AppleSRPServerConfirmation {
        var reader = Reader(data)
        let step = try reader.readUInt32()
        var sectionReader = Reader(try reader.readSection())
        return try readConfirmationFields(&sectionReader, step: step)
    }

    static func parseSecurityType36Confirmation(_ data: Data) throws -> AppleSRPServerConfirmation {
        var reader = Reader(try unwrapped(data))
        return try readConfirmationFields(&reader, step: 0)
    }

    private static func readChallengeFields(
        _ reader: inout Reader,
        stepCode: UInt32
    ) throws -> AppleSRPServerChallenge {
        let step = try reader.readUInt8()
        let prime = try reader.readMPI()
        let generator = try reader.readMPI()
        let salt = try reader.readOpaque()
        let serverPublicKey = try reader.readMPI()
        let iterations = try reader.readUInt64()
        let options = try reader.readUTF8()
        try reader.requireFullyRead()

        return AppleSRPServerChallenge(
            step: step == 0 ? UInt8(truncatingIfNeeded: stepCode) : step,
            prime: prime,
            generator: generator,
            serverPublicKey: serverPublicKey,
            salt: salt,
            iterations: iterations,
            options: options
        )
    }

    private static func readConfirmationFields(
        _ reader: inout Reader,
        step: UInt32
    ) throws -> AppleSRPServerConfirmation {
        let serverProof = try reader.readOpaque()
        let serverIV = try reader.readOpaque()
        let options = try reader.readUTF8()
        let maxBufferSize = try reader.readUInt32()
        try reader.requireFullyRead()
        return AppleSRPServerConfirmation(
            step: step,
            serverProof: serverProof,
            serverIV: serverIV,
            options: options,
            maxBufferSize: maxBufferSize
        )
    }

    private static func unwrapped(_ buffer: Data) throws -> Data {
        var reader = Reader(buffer)
        let innerLength = Int(try reader.readUInt32())
        guard innerLength == buffer.count - 4 else {
            throw VNCProtocolError.authenticationFailed(
                "Apple SRP buffer length mismatch: inner=\(innerLength), actual=\(buffer.count - 4)")
        }
        return Data(buffer.suffix(innerLength))
    }

    static func section(_ srpBuffer: Data) throws -> Data {
        guard srpBuffer.count <= Int(UInt16.max) else {
            throw VNCProtocolError.ioError("Apple SRP section too large: \(srpBuffer.count)")
        }
        var out = Data()
        appendUInt16(&out, UInt16(srpBuffer.count))
        out.append(srpBuffer)
        return out
    }

    private static func wrapped(_ fields: Data) -> Data {
        var out = Data()
        appendUInt32(&out, UInt32(fields.count))
        out.append(fields)
        return out
    }

    private static func appendMPI(_ value: Data, to data: inout Data) throws {
        guard value.count <= Int(UInt16.max) else {
            throw VNCProtocolError.ioError("Apple SRP MPI too large: \(value.count)")
        }
        appendUInt16(&data, UInt16(value.count))
        data.append(value)
    }

    private static func appendOpaque(_ value: Data, to data: inout Data) throws {
        guard value.count < 256 else {
            throw VNCProtocolError.ioError("Apple SRP opaque field too large: \(value.count)")
        }
        data.append(UInt8(value.count))
        data.append(value)
    }

    private static func appendUTF8(_ value: String, to data: inout Data) throws {
        let bytes = Data(value.utf8)
        guard bytes.count <= Int(UInt16.max) else {
            throw VNCProtocolError.ioError("Apple SRP UTF-8 field too large: \(bytes.count)")
        }
        appendUInt16(&data, UInt16(bytes.count))
        data.append(bytes)
    }

    private static func appendUInt16(_ data: inout Data, _ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    private static func appendUInt32(_ data: inout Data, _ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    private struct Reader {
        private let data: Data
        private var offset: Data.Index

        init(_ data: Data) {
            self.data = data
            self.offset = data.startIndex
        }

        mutating func readSection() throws -> Data {
            let sectionLength = Int(try readUInt16())
            let section = try readBytes(sectionLength)
            var sectionReader = Reader(section)
            let innerLength = Int(try sectionReader.readUInt32())
            guard innerLength == section.count - 4 else {
                throw VNCProtocolError.authenticationFailed(
                    "Apple SRP section length mismatch: inner=\(innerLength), actual=\(section.count - 4)")
            }
            return Data(section.suffix(section.count - 4))
        }

        mutating func readMPI() throws -> Data {
            let length = try readUInt16()
            return try readBytes(Int(length))
        }

        mutating func readOpaque() throws -> Data {
            let length = try readUInt8()
            return try readBytes(Int(length))
        }

        mutating func readUTF8() throws -> String {
            let length = try readUInt16()
            let bytes = try readBytes(Int(length))
            guard let string = String(data: bytes, encoding: .utf8) else {
                throw VNCProtocolError.authenticationFailed("Apple SRP UTF-8 field is invalid")
            }
            return string
        }

        mutating func readUInt8() throws -> UInt8 {
            guard offset < data.endIndex else {
                throw VNCProtocolError.authenticationFailed("Apple SRP buffer truncated reading UInt8")
            }
            let value = data[offset]
            offset += 1
            return value
        }

        mutating func readUInt16() throws -> UInt16 {
            let bytes = try readBytes(2)
            return UInt16(bytes[bytes.startIndex]) << 8
                | UInt16(bytes[bytes.startIndex + 1])
        }

        mutating func readUInt32() throws -> UInt32 {
            let bytes = try readBytes(4)
            return UInt32(bytes[bytes.startIndex]) << 24
                | UInt32(bytes[bytes.startIndex + 1]) << 16
                | UInt32(bytes[bytes.startIndex + 2]) << 8
                | UInt32(bytes[bytes.startIndex + 3])
        }

        mutating func readUInt64() throws -> UInt64 {
            let bytes = try readBytes(8)
            var value: UInt64 = 0
            for byte in bytes {
                value = (value << 8) | UInt64(byte)
            }
            return value
        }

        mutating func readBytes(_ count: Int) throws -> Data {
            guard count >= 0, offset + count <= data.endIndex else {
                throw VNCProtocolError.authenticationFailed(
                    "Apple SRP buffer truncated reading \(count) bytes")
            }
            let bytes = data[offset..<offset + count]
            offset += count
            return Data(bytes)
        }

        func requireFullyRead() throws {
            guard offset == data.endIndex else {
                throw VNCProtocolError.authenticationFailed(
                    "Apple SRP buffer has \(data.endIndex - offset) trailing bytes")
            }
        }
    }
}
