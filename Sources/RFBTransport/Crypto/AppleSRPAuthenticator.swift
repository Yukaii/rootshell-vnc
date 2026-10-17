import Foundation
import BigInt
import RFBProtocol

/// Security type 36: Apple's SASL-style SRP exchange.
///
/// Every message is `u32 length` followed by a length-wrapped field buffer:
/// 1. C→S: `s(authid) s(userid) s(sid) o(nonce)`
/// 2. S→C: `c(0) m(N) m(g) o(salt) m(B) q(iterations) s(options)`
/// 3. C→S: `m(A) o(M1) s(options) o(cIV)`
/// 4. S→C: `o(M2) o(sIV) s(options) u(maxBuffer)`, then the RFB SecurityResult
///
/// A rejected proof gets a one-byte body instead of step 4.
public struct AppleSRPAuthenticator: Authenticator, Sendable {

    /// Requests no SASL security layer, leaving the RFB stream in the clear
    /// for Apple's own msg 18 encryption.
    static let clientOptions = "mda=SHA-512"

    private static let maxMessageLength = 0x8000

    private let username: String
    private let password: String
    private let privateKey: (@Sendable () throws -> Data)?
    private let log = VNCLogger(category: "AppleSRP")

    public init(username: String, password: String) {
        self.init(username: username, password: password, privateKey: nil)
    }

    /// `privateKey` overrides the random SRP exponent `a` for tests.
    init(username: String, password: String, privateKey: (@Sendable () throws -> Data)?) {
        self.username = username
        self.password = password
        self.privateKey = privateKey
    }

    public func authenticate(connection: any RFBConnection) async throws -> AuthenticationResult {
        log.info("Starting Apple SRP authentication (Type 36)")

        try await send(
            AppleSRPBuffer.securityType36Request(
                username: username,
                clientNonce: AppleSRPClient.randomBytes(count: 16)),
            connection: connection)

        let challengeBody = try await readMessage(connection: connection)
        guard challengeBody.count > 1 else {
            throw VNCProtocolError.authenticationFailed("The server rejected the user name")
        }
        let challenge = try AppleSRPBuffer.parseSecurityType36Challenge(challengeBody)
        try AppleSRPClient.validate(challenge)
        log.debug(
            "Type 36 challenge: salt=\(challenge.salt.count) bytes, "
                + "iterations=\(challenge.iterations), options=\(challenge.options)")

        let x = try AppleSRPClient.passwordExponent(
            password: password, salt: challenge.salt, iterations: challenge.iterations)
        let a = try privateKey.map { BigUInt(try $0()) } ?? AppleSRPClient.randomPrivateKey()
        let client = try AppleSRPClient.respond(challenge: challenge, x: x, privateKey: a)

        try await send(
            AppleSRPBuffer.clientEvidence(
                publicKey: client.publicKey,
                proof: client.proof,
                options: Self.clientOptions,
                clientSalt: AppleSRPClient.randomBytes(count: 16)),
            connection: connection)

        let confirmationBody = try await readMessage(connection: connection)
        guard confirmationBody.count > 1 else {
            throw VNCProtocolError.authenticationFailed("Incorrect user name or password")
        }
        let confirmation = try AppleSRPBuffer.parseSecurityType36Confirmation(confirmationBody)
        guard confirmation.serverProof == client.expectedServerProof else {
            throw VNCProtocolError.authenticationFailed("Apple SRP: server proof did not match")
        }

        log.info("Type 36 authenticated; options=\(confirmation.options)")
        return AuthenticationResult(
            appleSessionKey: AppleSRPClient.rfbSessionKey(from: client.sessionKey))
    }

    private func send(_ buffer: Data, connection: any RFBConnection) async throws {
        var message = Data()
        let length = UInt32(buffer.count)
        message.append(UInt8((length >> 24) & 0xFF))
        message.append(UInt8((length >> 16) & 0xFF))
        message.append(UInt8((length >> 8) & 0xFF))
        message.append(UInt8(length & 0xFF))
        message.append(buffer)
        try await connection.send(message)
    }

    private func readMessage(connection: any RFBConnection) async throws -> Data {
        let header = try await connection.read(exactly: 4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        guard length > 0, length < Self.maxMessageLength else {
            throw VNCProtocolError.authenticationFailed("Apple SRP: invalid message length \(length)")
        }
        return try await connection.read(exactly: length)
    }
}
