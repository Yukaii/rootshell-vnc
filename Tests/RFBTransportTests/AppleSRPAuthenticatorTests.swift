import XCTest
import BigInt
import CryptoKit
import RFBProtocol
@testable import RFBTransport

/// Security type 36 against an in-test SRP server. The server is first pinned
/// to vectors produced by corecrypto's ccsrp client (via wayshare's
/// cross-check), so a client that authenticates against it speaks the same
/// SRP profile as Screen Sharing.
final class AppleSRPAuthenticatorTests: XCTestCase {

    func testServerMatchesCorecryptoVectors() throws {
        let server = TestSRPServer(
            salt: Data(1...8),
            x: TestSRPServer.exponent(salt: Data(1...8), stretchedPassword: Data("pass".utf8)),
            b: Data([0xab, 0x54, 0xa9, 0x8c, 0xeb, 0x1f, 0x0a, 0xd2]))
        for vector in Self.corecryptoVectors {
            let verified = try XCTUnwrap(server.verify(a: hexData(vector.a), m1: hexData(vector.m1)))
            XCTAssertEqual(verified.key, hexData(vector.k))
            XCTAssertEqual(verified.m2, hexData(vector.m2))
        }
    }

    func testAuthenticatesAndDerivesSessionKey() async throws {
        let server = try TestSRPServer(password: "secret", iterations: 1000)
        let script = ScriptedType36Server(server: server, username: "kit")
        let connection = ScriptedRFBConnection()
        await connection.setOnSend { script.respond(to: $0) }

        let result = try await AppleSRPAuthenticator(username: "kit", password: "secret")
            .authenticate(connection: connection)

        let key = try XCTUnwrap(script.sessionKey)
        XCTAssertEqual(result.appleSessionKey, Data(SHA256.hash(data: key).prefix(16)))
        XCTAssertEqual(script.clientOptions, AppleSRPAuthenticator.clientOptions)
    }

    func testRejectedProofIsAuthenticationFailure() async throws {
        let server = try TestSRPServer(password: "secret", iterations: 1000)
        let script = ScriptedType36Server(server: server, username: "kit")
        let connection = ScriptedRFBConnection()
        await connection.setOnSend { script.respond(to: $0) }

        do {
            _ = try await AppleSRPAuthenticator(username: "kit", password: "wrong")
                .authenticate(connection: connection)
            XCTFail("Expected a wrong password to fail")
        } catch let error as VNCProtocolError {
            XCTAssertEqual(error, .authenticationFailed("Incorrect user name or password"))
        }
    }

    func testMismatchedServerProofFails() async throws {
        let server = try TestSRPServer(password: "secret", iterations: 1000)
        let script = ScriptedType36Server(server: server, username: "kit", corruptM2: true)
        let connection = ScriptedRFBConnection()
        await connection.setOnSend { script.respond(to: $0) }

        do {
            _ = try await AppleSRPAuthenticator(username: "kit", password: "secret")
                .authenticate(connection: connection)
            XCTFail("Expected a forged server proof to fail")
        } catch let error as VNCProtocolError {
            XCTAssertEqual(error, .authenticationFailed("Apple SRP: server proof did not match"))
        }
    }

    func testTrustedGroupsAreTheRFC5054GroupsFrom2048Bits() {
        XCTAssertEqual(AppleSRPClient.trustedGroups.map(\.prime.bitWidth), [2048, 3072, 4096])
        XCTAssertEqual(AppleSRPClient.trustedGroups.map(\.generator), [2, 5, 5])
        XCTAssertEqual(AppleSRPClient.trustedGroups.first?.prime, TestSRPServer.modulus)
    }

    /// N=3 leaves three possible shared secrets, so a server could forge M2 from M1.
    func testWeakGroupIsRejectedBeforeAnyProofIsSent() async throws {
        let challenge = Self.challenge(
            prime: Data([3]), generator: Data([2]), serverPublicKey: Data([1]), iterations: 1)
        let sent = try await assertRejected(
            challenge,
            reason: "Apple SRP: server offered an untrusted 2-bit group")
        XCTAssertEqual(sent, 1)
    }

    func testExcessiveIterationsAreRejectedWithoutRunningPBKDF2() async throws {
        let server = try TestSRPServer(password: "secret", iterations: 1)
        let challenge = Self.challenge(
            prime: TestSRPServer.modulus.serialize(),
            generator: Data([2]),
            serverPublicKey: TestSRPServer.pad(server.publicKey),
            iterations: UInt64(UInt32.max))
        let started = ContinuousClock.now
        let sent = try await assertRejected(
            challenge,
            reason: "Apple SRP: unsupported PBKDF2 iteration count \(UInt32.max)")
        XCTAssertEqual(sent, 1)
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(1))
    }

    /// Returns how many messages the client sent before failing. The stream ends after the
    /// challenge, so a client that wrongly continues fails instead of waiting.
    private func assertRejected(_ challenge: Data, reason: String) async throws -> Int {
        let connection = ScriptedRFBConnection()
        await connection.enqueueServerBytes(challenge)
        await connection.finishServerStream()
        do {
            _ = try await AppleSRPAuthenticator(username: "kit", password: "secret")
                .authenticate(connection: connection)
            XCTFail("Expected the challenge to be rejected")
        } catch let error as VNCProtocolError {
            XCTAssertEqual(error, .authenticationFailed(reason))
        }
        var sent = await connection.sentBytes()[...]
        var messages = 0
        while sent.count >= 4 {
            let length = sent.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
            sent = sent.dropFirst(4 + length)
            messages += 1
        }
        return messages
    }

    private static func challenge(
        prime: Data, generator: Data, serverPublicKey: Data, iterations: UInt64
    ) -> Data {
        var fields = Data([0])
        fields += SRPWireFields.mpi(prime)
        fields += SRPWireFields.mpi(generator)
        fields += SRPWireFields.opaque(Data(count: 16))
        fields += SRPWireFields.mpi(serverPublicKey)
        fields += SRPWireFields.uint64(iterations)
        fields += SRPWireFields.string("mda=SHA-512")
        return SRPWireFields.message(fields)
    }

    // MARK: - Fixtures

    private static let corecryptoVectors: [(a: String, m1: String, k: String, m2: String)] = [
        (
            "00d618cf7b98426dba94dd75e5fb72eb5bf566111613458702d3881a941d71fea93e3b99fbed27b19b930273c54d4a20501df11c3404cf70e4279b95fd823f699d5dd56bf4fdb0930d960c0ac7ed6d68f039e5f3e408d7ec515289e8a7cdb3c4fdafd23775797f0ea913ac65bcf2a355c4d9901613a043e88a12f387d231f0a08513a96958f84bab3ec8bb7a4e829ea1e1d7e6526a5287ade2999c554e83f86e8ff2434dc563ff780a7290b8337e9900dbb2e2254ced2f72b238ce919e176a8de51b4274c3c00b04a8f659f21b3b173c4ae066dfc9d918681f4b8bd88d6d9c7881666070da65b9341d8e6825f88ce8eea4200221469784217a022365b73d3bc6",
            "58b2652f8f13660cbd4bbb6e9a4ced5365c4157391abb14c2e3197a85cdc5043f2a7b2990c4514a3a495945ed11e04f0843b18c029480f2fa2ff2fc831d33cf2",
            "142259478ffa74a35f031cb832006aea488145181b637477ff3f1bd5d1f710c2baab260232c8b3d1e0651f4d7a1f6c5ec20a32438925ee3c8f360cee7173baaf",
            "f3167a65a72e5f93c88c23a44094827f13cc90defa8570be117e06d1a504aefa40396cb417d281e3931c89789679e28af448ed95a6bf9f646f8f00613f3b7d66"
        ),
        (
            "56f5e85883cf9718eb2514c683addbae5a20ac1546e8791a86cf14dd381b3a865462e1986f9c340d9d19942d3028e5fd303e38573cb18d26fdac427238d6dbee9616d1baee9ac62c46aa56e57d4af71aac06cf910e1fff7613dc6303ffbab7af6a96822267a50620113150688f0d7741c4d36519d149d7ef9de1c8ca974b401f0f45cc139ff1c78717172faa309b4de0179479150dcfbd498e81f141f835f02d321052e3445f1d56da4edff98467d1fec5aa2dbea06681283c44e284c080477ff9ec764ba3deececeff9998799e1164faf6f094cdcb5b40e8a0772199dd8d778781de8440edaa92c4f3e8b5e19b9e7af1b134e5e2c8cfd206c680f407eae2d47",
            "a6149f3e3c6f229fabddb0d6073943f1136328ea2fc595c0aff56bd9c5632730d253a66855c59a875011460038fca4e5077df76fd3556800187b646b2c1ee3ee",
            "336dcabc2917b31d476abf699b0ce70e2cc0132407d478c61e7d1b3dbc5114aad0b1f87e24018c31fa22d0a3aecec20c16ed7e0e179b554eb626cae5eb4f2c0e",
            "8d248c05bc0f7fe126be9a440082416d5706359d1f46e419adb890ea4d66abd3d373acdf88f0bd843aa44f098fdd499ae8d5c47f62b16e925846e9097f4df8a7"
        ),
    ]
}

/// Drives the three-message type 36 exchange from the client's sends.
private final class ScriptedType36Server: @unchecked Sendable {
    private let lock = NSLock()
    private let server: TestSRPServer
    private let username: String
    private let corruptM2: Bool
    private var step = 0
    private var _sessionKey: Data?
    private var _clientOptions: String?

    init(server: TestSRPServer, username: String, corruptM2: Bool = false) {
        self.server = server
        self.username = username
        self.corruptM2 = corruptM2
    }

    var sessionKey: Data? { lock.withLock { _sessionKey } }
    var clientOptions: String? { lock.withLock { _clientOptions } }

    func respond(to sent: Data) -> Data? {
        lock.withLock {
            step += 1
            var fields = SRPWireFields(unwrapping: sent)
            switch step {
            case 1:
                XCTAssertEqual(fields.string(), username)
                XCTAssertEqual(fields.string(), "")
                XCTAssertEqual(fields.string(), "")
                XCTAssertEqual(fields.opaque().count, 16)
                return server.challengeMessage
            case 2:
                let a = fields.mpi()
                let m1 = fields.opaque()
                _clientOptions = fields.string()
                XCTAssertEqual(fields.opaque().count, 16)
                guard let verified = server.verify(a: a, m1: m1) else {
                    return Data([0, 0, 0, 1, 0])
                }
                _sessionKey = verified.key
                var m2 = verified.m2
                if corruptM2 { m2[m2.startIndex] ^= 0xFF }
                return TestSRPServer.confirmationMessage(m2: m2)
            default:
                XCTFail("Unexpected client send after the proof")
                return nil
            }
        }
    }
}
