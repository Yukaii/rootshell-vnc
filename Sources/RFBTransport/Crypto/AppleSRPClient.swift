import Foundation
import CommonCrypto
import CryptoKit
import Security
import BigInt
import RFBProtocol

/// Client side of Apple's Screen Sharing SRP-6a profile, shared by the type 33
/// SRP mode and type 36: SHA-512 throughout, a PBKDF2-SHA512 stretched
/// password, and an empty identity in both `x` and the client proof.
enum AppleSRPClient {
    struct Response: Sendable {
        let publicKey: Data
        let proof: Data
        let expectedServerProof: Data
        let sessionKey: Data
    }

    /// RFC 5054 groups of at least 2048 bits. Any other group could let a hostile server
    /// recover the session key from the client proof without knowing the password.
    static let trustedGroups: [(prime: BigUInt, generator: BigUInt)] = [
        (group("""
            AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050
            A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50
            E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8
            55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B
            CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748
            544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6
            AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6
            94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
            """), 2),
        (group("""
            FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
            020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
            4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
            EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
            98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
            9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
            E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
            3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33
            A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7
            ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864
            D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2
            08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
            """), 5),
        (group("""
            FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
            020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
            4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
            EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
            98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
            9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
            E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
            3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33
            A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7
            ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864
            D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2
            08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7
            88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8
            DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2
            233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9
            93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
            """), 5),
    ]

    /// A ceiling well above real verifiers; PBKDF2 runs synchronously and can't be cancelled.
    static let maximumIterations: UInt64 = 1_000_000

    private static func group(_ hex: String) -> BigUInt {
        BigUInt(hex.filter(\.isHexDigit), radix: 16)!
    }

    /// Rejects untrusted groups, bad server keys and excessive PBKDF2 work before any of it runs.
    static func validate(_ challenge: AppleSRPServerChallenge) throws {
        let N = BigUInt(challenge.prime)
        let g = BigUInt(challenge.generator)
        guard trustedGroups.contains(where: { $0.prime == N && $0.generator == g }) else {
            throw VNCProtocolError.authenticationFailed(
                "Apple SRP: server offered an untrusted \(N.bitWidth)-bit group")
        }
        guard BigUInt(challenge.serverPublicKey) % N != 0 else {
            throw VNCProtocolError.authenticationFailed("Apple SRP: invalid server public key")
        }
        try validateIterations(challenge.iterations)
    }

    private static func validateIterations(_ iterations: UInt64) throws {
        guard iterations > 0, iterations <= maximumIterations else {
            throw VNCProtocolError.authenticationFailed(
                "Apple SRP: unsupported PBKDF2 iteration count \(iterations)")
        }
    }

    /// `H(salt || H(":" || PBKDF2-SHA512(password, salt, iterations, 128)))`.
    static func passwordExponent(password: String, salt: Data, iterations: UInt64) throws -> BigUInt {
        try validateIterations(iterations)
        let stretched = try pbkdf2HMACSHA512(
            key: Data(password.utf8), salt: salt, iterations: UInt32(iterations), keyLength: 128)
        return BigUInt(sha512(salt + sha512(Data([0x3A]) + stretched)))
    }

    static func respond(
        challenge: AppleSRPServerChallenge,
        x: BigUInt,
        privateKey: BigUInt,
        proofUsername: Data = Data()
    ) throws -> Response {
        try validate(challenge)
        let primeLength = challenge.prime.count
        let N = BigUInt(challenge.prime)
        let g = BigUInt(challenge.generator)
        let B = BigUInt(challenge.serverPublicKey)

        let A = g.power(privateKey, modulus: N)
        guard A % N != 0 else {
            throw VNCProtocolError.authenticationFailed("Apple SRP: computed A is zero")
        }

        let paddedN = pad(N.serialize(), length: primeLength)
        let paddedG = pad(g.serialize(), length: primeLength)
        let paddedA = pad(A.serialize(), length: primeLength)
        let paddedB = pad(B.serialize(), length: primeLength)

        let k = BigUInt(sha512(paddedN + paddedG))
        let u = BigUInt(sha512(paddedA + paddedB))
        guard u != 0 else {
            throw VNCProtocolError.authenticationFailed("Apple SRP: computed u is zero")
        }

        let gx = g.power(x, modulus: N)
        let base = (B + N - ((k * gx) % N)) % N
        let S = base.power(privateKey + (u * x), modulus: N)
        let K = sha512(pad(S.serialize(), length: primeLength))

        let hashN = sha512(paddedN)
        let hashG = sha512(paddedG)
        let xor = Data(zip(hashN, hashG).map { $0 ^ $1 })
        let proof = sha512(xor + sha512(proofUsername) + challenge.salt + paddedA + paddedB + K)
        return Response(
            publicKey: paddedA,
            proof: proof,
            expectedServerProof: sha512(paddedA + proof + K),
            sessionKey: K
        )
    }

    /// The RFB session key: the first 16 bytes of `SHA-256(K)`.
    static func rfbSessionKey(from sessionKey: Data) -> Data {
        Data(SHA256.hash(data: sessionKey).prefix(kCCKeySizeAES128))
    }

    static func randomPrivateKey() throws -> BigUInt {
        BigUInt(try randomBytes(count: 64))
    }

    static func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        guard result == errSecSuccess else {
            throw VNCProtocolError.ioError("Failed to generate \(count) random bytes")
        }
        return data
    }

    /// PBKDF2 with HMAC-SHA512, using raw key bytes (not a password string).
    static func pbkdf2HMACSHA512(
        key: Data,
        salt: Data,
        iterations: UInt32,
        keyLength: Int
    ) throws -> Data {
        var derivedKey = Data(count: keyLength)

        let result = derivedKey.withUnsafeMutableBytes { derivedPtr in
            salt.withUnsafeBytes { saltPtr in
                key.withUnsafeBytes { keyPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        keyPtr.baseAddress?.assumingMemoryBound(to: Int8.self),
                        key.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        iterations,
                        derivedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }

        guard result == kCCSuccess else {
            throw VNCProtocolError.ioError("PBKDF2-SHA512 failed with status \(result)")
        }

        return derivedKey
    }

    private static func sha512(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    private static func pad(_ data: Data, length: Int) -> Data {
        if data.count >= length {
            return Data(data.suffix(length))
        }
        return Data(count: length - data.count) + data
    }
}
