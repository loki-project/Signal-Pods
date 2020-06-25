import CryptoSwift
import SessionCurve25519Kit

@objc public final class DiffieHellman : NSObject {
    public static let ivSize: Int32 = 16

    @objc public class DiffieHellmanError : NSError { // Not called `Error` for Obj-C interoperablity
        
        @objc public static let decryptionFailed = DiffieHellmanError(domain: "DiffieHellmanErrorDomain", code: 1, userInfo: [ NSLocalizedDescriptionKey : "Couldn't decrypt data." ])
    }
    
    private override init() { }

    public static func encrypt(_ plaintext: Data, using symmetricKey: Data) throws -> Data {
        let iv = Randomness.generateRandomBytes(ivSize)!
        let blockMode = CBC(iv: iv.bytes)
        let aes = try AES(key: symmetricKey.bytes, blockMode: blockMode)
        let ciphertext = try aes.encrypt(plaintext.bytes)
        let ivAndCiphertext = iv.bytes + ciphertext
        return Data(bytes: ivAndCiphertext)
    }
    
    public static func encrypt(_ plaintext: Data, publicKey: Data, privateKey: Data) throws -> Data {
        let symmetricKey = try Curve25519.generateSharedSecret(fromPublicKey: publicKey, privateKey: privateKey)
        return try encrypt(plaintext, using: symmetricKey)
    }
    
    public static func decrypt(_ ivAndCiphertext: Data, using symmetricKey: Data) throws -> Data {
        guard ivAndCiphertext.count >= ivSize else { throw DiffieHellmanError.decryptionFailed }
        let iv = ivAndCiphertext[..<ivSize]
        let ciphertext = ivAndCiphertext[ivSize...]
        let blockMode = CBC(iv: iv.bytes)
        let aes = try AES(key: symmetricKey.bytes, blockMode: blockMode)
        let plaintext = try aes.decrypt(ciphertext.bytes)
        return Data(bytes: plaintext)
    }
    
    public static func decrypt(_ ivAndCiphertext: Data, publicKey: Data, privateKey: Data) throws -> Data {
        let symmetricKey = try Curve25519.generateSharedSecret(fromPublicKey: publicKey, privateKey: privateKey)
        return try decrypt(ivAndCiphertext, using: symmetricKey)
    }
}
