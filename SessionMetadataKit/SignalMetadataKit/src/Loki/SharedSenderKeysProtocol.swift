
@objc public protocol SharedSenderKeysProtocol {

    func isClosedGroup(_ publicKey: String) -> Bool
    func getKeyPair(forGroupWithPublicKey groupPublicKey: String) -> ECKeyPair
    func encrypt(_ plaintext: Data, forGroupWithPublicKey groupPublicKey: String, senderPublicKey: String, protocolContext: Any) throws -> [Any]
    func decrypt(_ ivAndCiphertext: Data, forGroupWithPublicKey groupPublicKey: String, senderPublicKey: String, keyIndex: UInt, protocolContext: Any) throws -> Data
}
