
@objc(LKSessionResetProtocol)
public protocol SessionResetProtocol {
    func verifyFriendRequestAcceptPreKey(for recipientId: String, whisperMessage: CipherMessage, protocolContext: Any?) throws
    func getSessionResetStatus(for recipientId: String, protocolContext: Any?) -> SessionResetStatus
}
