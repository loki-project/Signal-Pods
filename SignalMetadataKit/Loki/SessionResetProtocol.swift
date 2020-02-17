
@objc(LKSessionResetProtocol)
public protocol SessionResetProtocol {
    
    func validatePreKeyForFriendRequestAcceptance(for recipientID: String, whisperMessage: CipherMessage, protocolContext: Any?) throws
    func getSessionResetStatus(for recipientID: String, protocolContext: Any?) -> SessionResetStatus
}
