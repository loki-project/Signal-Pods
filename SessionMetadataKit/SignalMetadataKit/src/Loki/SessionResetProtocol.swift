
@objc(LKSessionResetProtocol)
public protocol SessionResetProtocol {
    
    func validatePreKeyWhisperMessage(for recipientID: String, whisperMessage: CipherMessage, protocolContext: Any?) throws
    func getSessionResetStatus(for recipientID: String, protocolContext: Any?) -> SessionResetStatus
}
