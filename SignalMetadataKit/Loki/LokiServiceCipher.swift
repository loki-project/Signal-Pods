import Foundation

@objc(LKSessionCipher)
public final class LokiSessionCipher : SessionCipher {
    
    @objc public static let sessionAdoptedNotification = "LKSessionAddopted"
    @objc public static let contactPubKeyField = "LKContactPubKeyField"

    private let sessionReset: SessionResetProtocol?
    private let sessionStore: SessionStore
    private let preKeyStore: PreKeyStore
    private let recipientId: String
    private let deviceId: Int32
    
    @objc public init(sessionReset: SessionResetProtocol , sessionStore: SessionStore, preKeyStore: PreKeyStore, signedPreKeyStore: SignedPreKeyStore, identityKeyStore: IdentityKeyStore, recipientId: String, deviceId: Int32) {
        self.sessionReset = sessionReset
        self.sessionStore = sessionStore
        self.preKeyStore = preKeyStore
        self.recipientId = recipientId
        self.deviceId = deviceId
        super.init(sessionStore: sessionStore, preKeyStore: preKeyStore, signedPreKeyStore: signedPreKeyStore, identityKeyStore: identityKeyStore, recipientId: recipientId, deviceId: deviceId)
    }
    
    @available(*, unavailable)
    override convenience private init(axolotlStore sessionStore: AxolotlStore, recipientId: String, deviceId: Int32) {
        self.init(sessionStore: sessionStore, preKeyStore: sessionStore, signedPreKeyStore: sessionStore, identityKeyStore: sessionStore, recipientId: recipientId, deviceId: deviceId)
    }
    
    override private init(sessionStore: SessionStore, preKeyStore: PreKeyStore, signedPreKeyStore: SignedPreKeyStore, identityKeyStore: IdentityKeyStore, recipientId: String, deviceId: Int32) {
        self.sessionReset = nil
        self.sessionStore = sessionStore
        self.preKeyStore = preKeyStore
        self.recipientId = recipientId
        self.deviceId = deviceId
        super.init(sessionStore: sessionStore, preKeyStore: preKeyStore, signedPreKeyStore: signedPreKeyStore, identityKeyStore: identityKeyStore, recipientId: recipientId, deviceId: deviceId)
    }
    
    override public func decrypt(_ whisperMessage: CipherMessage, protocolContext: Any?) throws -> Data {
        // Our state before we decrypt the message
        let currentState = getCurrentState(protocolContext: protocolContext)
        
        // Verify incoming friend request messages
        if (currentState == nil && whisperMessage.cipherMessageType == .prekey) {
            try sessionReset?.verifyFriendRequestAcceptPreKey(for: recipientId, whisperMessage: whisperMessage, protocolContext: protocolContext)
        }
        
        // While decrypting our state may change internally
        let plainText = try super.decrypt(whisperMessage, protocolContext: protocolContext)
        
        handleSessionReset(for: whisperMessage, previousState: currentState, protocolContext: protocolContext)
        
        return plainText
    }
    
    private func getCurrentState(protocolContext: Any?) -> SessionState? {
        let record = sessionStore.loadSession(recipientId, deviceId: deviceId, protocolContext: protocolContext)
        return record.isFresh() ? nil : record.sessionState()
    }
    
    private func handleSessionReset(for whisperMessage: CipherMessage, previousState: SessionState?, protocolContext: Any?) {
        // Don't bother doing anything if we didn't have a session before
        guard let previousState = previousState else { return }
        
        let sessionResetStatus = sessionReset?.getSessionResetStatus(for: recipientId, protocolContext: protocolContext) ?? SessionResetStatus.none
        
        // Bail early if no session reset is in progress
        if (sessionResetStatus == .none) { return; }
        
        let currentState = getCurrentState(protocolContext: protocolContext)

        // Check if our previous state and our current state differ
        if (currentState == nil || currentState!.aliceBaseKey != previousState.aliceBaseKey) {
            if (sessionResetStatus == .requestReceived) {
                // The other user used an old session to contact us.
                // Wait for them to use a new one
                restoreSession(previousState, protocolContext: protocolContext)
            } else {
                // Our session reset went through successfully
                // We had initiated a session reset and got a different session back from the user
                deleteAllSessions(except: currentState, protocolContext: protocolContext)
                notifySessionAdopted()
            }
        } else if (sessionResetStatus == .requestReceived) {
            // Our session reset went through successfully
            // We got a message with the same session from the other user
            deleteAllSessions(except: previousState, protocolContext: protocolContext)
            notifySessionAdopted()
        }
    }
    
    private func notifySessionAdopted() {
        NotificationCenter.default.post(name: NSNotification.Name(rawValue: LokiSessionCipher.sessionAdoptedNotification), object: nil, userInfo: [ LokiSessionCipher.contactPubKeyField : recipientId ])
    }
    
    private func deleteAllSessions(except state: SessionState?, protocolContext: Any?) {
        let record = sessionStore.loadSession(recipientId, deviceId: deviceId, protocolContext: protocolContext)
        record.removePreviousSessionStates()
        
        let newState = state ?? SessionState()
        record.setState(newState)
        
        sessionStore.storeSession(recipientId, deviceId: deviceId, session: record, protocolContext: protocolContext)
    }
    
    private func restoreSession(_ state: SessionState, protocolContext: Any?) {
        let record = sessionStore.loadSession(recipientId, deviceId: deviceId, protocolContext: protocolContext)
        // Remove the state from previous session states
        record.previousSessionStates()?.enumerateObjects(options: .reverse) { (obj, index, stop) in
            guard let obj = obj as? SessionState, state.aliceBaseKey == obj.aliceBaseKey else { return }
            record.previousSessionStates()?.removeObject(at: index)
            stop.pointee = true
        }

        // Promote it so the previous state gets archived
        record.promoteState(state)
        
        sessionStore.storeSession(recipientId, deviceId: deviceId, session: record, protocolContext: protocolContext)
    }
}
