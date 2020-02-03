//
//  Copyright (c) 2018 Open Whisper Systems. All rights reserved.
//

import Foundation

public enum SMKCertificateError: Error {
    case invalidCertificate(description: String)
}

@objc public protocol SMKCertificateValidator: class {

    @objc func throwswrapped_validate(senderCertificate: SMKSenderCertificate, validationTime: UInt64) throws

    @objc func throwswrapped_validate(serverCertificate: SMKServerCertificate) throws
}

// See: https://github.com/signalapp/libsignal-metadata-java/blob/master/java/src/main/java/org/signal/libsignal/metadata/certificate/CertificateValidator.java
//public class CertificateValidator {
@objc public class SMKCertificateDefaultValidator: NSObject, SMKCertificateValidator {

//    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
//    private static final Set<Integer> REVOKED = new HashSet<Integer>() {{
//
//    }};
    private static let kRevokedCertificateIds = Set<UInt32>()

//
//    private final ECPublicKey trustRoot;
    private let trustRoot: ECPublicKey

//    public CertificateValidator(ECPublicKey trustRoot) {
//    this.trustRoot = trustRoot;
//    }
    @objc public init(trustRoot: ECPublicKey ) {
        self.trustRoot = trustRoot
    }

//    public void validate(SenderCertificate certificate, long validationTime) throws InvalidCertificateException {
    @objc public func throwswrapped_validate(senderCertificate: SMKSenderCertificate, validationTime: UInt64) throws {
      if (senderCertificate.senderRecipientId.isEmpty || senderCertificate.senderDeviceId == 0) {
        let error = SMKCertificateError.invalidCertificate(description: "Missing field.")
        Logger.error("\(error)")
        throw error
      }
    }

//    // VisibleForTesting
//    void validate(ServerCertificate certificate) throws InvalidCertificateException {
    @objc public func throwswrapped_validate(serverCertificate: SMKServerCertificate) throws {
        let certificateBuilder = SMKProtoServerCertificateCertificate.builder(id: serverCertificate.keyId,
                                                                              key: serverCertificate.key.serialized)
        let certificateData = try certificateBuilder.build().serializedData()

        guard try Ed25519.verifySignature(serverCertificate.signatureData,
                                          publicKey: trustRoot.keyData,
                                          data: certificateData) else {
                                            let error = SMKCertificateError.invalidCertificate(description: "Server certificate signature verification failed.")
                                            Logger.error("\(error)")
                                            throw error
        }
        guard !SMKCertificateDefaultValidator.kRevokedCertificateIds.contains(serverCertificate.keyId) else {
            let error = SMKCertificateError.invalidCertificate(description: "Revoked certificate.")
            Logger.error("\(error)")
            throw error
        }
    }
}
