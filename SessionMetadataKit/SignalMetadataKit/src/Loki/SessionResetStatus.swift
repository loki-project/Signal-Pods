import Foundation

// TODO: Can we make this a computed property?

@objc(LKSessionResetStatus)
public enum SessionResetStatus: Int {
    /// No ongoing session reset.
    case none = 0
    /// We initiated a session reset.
    case initiated
    /// We received a session reset.
    case requestReceived
}
