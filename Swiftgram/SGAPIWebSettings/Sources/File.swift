import Foundation

import SGAPIToken
import SGAPI
import SGLogging

import AccountContext

import SGSimpleSettings
import TelegramCore

// HARDENED_BUILD: automatic initData upload to api.swiftgram.app is disabled.
public func updateSGWebSettingsInteractivelly(context: AccountContext) {
    _ = context
}


public func postSGWebSettingsInteractivelly(context: AccountContext, data: [String: Any]) {
    let _ = getSGApiToken(context: context).startStandalone(next: { token in
        let _ = postSGSettings(token: token, data: data).startStandalone(error: { e in
            if case let .generic(errorMessage) = e, let errorMessage = errorMessage {
                SGLogger.shared.log("SGAPI", errorMessage)
            }
        })
    }, error: { e in
        if case let .generic(errorMessage) = e, let errorMessage = errorMessage {
            SGLogger.shared.log("SGAPI", errorMessage)
        }
    })
}
