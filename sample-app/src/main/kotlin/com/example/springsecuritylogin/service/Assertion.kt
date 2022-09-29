package com.example.springsecuritylogin.service

import com.linecorp.line.auth.fido.fido2.common.Credential
import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientOutputs
import com.linecorp.line.auth.fido.fido2.common.server.ServerAuthenticatorAssertionResponse

class Assertion: Credential() {
    val rawId: String = ""
    val response: ServerAuthenticatorAssertionResponse? = null
    val extensions: AuthenticationExtensionsClientOutputs? = null
}
