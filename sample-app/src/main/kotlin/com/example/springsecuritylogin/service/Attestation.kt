package com.example.springsecuritylogin.service

import com.linecorp.line.auth.fido.fido2.common.Credential
import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientOutputs
import com.linecorp.line.auth.fido.fido2.common.server.ServerAuthenticatorAttestationResponse

class Attestation : Credential() {
    val rawId: String = ""
    val response: ServerAuthenticatorAttestationResponse? = null
    val extensions: AuthenticationExtensionsClientOutputs? = null
}
