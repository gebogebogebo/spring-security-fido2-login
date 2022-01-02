package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.controller.AdapterServerResponse
import com.example.springsecuritylogin.controller.ServerPublicKeyCredentialCreationOptionsResponse
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorAttachment

interface LineFido2ServerService {
    fun getRegisterOption(
        userName: String,
        authenticatorAttachment: AuthenticatorAttachment?,
    ): Pair<ServerPublicKeyCredentialCreationOptionsResponse, String>

    fun verifyRegisterAttestation(
        sessionId: String,
        clientResponse: Attestation,
    ): AdapterServerResponse
}
