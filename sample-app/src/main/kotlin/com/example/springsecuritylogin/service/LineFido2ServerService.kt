package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.controller.AdapterServerResponse
import com.example.springsecuritylogin.controller.ServerPublicKeyCredentialCreationOptionsResponse
import com.example.springsecuritylogin.controller.ServerPublicKeyCredentialGetOptionsResponse
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorAttachment
import com.linecorp.line.auth.fido.fido2.common.server.GetCredentialsResult

interface LineFido2ServerService {
    fun getRegisterOption(
        userName: String,
        authenticatorAttachment: AuthenticatorAttachment?,
    ): Pair<ServerPublicKeyCredentialCreationOptionsResponse, String>

    fun verifyRegisterAttestation(
        sessionId: String,
        clientResponse: Attestation,
    ): AdapterServerResponse

    fun getAuthenticateOption(
        userName: String,
    ): Pair<ServerPublicKeyCredentialGetOptionsResponse, String>

    fun verifyAuthenticateAssertion(
        sessionId: String,
        clientResponse: Assertion,
    ): Boolean

    fun getCredentialsWithUsername(
        username: String,
    ): GetCredentialsResult
}
