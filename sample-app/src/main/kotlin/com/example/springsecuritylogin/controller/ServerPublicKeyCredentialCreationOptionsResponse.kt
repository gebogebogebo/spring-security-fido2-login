package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status
import com.linecorp.line.auth.fido.fido2.common.AttestationConveyancePreference
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorSelectionCriteria
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialParameters
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialRpEntity
import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientInputs
import com.linecorp.line.auth.fido.fido2.common.server.RegOptionResponse
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialDescriptor
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialUserEntity

class ServerPublicKeyCredentialCreationOptionsResponse(
    val rp: PublicKeyCredentialRpEntity?,
    val user: ServerPublicKeyCredentialUserEntity?,
    val attestation: AttestationConveyancePreference?,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    val challenge: String?,
    val excludeCredentials: List<ServerPublicKeyCredentialDescriptor>?,
    val pubKeyCredParams: List<PublicKeyCredentialParameters>?,
    val timeout: Long?,
    val extensions: AuthenticationExtensionsClientInputs?,
) : AdapterServerResponse(Status.OK, "") {
    constructor(
        status: Status,
        errorMessage: String,
    ) : this(
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }

    constructor(
        regOptionResponse: RegOptionResponse,
    ) : this(
        regOptionResponse.rp,
        regOptionResponse.user,
        regOptionResponse.attestation,
        regOptionResponse.authenticatorSelection,
        regOptionResponse.challenge,
        regOptionResponse.excludeCredentials,
        regOptionResponse.pubKeyCredParams,
        regOptionResponse.timeout,
        regOptionResponse.extensions,
    )
}
