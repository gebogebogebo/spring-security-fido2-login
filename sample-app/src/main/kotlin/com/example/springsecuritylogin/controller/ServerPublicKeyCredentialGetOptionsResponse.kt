package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status
import com.linecorp.line.auth.fido.fido2.common.UserVerificationRequirement
import com.linecorp.line.auth.fido.fido2.common.extension.AuthenticationExtensionsClientInputs
import com.linecorp.line.auth.fido.fido2.common.server.AuthOptionResponse
import com.linecorp.line.auth.fido.fido2.common.server.ServerPublicKeyCredentialDescriptor

class ServerPublicKeyCredentialGetOptionsResponse(
    val challenge: String?,
    val timeout: Long?,
    val rpId: String?,
    val allowCredentials: List<ServerPublicKeyCredentialDescriptor>?,
    val userVerification: UserVerificationRequirement?,
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
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }

    constructor(
        authOptionResponse: AuthOptionResponse,
    ) : this(
        authOptionResponse.challenge,
        authOptionResponse.timeout,
        authOptionResponse.rpId,
        authOptionResponse.allowCredentials,
        authOptionResponse.userVerification,
        authOptionResponse.extensions
    )
}
