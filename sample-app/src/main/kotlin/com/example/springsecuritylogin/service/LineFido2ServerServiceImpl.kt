package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.controller.AdapterServerResponse
import com.example.springsecuritylogin.controller.ServerPublicKeyCredentialCreationOptionsResponse
import com.linecorp.line.auth.fido.fido2.common.AttestationConveyancePreference
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorAttachment
import com.linecorp.line.auth.fido.fido2.common.AuthenticatorSelectionCriteria
import com.linecorp.line.auth.fido.fido2.common.PublicKeyCredentialRpEntity
import com.linecorp.line.auth.fido.fido2.common.UserVerificationRequirement
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests
import com.linecorp.line.auth.fido.fido2.common.extension.CredProtect
import com.linecorp.line.auth.fido.fido2.common.server.*
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import java.nio.charset.StandardCharsets
import java.util.Base64

@Service
class LineFido2ServerServiceImpl(
    private val restTemplate: RestTemplate
) : LineFido2ServerService {
    companion object {
        private const val RP_ID = "localhost"
        private const val RP_NAME = "test-rp"
        private const val ORIGIN = "http://localhost:8080"
        private const val REG_CHALLENGE_URI = "http://localhost:8081/fido2/reg/challenge"
        private const val REG_RESPONSE_URI = "http://localhost:8081/fido2/reg/response"
    }

    override fun getRegisterOption(
        userName: String,
        authenticatorAttachment: AuthenticatorAttachment?,
    ): Pair<ServerPublicKeyCredentialCreationOptionsResponse, String> {
        val rp = PublicKeyCredentialRpEntity()
        rp.id = RP_ID
        rp.name = RP_NAME

        val user = ServerPublicKeyCredentialUserEntity()
        user.name = userName
        user.id = createUserId(userName)
        user.displayName = userName

        val authenticatorSelection = AuthenticatorSelectionCriteria()
        authenticatorSelection.authenticatorAttachment = authenticatorAttachment
        authenticatorSelection.isRequireResidentKey = false
        authenticatorSelection.userVerification = UserVerificationRequirement.REQUIRED

        val regOptionRequest = RegOptionRequest
            .builder()
            .rp(rp)
            .user(user)
            .authenticatorSelection(authenticatorSelection)
            .attestation(AttestationConveyancePreference.none)
            .credProtect(CredProtect())
            .build()

        val request = HttpEntity(regOptionRequest, HttpHeaders())
        val response = restTemplate.postForObject(
            REG_CHALLENGE_URI,
            request,
            RegOptionResponse::class.java
        )

        return ServerPublicKeyCredentialCreationOptionsResponse(response!!) to response.sessionId
    }

    override fun verifyRegisterAttestation(
        sessionId: String,
        clientResponse: Attestation,
    ): AdapterServerResponse {
        val serverRegPublicKeyCredential = ServerRegPublicKeyCredential()
        serverRegPublicKeyCredential.id = clientResponse.id
        serverRegPublicKeyCredential.type = clientResponse.type
        serverRegPublicKeyCredential.response = clientResponse.response
        serverRegPublicKeyCredential.extensions = clientResponse.extensions

        val registerCredential = RegisterCredential()
        registerCredential.serverPublicKeyCredential = serverRegPublicKeyCredential
        registerCredential.rpId = RP_ID
        registerCredential.sessionId = sessionId
        registerCredential.origin = ORIGIN

        val request = HttpEntity(registerCredential, HttpHeaders())
        restTemplate.postForObject(REG_RESPONSE_URI, request, RegisterCredentialResult::class.java)

        return AdapterServerResponse(Status.OK, "")
    }

    private fun createUserId(username: String): String {
        val digest = Digests.sha256(username.toByteArray(StandardCharsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
