package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.controller.AdapterServerResponse
import com.example.springsecuritylogin.controller.ServerPublicKeyCredentialCreationOptionsResponse
import com.example.springsecuritylogin.controller.ServerPublicKeyCredentialGetOptionsResponse
import com.linecorp.line.auth.fido.fido2.common.*
import com.linecorp.line.auth.fido.fido2.common.crypto.Digests
import com.linecorp.line.auth.fido.fido2.common.extension.CredProtect
import com.linecorp.line.auth.fido.fido2.common.server.*
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate
import org.springframework.web.util.UriComponentsBuilder
import java.nio.charset.StandardCharsets
import java.util.Base64

@Service
class LineFido2ServerServiceImpl(
    private val restTemplate: RestTemplate
) : LineFido2ServerService {
    companion object {
        private const val RP_ID = "localhost"
        private const val RP_NAME = "LINE-FIDO2-Server Spring-Security-Sample-App"
        private const val ORIGIN = "http://localhost:8080"
        private const val REG_CHALLENGE_URI = "http://localhost:8081/fido2/reg/challenge"
        private const val REG_RESPONSE_URI = "http://localhost:8081/fido2/reg/response"
        private const val AUTH_CHALLENGE_URI = "http://localhost:8081/fido2/auth/challenge"
        private const val AUTH_RESPONSE_URI = "http://localhost:8081/fido2/auth/response"
        private const val CREDENTIALS_URI = "http://localhost:8081/fido2/credentials/"
    }

    override fun getRegisterOption(
        userName: String,
        authenticatorAttachment: AuthenticatorAttachment?,
        requireResidentKey: Boolean,
    ): Pair<ServerPublicKeyCredentialCreationOptionsResponse, String> {
        val rp = PublicKeyCredentialRpEntity()
        rp.id = RP_ID
        rp.name = RP_NAME

        val user = ServerPublicKeyCredentialUserEntity()
        user.name = userName
        user.id = createUserId(userName)
        user.displayName = "$RP_NAME $userName"

        val authenticatorSelection = AuthenticatorSelectionCriteria()
        authenticatorSelection.authenticatorAttachment = authenticatorAttachment
        authenticatorSelection.isRequireResidentKey = requireResidentKey
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

    override fun getAuthenticateOption(
        userName: String?,
    ): Pair<ServerPublicKeyCredentialGetOptionsResponse, String> {
        val authOptionRequest = if (userName.isNullOrEmpty()) {
            AuthOptionRequest
                .builder()
                .rpId(RP_ID)
                .userVerification(UserVerificationRequirement.REQUIRED)
                .build()
        } else {
            AuthOptionRequest
                .builder()
                .rpId(RP_ID)
                .userId(createUserId(userName!!))
                .userVerification(UserVerificationRequirement.DISCOURAGED)
                .build()
        }

        val request = HttpEntity(authOptionRequest, HttpHeaders())
        val response = restTemplate.postForObject(AUTH_CHALLENGE_URI, request, AuthOptionResponse::class.java)
        if (response?.serverResponse?.internalErrorCode != 0) {
            return ServerPublicKeyCredentialGetOptionsResponse(
                Status.FAILED,
                response?.serverResponse!!.internalErrorCodeDescription
            ) to ""
        }

        return ServerPublicKeyCredentialGetOptionsResponse(response) to response.sessionId
    }

    override fun verifyAuthenticateAssertion(
        sessionId: String,
        assertion: Assertion,
    ): Boolean {
        val serverAuthPublicKeyCredential = ServerAuthPublicKeyCredential()
        serverAuthPublicKeyCredential.response = assertion.response
        serverAuthPublicKeyCredential.id = assertion.id
        serverAuthPublicKeyCredential.type = assertion.type
        serverAuthPublicKeyCredential.extensions = assertion.extensions

        val verifyCredential = VerifyCredential()
        verifyCredential.serverPublicKeyCredential = serverAuthPublicKeyCredential
        verifyCredential.rpId = RP_ID
        verifyCredential.sessionId = sessionId
        verifyCredential.origin = ORIGIN

        val request = HttpEntity(verifyCredential, HttpHeaders())

        return try {
            val response = restTemplate.postForObject(AUTH_RESPONSE_URI, request, VerifyCredentialResult::class.java)
            true
        } catch (e: Exception) {
            false
        }
    }

    override fun getCredentialsWithUsername(
        username: String,
    ): List<ServerUserKey> {
        val userId = createUserId(username)
        val uriComponentsBuilder = UriComponentsBuilder.fromUriString(CREDENTIALS_URI)
        val uri = uriComponentsBuilder
            .queryParam("rpId", RP_ID)
            .queryParam("userId", userId)
            .build().toUri()
        val response = restTemplate.exchange(uri, HttpMethod.GET, null, GetCredentialsResult::class.java)
        return response.body!!.credentials
    }

    override fun getCredentialWithCredentialId(
        credentialId: String
    ): ServerUserKey {
        val uriComponentsBuilder = UriComponentsBuilder.fromUriString(CREDENTIALS_URI)
        val uri = uriComponentsBuilder
            .path(credentialId!!)
            .queryParam("rpId", RP_ID)
            .build().toUri()
        val response = restTemplate.exchange(uri, HttpMethod.GET, null, GetCredentialResult::class.java)
        return response.body!!.credential
    }

    private fun createUserId(username: String): String {
        val digest = Digests.sha256(username.toByteArray(StandardCharsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }
}
