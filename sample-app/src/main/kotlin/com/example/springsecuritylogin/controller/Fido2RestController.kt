package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Attestation
import com.example.springsecuritylogin.service.LineFido2ServerService
import com.example.springsecuritylogin.service.Status
import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


@RestController
class Fido2RestController(
    private val lineFido2ServerService: LineFido2ServerService,
) {
    @PostMapping("/register/option")
    fun registerOption(
        @RequestBody optionsRequest: ServerPublicKeyCredentialCreationOptionsRequest,
        httpServletResponse: HttpServletResponse
    ): ServerPublicKeyCredentialCreationOptionsResponse {
        return try {
            val user = SampleUtil.getLoginUser()
            val (serverResponse, sessionId) = lineFido2ServerService.getRegisterOption(
                user!!.username,
                optionsRequest.authenticatorAttachment
            )

            SampleUtil.setFido2SessionId(sessionId, httpServletResponse)
            serverResponse
        } catch (e: Exception) {
            ServerPublicKeyCredentialCreationOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }

    @PostMapping("/register/verify")
    fun registerVerify(
        @RequestBody clientResponse: Attestation,
        httpServletRequest: HttpServletRequest
    ): AdapterServerResponse {
        val sessionId = SampleUtil.getFido2SessionId(httpServletRequest)
        if (sessionId.isNullOrEmpty()) {
            return AdapterServerResponse(Status.FAILED, "Cookie not found")
        }

        return try {
            lineFido2ServerService.verifyRegisterAttestation(
                sessionId,
                clientResponse
            )
        } catch (e: Exception) {
            AdapterServerResponse(Status.FAILED, e.message ?: "")
        }
    }

    @PostMapping("/authenticate/option")
    fun authenticateOption(
        httpServletResponse: HttpServletResponse
    ): ServerPublicKeyCredentialGetOptionsResponse {
        return try {
            val user = SampleUtil.getLoginUser()
            val (serverResponse, sessionId) = lineFido2ServerService.getAuthenticateOption(user!!.username)
            SampleUtil.setFido2SessionId(sessionId, httpServletResponse)
            serverResponse
        } catch (e: Exception) {
            ServerPublicKeyCredentialGetOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }
}
