package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.*
import com.example.springsecuritylogin.util.LineFido2Util
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
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
            val principal = SecurityContextHolder.getContext().authentication.principal
            val username = if (principal is UserDetails) {
                principal.username
            } else {
                throw UsernameNotFoundException("userId is null or empty")
            }

            val (serverResponse, sessionId) = lineFido2ServerService.getRegisterOption(
                username,
                optionsRequest.authenticatorAttachment
            )

            LineFido2Util.setFido2SessionId(sessionId, httpServletResponse)
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
        val sessionId = LineFido2Util.getFido2SessionId(httpServletRequest)
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
        @RequestBody optionsRequest: ServerPublicKeyCredentialGetOptionsRequest,
        httpServletResponse: HttpServletResponse
    ): ServerPublicKeyCredentialGetOptionsResponse {
        return try {
            val (serverResponse, sessionId) = lineFido2ServerService.getAuthenticateOption(
                optionsRequest.username,
            )
            LineFido2Util.setFido2SessionId(sessionId, httpServletResponse)
            serverResponse
        } catch (e: Exception) {
            ServerPublicKeyCredentialGetOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }

    @GetMapping("/credentials/count")
    fun credentialsCount(
        @RequestParam("username") username: String,
        httpServletRequest: HttpServletRequest
    ): CredentialsCountResponse {
        return try {
            val getCredentialsResult = lineFido2ServerService.getCredentialsWithUsername(username)
            CredentialsCountResponse(getCredentialsResult.credentials.count())
        } catch (e: Exception) {
            CredentialsCountResponse(Status.FAILED, e.message ?: "")
        }
    }
}
