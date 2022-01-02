package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.Assertion
import com.example.springsecuritylogin.util.LineFido2Util
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class UsernamePasswordAssertionAuthenticationFilter : UsernamePasswordAuthenticationFilter() {
    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        if (request!!.method != "POST") {
            throw AuthenticationServiceException("Authentication method not supported: " + request.method)
        }

        val json = request.getParameter("assertion")
        if (!json.isNullOrEmpty()) {
            val username = obtainUsername(request) ?: ""
            val password = obtainPassword(request) ?: ""
            val sessionId = LineFido2Util.getFido2SessionId(request)
            val assertion = ObjectMapper().readValue(json, Assertion::class.java)

            val authRequest = UsernamePasswordAssertionAuthenticationToken(username, password, sessionId, assertion)
            setDetails(request, authRequest)

            return authenticationManager.authenticate(authRequest)
        } else {
            return super.attemptAuthentication(request, response)
        }
    }
}