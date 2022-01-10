package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.Assertion
import com.example.springsecuritylogin.util.SampleUtil
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


class AssertionAuthenticationFilter(
    pattern: String,
    httpMethod: String,
) : AbstractAuthenticationProcessingFilter(AntPathRequestMatcher(pattern, httpMethod)) {
    override fun attemptAuthentication(request: HttpServletRequest?, response: HttpServletResponse?): Authentication {
        if (request!!.method != "POST") {
            throw AuthenticationServiceException("Authentication method not supported: " + request.method)
        }

        val assertion = obtainAssertion(request)
        val principal = obtainPrincipal(request)

        val credentials = AssertionAuthenticationToken.Fido2Credentials(
            SampleUtil.getFido2SessionId(request),
            assertion
        )

        val authorities = principal.authorities.map {
            SimpleGrantedAuthority(it.authority)
        }

        val authRequest = AssertionAuthenticationToken(principal, credentials, authorities)
        setDetails(request, authRequest)
        return authenticationManager.authenticate(authRequest)
    }

    private fun obtainAssertion(request: HttpServletRequest): Assertion {
        val json = request.getParameter("assertion")
        if (json.isNullOrEmpty()) {
            throw AuthenticationServiceException("assertion")
        }
        return ObjectMapper().readValue(json, Assertion::class.java)
    }

    private fun obtainPrincipal(request: HttpServletRequest): User {
        val session = request.session
        val securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT") as SecurityContext
        val principal = securityContext.authentication.principal
        if (principal !is User) {
            throw AuthenticationServiceException("assertion")
        }
        return principal
    }

    private fun setDetails(request: HttpServletRequest?, authRequest: AssertionAuthenticationToken) {
        authRequest.details = authenticationDetailsSource.buildDetails(request)
    }

}
