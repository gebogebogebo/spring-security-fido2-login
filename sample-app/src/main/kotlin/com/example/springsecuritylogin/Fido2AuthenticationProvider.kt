package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.LineFido2ServerService
import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component

@Component
class Fido2AuthenticationProvider(
    private val lineFido2ServerService: LineFido2ServerService,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        if (authentication is AssertionAuthenticationToken) {
            // verify FIDO assertion
            if (!lineFido2ServerService.verifyAuthenticateAssertion(
                    authentication.credentials.sessionId,
                    authentication.credentials.assertion,
                )
            ) {
                throw BadCredentialsException("Invalid Assertion")
            }
        } else {
            throw BadCredentialsException("Invalid Authentication")
        }

        // set Authenticated
        val authorities = listOf(
            SimpleGrantedAuthority(SampleUtil.Auth.AUTHENTICATED_FIDO.value),
            SimpleGrantedAuthority("ROLE_USER")
        )

        val principalNew = User(
            authentication.principal.username,
            authentication.principal.password ?: "",
            authorities)

        var result = AssertionAuthenticationToken(principalNew, authentication.credentials, authorities)
        result.isAuthenticated = true
        return result
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return AssertionAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
