package com.example.springsecuritylogin

import com.example.springsecuritylogin.repository.MuserRepository
import com.example.springsecuritylogin.service.LineFido2ServerService
import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component

@Component
class Fido2AuthenticationProvider(
    private val mUserRepository: MuserRepository,
    private val lineFido2ServerService: LineFido2ServerService,
) : AuthenticationProvider {
    override fun authenticate(authentication: Authentication): Authentication {
        val userName = if (authentication is AssertionAuthenticationToken) {
            // verify FIDO assertion
            if (!lineFido2ServerService.verifyAuthenticateAssertion(
                    authentication.credentials.sessionId,
                    authentication.credentials.assertion,
                )
            ) {
                throw BadCredentialsException("Invalid Assertion")
            }
            val credential = lineFido2ServerService.getCredentialWithCredentialId(authentication.credentials.assertion.id)

            mUserRepository.findById(credential.name)
                .orElse(null) ?: throw BadCredentialsException("Invalid Assertion")

            credential.name
        } else {
            throw BadCredentialsException("Invalid Authentication")
        }

        // set Authenticated
        val authorities = listOf(
            SimpleGrantedAuthority(SampleUtil.Auth.AUTHENTICATED_FIDO.value),
            SimpleGrantedAuthority(SampleUtil.Role.USER.value)
        )

        val principalNew = User(userName,"", authorities)

        var result = AssertionAuthenticationToken(principalNew, authentication.credentials, authorities)
        result.isAuthenticated = true
        return result
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return AssertionAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
