package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.LineFido2ServerService
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class Fido2AuthenticationProvider(
    private val lineFido2ServerService: LineFido2ServerService,
) : DaoAuthenticationProvider() {
    override fun additionalAuthenticationChecks(
        userDetails: UserDetails,
        authentication: UsernamePasswordAuthenticationToken
    ) {
        // verify password
        super.additionalAuthenticationChecks(userDetails, authentication)

        if (authentication is UsernamePasswordAssertionAuthenticationToken) {
            // verify FIDO assertion
            if (!lineFido2ServerService.verifyAuthenticateAssertion(
                    authentication.sessionId,
                    authentication.assertion,
                )
            ) {
                throw BadCredentialsException("Invalid Assertion")
            }
        } else {
            // verify password only
            val getCredentialsResult = lineFido2ServerService.getCredentialsWithUsername(userDetails.username)
            if (getCredentialsResult.credentials.isNotEmpty()) {
                throw BadCredentialsException("Two-factor authentication required")
            }
        }
    }

    override fun doAfterPropertiesSet() {}
}
