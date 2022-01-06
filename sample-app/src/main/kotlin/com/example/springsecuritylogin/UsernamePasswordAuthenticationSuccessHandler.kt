package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.LineFido2ServerService
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import java.util.Collections
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class SampleForwardAuthenticationSuccessHandler(
    private val redirectUrl: String
) : SavedRequestAwareAuthenticationSuccessHandler() {
    override fun onAuthenticationSuccess(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication
    ) {
        val needFido = authentication.authorities?.any {
            // TODO
            it.authority == "pre-authenticate-fido"
        } ?: false

        if (needFido) {
            response?.sendRedirect(redirectUrl)
        } else {
            super.onAuthenticationSuccess(request, response, authentication)
        }
    }
}
