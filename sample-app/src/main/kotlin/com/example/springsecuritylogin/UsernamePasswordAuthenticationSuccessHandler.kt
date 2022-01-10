package com.example.springsecuritylogin

import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
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
            it.authority == SampleUtil.Auth.PRE_AUTHENTICATE_FIDO.value
        } ?: false

        if (needFido) {
            response?.sendRedirect(redirectUrl)
        } else {
            super.onAuthenticationSuccess(request, response, authentication)
        }
    }
}
