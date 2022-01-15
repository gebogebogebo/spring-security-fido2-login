package com.example.springsecuritylogin

import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class UsernamePasswordAuthenticationSuccessHandler(
    private val nextAuthUrl: String,
    defaultTargetUrl: String
) : SimpleUrlAuthenticationSuccessHandler(defaultTargetUrl) {
    override fun onAuthenticationSuccess(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication
    ) {
        val needFido = authentication.authorities?.any {
            it.authority == SampleUtil.Auth.PRE_AUTHENTICATE_FIDO.value
        } ?: false

        if (needFido) {
            response?.sendRedirect(nextAuthUrl)
        } else {
            super.onAuthenticationSuccess(request, response, authentication)
        }
    }
}
