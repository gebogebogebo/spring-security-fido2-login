package com.example.springsecuritylogin.util

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class SampleUtil {

    enum class Auth(val value: String) {
        AUTHENTICATED_PASSWORD("authenticated-password"),
        PRE_AUTHENTICATE_FIDO("pre-authenticate-fido"),
        AUTHENTICATED_FIDO("authenticated-fido"),
    }

    enum class Role(val value: String) {
        USER("ROLE_USER")
    }

    companion object {
        private const val COOKIE_NAME = "fido2-session-id"

        fun setFido2SessionId(
            sessionId: String,
            httpServletResponse: HttpServletResponse
        ) {
            val cookie = Cookie(COOKIE_NAME, sessionId)
            cookie.path = ("/")
            httpServletResponse.addCookie(cookie)
        }

        fun getFido2SessionId(
            httpServletRequest: HttpServletRequest
        ): String {
            val cookies = httpServletRequest.cookies
            if (cookies == null || cookies.isEmpty()) {
                return ""
            }
            var sessionId = ""
            for (cookie in cookies) {
                if (cookie.name == COOKIE_NAME) {
                    sessionId = cookie.value
                    break
                }
            }
            return sessionId
        }

        fun getLoginUser(): User? {
            val principal = SecurityContextHolder.getContext().authentication.principal
            return if (principal is User) {
                principal
            } else {
                null
            }
        }
    }
}
