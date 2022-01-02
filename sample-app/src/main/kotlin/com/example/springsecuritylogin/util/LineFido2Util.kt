package com.example.springsecuritylogin.util

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class LineFido2Util {

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

    }
}