package com.example.springsecuritylogin.controller

import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.WebAttributes.AUTHENTICATION_EXCEPTION
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpSession

@Controller
class LoginController {
    @GetMapping("/")
    fun root(): String {
        return "redirect:mypage"
    }

    // 起動時 または 認証失敗時に表示される
    // - 認証失敗時は error パラメータが spring によって付与される
    @GetMapping("login")
    fun login(
        @RequestParam(value = "error", required = false) error: String?,
        @RequestParam(value = "logout", required = false) logout: String?,
        model: Model,
        session: HttpSession,
    ): String {
        model.addAttribute("showErrorMsg", false)
        model.addAttribute("showLogoutedMsg", false)

        if (error != null) {
            val ex = session.getAttribute(AUTHENTICATION_EXCEPTION) as AuthenticationException?
            if (ex != null) {
                model.addAttribute("showErrorMsg", true)
                model.addAttribute("errorMsg", ex.message)
            }
        } else if (logout != null) {
            model.addAttribute("showLogoutedMsg", true)
            model.addAttribute("logoutedMsg", "Logouted")
        }

        return "login"
    }

    @GetMapping("mypage")
    fun mypage(
        request: HttpServletRequest,
        model: Model,
    ): String {
        val session = request.session
        val securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT") as SecurityContext
        val authentication = securityContext.authentication
        val user = authentication.principal as User

        model.addAttribute("userName", user.username)

        return "mypage"
    }
}
