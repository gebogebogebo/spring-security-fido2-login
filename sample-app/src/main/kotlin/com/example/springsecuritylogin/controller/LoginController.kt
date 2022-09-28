package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.core.AuthenticationException
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

    @GetMapping("password")
    fun loginPassowrd(model: Model): String {
        val user = SampleUtil.getLoginUser()
        model.addAttribute("username", user?.username)
        return "password"
    }

    @GetMapping("mypage")
    fun mypage(
        request: HttpServletRequest,
        model: Model,
    ): String {
        val user = SampleUtil.getLoginUser()
        model.addAttribute("username", user?.username)
        return "mypage"
    }
}
