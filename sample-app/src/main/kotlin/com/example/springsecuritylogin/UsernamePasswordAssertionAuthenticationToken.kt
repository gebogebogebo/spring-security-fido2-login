package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.Assertion
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

class UsernamePasswordAssertionAuthenticationToken(
    username:String,
    password:String,
    val sessionId: String,
    val assertion: Assertion,
): UsernamePasswordAuthenticationToken(username,password)