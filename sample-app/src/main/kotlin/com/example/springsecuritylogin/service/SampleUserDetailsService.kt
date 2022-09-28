package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MuserRepository
import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service


@Service
class SampleUserDetailsService(
    private val mUserRepository: MuserRepository,
) : UserDetailsService {
    override fun loadUserByUsername(userId: String?): UserDetails {
        if (userId.isNullOrEmpty()) {
            throw UsernameNotFoundException("userId is null or empty")
        }

        val mUser = mUserRepository.findById(userId).orElse(null) ?: throw UsernameNotFoundException("Not found userId")

        val authorities = if (SampleUtil.isUsernameAuthenticated()) {
            listOf(
                SimpleGrantedAuthority(SampleUtil.Auth.AUTHENTICATED_PASSWORD.value),
                SimpleGrantedAuthority(SampleUtil.Role.USER.value)
            )
        } else {
            listOf(SimpleGrantedAuthority(SampleUtil.Auth.AUTHENTICATED_USERNAME.value))
        }

        return User(mUser.id, mUser.password, authorities)
    }
}
