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
    private val lineFido2ServerService: LineFido2ServerService,
) : UserDetailsService {
    override fun loadUserByUsername(userId: String?): UserDetails {
        if (userId == null || userId.isEmpty()) {
            throw UsernameNotFoundException("userId is null or empty")
        }

        val mUser = mUserRepository.findById(userId).orElse(null) ?: throw UsernameNotFoundException("Not found userId")

        val getCredentialsResult = lineFido2ServerService.getCredentialsWithUsername(userId)

        val authorities = if (getCredentialsResult.credentials.isEmpty()) {
            listOf(
                SimpleGrantedAuthority(SampleUtil.Auth.AUTHENTICATED_PASSWORD.value),
                SimpleGrantedAuthority(SampleUtil.Role.USER.value)
            )
        } else {
            listOf(
                SimpleGrantedAuthority(SampleUtil.Auth.PRE_AUTHENTICATE_FIDO.value)
            )
        }

        return User(mUser.id, mUser.password, authorities)
    }
}
