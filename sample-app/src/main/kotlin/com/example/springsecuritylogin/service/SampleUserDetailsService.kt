package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MuserRepository
import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import java.util.Collections

@Service
class SampleUserDetailsService(
    private val mUserRepository: MuserRepository,
    private val lineFido2ServerService: LineFido2ServerService,
): UserDetailsService {

    // loadUserByUsername
    // - ログイン画面で login される度に実行される
    // - userId : 入力されたID
    // - 入力されたパスワードは渡ってこない
    // - userId が 不正な値の場合は throw UsernameNotFoundException("") する → /login?error に遷移する
    // - userId が 正しい値の場合は UserDetails クラスを生成して返す
    //      - Userクラスに password と authorities を設定する
    //      - return後 spring が password と authorities を verrify して認証成功の場合は .defaultSuccessUrl("/success") に遷移する
    override fun loadUserByUsername(userId: String?): UserDetails {
        if (userId == null || userId.isEmpty()) {
            throw UsernameNotFoundException("userId is null or empty")
        }

        val mUser = mUserRepository.findById(userId).orElse(null) ?: throw UsernameNotFoundException("Not found userId")

        val getCredentialsResult = lineFido2ServerService.getCredentialsWithUsername(userId)

        val authorities = if (getCredentialsResult.credentials.isEmpty()) {
            // TODO
            //Collections.emptyList()
            listOf(SimpleGrantedAuthority("ROLE_USER"))
        }else {
            listOf(SimpleGrantedAuthority(SampleUtil.Auth.PRE_AUTHENTICATE_FIDO.value))
        }

        return User(mUser.id,mUser.password, authorities)
    }

}
