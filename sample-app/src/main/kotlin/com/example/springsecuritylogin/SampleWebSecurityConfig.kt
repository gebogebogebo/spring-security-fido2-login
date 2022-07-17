package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.SampleUserDetailsService
import com.example.springsecuritylogin.util.SampleUtil
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
class SampleWebSecurityConfig : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var fido2AuthenticationProvider: Fido2AuthenticationProvider

    @Autowired
    private lateinit var userDetailsService: SampleUserDetailsService

    override fun configure(
        auth: AuthenticationManagerBuilder,
    ) {
        // Authentication Provider
        val daoAuthenticationProvider = DaoAuthenticationProvider().also {
            it.setUserDetailsService(userDetailsService)
        }
        auth.authenticationProvider(daoAuthenticationProvider)
        auth.authenticationProvider(fido2AuthenticationProvider)
    }

    override fun configure(web: WebSecurity) {
        web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }

    override fun configure(http: HttpSecurity) {
        http
            .authorizeRequests()
            .antMatchers("/h2-console/**").permitAll()
            .antMatchers("/login", "/authenticate/option").permitAll()
            .antMatchers("/login-fido2").hasAnyAuthority(SampleUtil.Auth.PRE_AUTHENTICATE_FIDO.value)
            .anyRequest().hasRole(SampleUtil.Role.USER.name)

        // Security Filter
        http
            .formLogin()
            .loginPage("/login").permitAll()
            .successHandler(UsernamePasswordAuthenticationSuccessHandler("/login-fido2","/mypage"))
            .failureUrl("/login?error")

        http
            .addFilterAt(createFido2AuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)

        // for h2db debug
        http.csrf().disable()
        http.headers().frameOptions().disable()
    }

    private fun createFido2AuthenticationFilter(): Fido2AuthenticationFilter {
        return Fido2AuthenticationFilter("/login-fido2", "POST").also {
            it.setAuthenticationManager(authenticationManagerBean())
            it.setAuthenticationSuccessHandler(SimpleUrlAuthenticationSuccessHandler("/mypage"))
            it.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }
    }
}
