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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
class SampleWebSecurityConfig : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var fido2AuthenticationProvider: Fido2AuthenticationProvider

    @Autowired
    private lateinit var userDetailsService: SampleUserDetailsService

    /*
    @Autowired
    fun configureGlobal(
        auth: AuthenticationManagerBuilder,
        userDetailsService: UserDetailsService,
    ) {
        authenticationProvider.setUserDetailsService(userDetailsService)
        auth.eraseCredentials(true)
            .authenticationProvider(authenticationProvider)
    }
    */

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
            .antMatchers("/login", "/login-fido2", "/authenticate/option").permitAll()
            .anyRequest().hasRole(SampleUtil.Role.USER.name)

        // Security Filter
        http
            .formLogin()
            .loginPage("/login").permitAll()
            .successHandler(SampleAuthenticationSuccessHandler("/login-fido2"))
            .failureUrl("/login?error")

        http
            .addFilterAt(createAssertionAuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)

        // for h2db debug
        http.csrf().disable()
        http.headers().frameOptions().disable()
    }

    private fun createAssertionAuthenticationFilter(): Fido2AuthenticationFilter {
        return Fido2AuthenticationFilter("/login-fido2", "POST").also {
            it.setAuthenticationManager(authenticationManagerBean())
            it.setAuthenticationSuccessHandler(SampleAuthenticationSuccessHandler("/mypage"))
            it.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }
    }
}
