package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.SampleUserDetailsService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


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
            .antMatchers("/login", "/to-login-fido2", "/login-fido2", "/authenticate/**", "/credentials/count")
            .permitAll()
            .anyRequest().authenticated()
        /*
    .and()
    .formLogin()
        .loginPage("/login").permitAll()
        .defaultSuccessUrl("/mypage", true)
        */

        // for h2db debug
        http.csrf().disable()
        http.headers().frameOptions().disable()

        // Security Filter
        http.addFilterAt(createAssertionAuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)
        http.addFilterAt(createUsernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)
    }

    private fun createUsernamePasswordAuthenticationFilter(): UsernamePasswordAuthenticationFilter {
        return UsernamePasswordAuthenticationFilter().also {
            it.setRequiresAuthenticationRequestMatcher(AntPathRequestMatcher("/login", "POST"))
            it.setAuthenticationManager(authenticationManagerBean())
            it.setAuthenticationSuccessHandler(SampleForwardAuthenticationSuccessHandler("/login-fido2"))
            it.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }
    }

    private fun createAssertionAuthenticationFilter(): AssertionAuthenticationFilter {
        return AssertionAuthenticationFilter("/login-fido2", "POST").also {
            it.setAuthenticationManager(authenticationManagerBean())
            it.setAuthenticationSuccessHandler(SampleForwardAuthenticationSuccessHandler("/mypage"))
            it.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }
    }
}
