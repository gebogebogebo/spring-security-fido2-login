package com.example.springsecuritylogin

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher


@Configuration
class SampleWebSecurityConfig : WebSecurityConfigurerAdapter() {
    @Autowired
    private lateinit var authenticationProvider: Fido2AuthenticationProvider

    @Autowired
    fun configureGlobal(
        auth: AuthenticationManagerBuilder,
        userDetailsService: UserDetailsService,
    ) {
        authenticationProvider.setUserDetailsService(userDetailsService)
        auth.eraseCredentials(true)
            .authenticationProvider(authenticationProvider)
    }

    override fun configure(web: WebSecurity) {
        web.ignoring().antMatchers("/css/**","/js/**","/images/**");
    }

    override fun configure(http: HttpSecurity) {
        http
            .authorizeRequests()
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers("/login","/to-login-fido2","/login-fido2","/authenticate/**","/credentials/count").permitAll()
                .anyRequest().authenticated()
            .and()
            .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/mypage", true)

        // for h2db debug
        http.csrf().disable()
        http.headers().frameOptions().disable()

        val filter = UsernamePasswordAssertionAuthenticationFilter()
        filter.setRequiresAuthenticationRequestMatcher(AntPathRequestMatcher("/login", "POST"))
        filter.setAuthenticationManager(authenticationManagerBean())
        filter.setAuthenticationSuccessHandler(SimpleUrlAuthenticationSuccessHandler("/mypage"))
        filter.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        http.addFilterAt(filter, UsernamePasswordAssertionAuthenticationFilter::class.java)
    }
}
