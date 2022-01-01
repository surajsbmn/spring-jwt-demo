package com.surajsbmn.jwtapi.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private CustomAuthorizationFilter customAuthorizationFilter;

    @Autowired
    private JWTManager jwtManager;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // set the UserDetails provider and password encoder
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean(), jwtManager);
        // override default /login path
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        // disable csrf and set Session policy to stateless
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Public paths that don't need authentication
        http.authorizeRequests().antMatchers("/api/public/**", "/api/token/refresh/**").permitAll();

        // Authorize paths based on role
        http.authorizeRequests()
                .antMatchers(GET, "/api/user/**")
                .hasAnyAuthority("ROLE_USER");
        http.authorizeRequests()
                .antMatchers(POST, "/api/user/save/**","/api/role/save/**")
                .hasAnyAuthority("ROLE_ADMIN");

        // Secure all other routes
        http.authorizeRequests().anyRequest().authenticated();

        // add the Authentication and Authorization filters
        http.addFilter(customAuthenticationFilter);
        http.addFilterBefore(customAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
