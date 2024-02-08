package com.example.restservice.config;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest()
            .authenticated()
            .and()
            .x509()
            .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
            .userDetailsService(userDetailsService());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() { //Can use to validation user and roles
        return username -> {
            if (username.equals("Admin")) {
                return new User(username, "", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER"));
            } else if (username.equals("postman.pqc.test.com")) {
                return new User(username, "", AuthorityUtils.createAuthorityList("ROLE_USER"));
            } else {
                //403 status code
                throw new UsernameNotFoundException(String.format("User %s not found", username));
            }
        };
    }
}