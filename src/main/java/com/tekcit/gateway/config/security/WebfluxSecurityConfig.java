package com.tekcit.gateway.config.security;

import com.tekcit.gateway.config.gateway.filter.JwtToHeaderFilter;
import com.tekcit.gateway.config.security.jwt.JwtTokenProvider;
import com.tekcit.gateway.config.security.repository.JwtSecurityContextRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class WebfluxSecurityConfig {


    private final JwtTokenProvider jwtTokenProvider;
    private final JwtToHeaderFilter jwtToHeaderFilter;
    private final JwtSecurityContextRepository jwtSecurityContextRepository;

    // password encoder 설정
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(auth -> auth
                        .anyExchange().permitAll()
                )
                .securityContextRepository(jwtSecurityContextRepository)
                .build();
    }
}