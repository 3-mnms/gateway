package com.tekcit.gateway.config.security.repository;

import com.tekcit.gateway.config.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Mono.empty();
        }
        String token = authHeader.substring(7);
        try {
            Claims claims = jwtTokenProvider.getAllClaims(token);
            String username = jwtTokenProvider.getName(claims);
            String role = jwtTokenProvider.getRole(claims);

            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));

            JwtAuthenticationToken auth = new JwtAuthenticationToken(jwtTokenProvider.convertToSpringJwt(token), authorities);
            return Mono.just(new SecurityContextImpl(auth));
        } catch (ExpiredJwtException e) {
            return writeJson(exchange, HttpStatus.UNAUTHORIZED,
                    false, "AUTHENTICATION_ERROR", "액세스 토큰이 만료되었습니다.")
                    .then(Mono.empty());

        } catch (JwtException e) {
            return writeJson(exchange, HttpStatus.UNAUTHORIZED,
                    false, "AUTHENTICATION_ERROR", "유효하지 않은 액세스 토큰입니다.")
                    .then(Mono.empty());

        } catch (Exception e) {
            return writeJson(exchange, HttpStatus.UNAUTHORIZED,
                    false, "AUTHENTICATION_ERROR", "토큰 처리 중 오류가 발생했습니다.")
                    .then(Mono.empty());
        }
    }


    private Mono<Void> writeJson(ServerWebExchange exchange, HttpStatus status, boolean success, String code, String message) {
        var res = exchange.getResponse();
        if (res.isCommitted())
            return Mono.empty();
        res.setStatusCode(status);
        res.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = String.format("{\"success\":%s,\"code\":\"%s\",\"message\":\"%s\"}", success, code, message);
        var buf = res.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return res.writeWith(Mono.just(buf));
    }
}