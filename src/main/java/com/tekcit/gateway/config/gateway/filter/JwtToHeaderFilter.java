package com.tekcit.gateway.config.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tekcit.gateway.config.security.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Component
@RequiredArgsConstructor
public class JwtToHeaderFilter implements GlobalFilter, Ordered {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .doOnNext(ctx -> System.out.println("SecurityContext 있음: " + ctx))
                .map(securityContext -> securityContext.getAuthentication())
                .doOnNext(auth -> System.out.println("Authentication 있음: " + auth))
                .cast(JwtAuthenticationToken.class)
                .doOnNext(auth -> System.out.println("JwtAuthenticationToken으로 캐스팅 성공"))
                .flatMap(auth -> {
                    String jwt = auth.getToken().getTokenValue();
                    Claims claims = jwtTokenProvider.getAllClaims(jwt);
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .headers(h ->{
                                h.set("X-User-Id", jwtTokenProvider.getSubject(claims));
                                h.set("X-User-Name", jwtTokenProvider.getName(claims));
                                h.set("X-User-Role", jwtTokenProvider.getClaimAsString(claims, "role"));
                            })
                            .build();
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .switchIfEmpty(Mono.defer(() -> {
                    System.out.println("SecurityContext 없거나 인증 안 됨");
                    return chain.filter(exchange);
                }));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
