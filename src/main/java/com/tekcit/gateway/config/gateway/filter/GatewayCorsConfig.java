package com.tekcit.gateway.config.gateway.filter;

import com.tekcit.gateway.config.gateway.property.CorsProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class GatewayCorsConfig {


    private final CorsProperties corsProperties;


    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        for(String url : corsProperties.getUrl()){
            config.addAllowedOrigin(url);
        }
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }

    @Bean
    public WebFilter webSocketCorsFilter() {
        return (ServerWebExchange exchange, WebFilterChain chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String upgradeHeader = request.getHeaders().getFirst(HttpHeaders.UPGRADE);

            if ("websocket".equalsIgnoreCase(upgradeHeader)) {
                String origin = request.getHeaders().getOrigin();
                CorsConfiguration corsConfig = new CorsConfiguration();

                if (origin != null && corsProperties.getUrl().contains(origin)) {
                    corsConfig.addAllowedOrigin(origin);
                    corsConfig.setAllowCredentials(true);
                    corsConfig.addAllowedMethod("*");
                    corsConfig.addAllowedHeader("*");
                }

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", corsConfig);
            }

            return chain.filter(exchange);
        };
    }
}