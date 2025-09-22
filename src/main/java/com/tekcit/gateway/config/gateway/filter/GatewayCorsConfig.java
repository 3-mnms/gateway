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


//    @Bean
//    public CorsWebFilter corsWebFilter() {
//        CorsConfiguration config = new CorsConfiguration();
//        for(String url : corsProperties.getUrl()){
//            config.addAllowedOrigin(url);
//        }
//        config.addAllowedMethod("*");
//        config.addAllowedHeader("*");
//        config.setAllowCredentials(true);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//
//        source.registerCorsConfiguration("/**", config);
//
//        return new CorsWebFilter(source);
//    }
//

        @Bean
        public WebFilter corsFilter() {
            return (exchange, chain) -> {
                String path = exchange.getRequest().getURI().getPath();
                if (path.startsWith("/ws")) {
                    // WebSocket 경로는 CORS 필터 건너뛰기 (서버로 그대로 전달)
                    return chain.filter(exchange);
                }

                CorsConfiguration config = new CorsConfiguration();
                for (String url : corsProperties.getUrl()) {
                    config.addAllowedOrigin(url);
                }
                config.addAllowedMethod("*");
                config.addAllowedHeader("*");
                config.setAllowCredentials(true);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", config);

                return new CorsWebFilter(source).filter(exchange, chain);
            };
        }


}