package com.tekcit.gateway.config.swagger;


import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiGatewayConfig {

    @Bean
    public GroupedOpenApi apiGroup(){
        return GroupedOpenApi.builder()
                .group("all-services")
                .pathsToMatch("/**")
                .build();
    }
}
