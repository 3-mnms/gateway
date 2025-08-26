package com.tekcit.gateway.config.gateway.property;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Getter @Setter
@ConfigurationProperties(prefix = "cors")
public class CorsProperties {
    private List<String> url;
}
