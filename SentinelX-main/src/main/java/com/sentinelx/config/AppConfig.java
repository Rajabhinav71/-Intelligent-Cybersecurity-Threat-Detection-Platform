package com.sentinelx.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {
    // RestTemplate is used by DetectionService to call the Python ML microservice
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
