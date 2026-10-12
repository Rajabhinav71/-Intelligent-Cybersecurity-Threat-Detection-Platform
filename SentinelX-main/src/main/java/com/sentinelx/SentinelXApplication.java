package com.sentinelx;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling   // needed for periodic cleanup tasks
public class SentinelXApplication {
    public static void main(String[] args) {
        SpringApplication.run(SentinelXApplication.class, args);
        System.out.println("SentinelX is running — monitoring started.");
    }
}
