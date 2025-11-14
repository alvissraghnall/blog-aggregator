package com.ominimie.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;


@SpringBootApplication
@EnableScheduling
public class AuthApplication {

    public static void main(final String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
}
