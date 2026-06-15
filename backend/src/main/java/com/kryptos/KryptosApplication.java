package com.kryptos;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class KryptosApplication {
    public static void main(String[] args) {
        SpringApplication.run(KryptosApplication.class, args);
    }
}
