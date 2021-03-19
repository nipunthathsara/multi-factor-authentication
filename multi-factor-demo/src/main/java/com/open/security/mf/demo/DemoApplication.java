package com.open.security.mf.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Multi factor authentication demo application.
 */

@SpringBootApplication(scanBasePackages = {"com.open.security", "org.open.security"})
public class DemoApplication {

    public static void main(String[] args) {

        SpringApplication.run(DemoApplication.class, args);
    }
}
