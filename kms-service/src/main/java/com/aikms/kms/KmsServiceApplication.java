package com.aikms.kms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableKafka
@EnableScheduling
public class KmsServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(KmsServiceApplication.class, args);
    }
}
