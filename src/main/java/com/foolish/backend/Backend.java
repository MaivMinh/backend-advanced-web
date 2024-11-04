package com.foolish.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories("com.foolish.backend.repository")
@EntityScan("com.foolish.backend.model")
public class Backend {

  public static void main(String[] args) {
    SpringApplication.run(Backend.class, args);
  }

}
