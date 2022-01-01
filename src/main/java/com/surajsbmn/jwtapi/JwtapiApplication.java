package com.surajsbmn.jwtapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.surajsbmn.jwtapi.model.Role;
import com.surajsbmn.jwtapi.model.User;
import com.surajsbmn.jwtapi.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtapiApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtapiApplication.class, args);
    }


    // Load test data into DB
    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));

            userService.saveUser(
                    new User(null, "Anakin Skywalker", "darklord", "123456", new ArrayList<>()));
            userService.saveUser(
                    new User(null, "Kylo Ren", "kyloren", "123456", new ArrayList<>()));
            userService.saveUser(
                    new User(null, "Luke Skywalker", "lskywalker", "123456", new ArrayList<>()));

            userService.addRoleToUser("darklord", "ROLE_ADMIN");
            userService.addRoleToUser("darklord", "ROLE_USER");
            userService.addRoleToUser("kyloren", "ROLE_USER");
            userService.addRoleToUser("lskywalker", "ROLE_USER");
        };
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
