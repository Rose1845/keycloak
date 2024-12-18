package com.rose.keycloak.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class KeycloakController {

    @GetMapping
    @PreAuthorize("hasRole('CLIENT_USER')")
    public String hello() {
        return "Hello from Spring boot & Keycloak";
    }

    @GetMapping("/hello-2")
    @PreAuthorize("hasRole('CLIENT_ADMIN')")
    public String hello2() {
        return "Hello from Spring boot & Keycloak - ADMIN";
    }
}