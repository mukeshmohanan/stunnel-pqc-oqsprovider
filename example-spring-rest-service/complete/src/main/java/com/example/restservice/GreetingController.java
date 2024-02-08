package com.example.restservice;

import java.util.concurrent.atomic.AtomicLong;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.annotation.Secured;

@RestController
public class GreetingController {

    @GetMapping("admin")
    @Secured("ROLE_ADMIN")
    public String apiAdmin() {
        return "ADMIN hereeeee!";
    }

    @GetMapping("user")
    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    public String apiUser() {
        return "This is a User";
    }
}
