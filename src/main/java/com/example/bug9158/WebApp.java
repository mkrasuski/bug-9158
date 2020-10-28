package com.example.bug9158;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WebApp {

    @GetMapping("/admin")
    @Secured({"ROLE_ADMIN"})
    protected String adminMethod() {
        return "@Secured({ROLE_ADMIN})\n";
    }

    @GetMapping("/user")
    @Secured({"ROLE_USER"})
    protected String usersMethod() {
        return "@Secured({ROLE_USER})\n";
    }

    @GetMapping("/userPre")
    @PreAuthorize("hasRole('USER')")
    protected String usersMethodWorking() {
        return "@PreAuthorize(hasRole('USER'))\n";
    }
}
