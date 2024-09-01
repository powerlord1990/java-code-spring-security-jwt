package com.company.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleController {

    @GetMapping("/admin")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public String adminOnly() {
        return "This is an admin page!";
    }

    @GetMapping("/moderator")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorOnly() {
        return "This is a moderator page!";
    }
}
