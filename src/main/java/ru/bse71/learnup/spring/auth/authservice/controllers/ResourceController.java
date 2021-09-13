package ru.bse71.learnup.spring.auth.authservice.controllers;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by bse71
 * Date: 10.09.2021
 * Time: 22:12
 */

@RestController
public class ResourceController {

    @GetMapping("/resource")
    public String auth() {
        final Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return "SUCCESS AUTH: " + principal;
    }
}
