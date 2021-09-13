package ru.bse71.learnup.spring.auth.authservice.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.bse71.learnup.spring.auth.authservice.jwt.JwtService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static ru.bse71.learnup.spring.auth.authservice.filters.JwtAuthorizationFilter.TOKEN_PREFIX;
import static ru.bse71.learnup.spring.auth.authservice.filters.JwtAuthorizationFilter.getToken;

/**
 * Created by bse71
 * Date: 10.09.2021
 * Time: 22:12
 */

@RestController
public class TokenController {

    private final JwtService jwtService;
    private final UserDetailsService userService;

    @Autowired
    public TokenController(UserDetailsService userService, JwtService jwtService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    @GetMapping("/api/tokenRefresh")
    public void auth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String token = getToken(request);
        String username = null;

        if (token != null) {
            username = jwtService.getUsernameFromRefreshToken(token);
            if (username != null) {
                final UserDetails user = userService.loadUserByUsername(username);
                if (user != null) {
                    final String accessToken = jwtService.generateAccessToken(request.getRequestURI(), user);
                    final String refreshToken = jwtService.generateRefreshToken(request.getRequestURI(), user);
                    response.setHeader("access_token", accessToken);
                    response.setHeader("refresh_token", refreshToken);
                    return;
                }
            }
        }

        response.sendRedirect("/api/auth");
    }
}
