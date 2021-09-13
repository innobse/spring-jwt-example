package ru.bse71.learnup.spring.auth.authservice.filters;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.bse71.learnup.spring.auth.authservice.jwt.JwtService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/**
 * Created by bse71
 * Date: 10.09.2021
 * Time: 23:40
 */

@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthorizationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String servletPath = request.getServletPath();
        if (!servletPath.equals("/api/auth") && !servletPath.equals("/api/tokenRefresh")) {
            String token = getToken(request);

            if (token != null) {
                jwtService.verify(token);
            }
        }

        filterChain.doFilter(request, response);
    }

    public static String getToken(HttpServletRequest request) {
        final String authHeader = request.getHeader(AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith(TOKEN_PREFIX)) {
            return authHeader.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    public static final String TOKEN_PREFIX = "Bearer ";
}
