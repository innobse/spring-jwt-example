package ru.bse71.learnup.spring.auth.authservice.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;

import static java.util.stream.Collectors.toList;

/**
 * Created by bse71
 * Date: 10.09.2021
 * Time: 22:22
 */

@Component
public class JwtService {

    private static long ACCESS_TIMEOUT = 60;
    private static long REFRESH_TIMEOUT = 10 * 60;

    private final Algorithm jwtAlgorithm;
    private final Map<String, String> refreshTokens = new HashMap<>();

    public JwtService(@Value("${auth.jwt.secret}") String jwtSecret) {
        this.jwtAlgorithm = Algorithm.HMAC256(jwtSecret.getBytes());
    }

    public String generateAccessToken(String issuer, UserDetails user) {
        final List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(toList());

        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (ACCESS_TIMEOUT * 1000L)))
                .withIssuer(issuer)
                .withClaim("roles", roles)
                .sign(jwtAlgorithm);
    }

    public String generateRefreshToken(String issuer, UserDetails user) {

        final String refreshToken = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (REFRESH_TIMEOUT * 1000L)))
                .withIssuer(issuer)
                .sign(jwtAlgorithm);

        refreshTokens.put(user.getUsername(), refreshToken);
        return refreshToken;

    }

    public boolean verify(String token) {
        try {
            JWTVerifier verifier = JWT.require(jwtAlgorithm).build();
            DecodedJWT decodedJWT = verifier.verify(token);
            String username = decodedJWT.getSubject();
            String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
            final List<SimpleGrantedAuthority> authorities = Arrays.stream(roles)
                    .map(SimpleGrantedAuthority::new)
                    .collect(toList());
            final UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return true;
        } catch (Exception err) {
            err.printStackTrace();
            return false;
        }

    }

    public String getUsernameFromRefreshToken(String refreshToken) {
        try {
            JWTVerifier verifier = JWT.require(jwtAlgorithm).build();
            DecodedJWT decodedJWT = verifier.verify(refreshToken);
            final String subject = decodedJWT.getSubject();

            final String etalon = refreshTokens.get(subject);

            return (refreshToken.equals(etalon)) ? subject : null;
        } catch (Exception err) {
            return null;
        }

    }
}
