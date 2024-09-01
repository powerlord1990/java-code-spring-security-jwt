package com.company.security;

import com.company.security.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Логика аутентификации с использованием токена
        String token = (String) authentication.getCredentials();
        if (validateToken(token)) {
            return createAuthentication(token);
        } else {
            throw new BadCredentialsException("Invalid JWT token");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public boolean validateToken(String token) {
        // Логика верификации токена
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            System.out.println("exception occurred with validate token: " + e.getMessage());
            return false;
        }
    }

    public Authentication createAuthentication(String token) {
        // Логика создания объекта Authentication на основе токена
        UserDetails userDetails = extractUserDetailsFromToken(token);
        // Создание объекта Authentication
        return new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities());
    }

    private UserDetails extractUserDetailsFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody(); // Получение тела из JWT

        String username = claims.getSubject();
        return new User(username, "", getAuthoritiesFromClaims(claims));
    }

    private Key getSigningKey() {
        return JwtUtil.getSigningKey();
    }

    private Collection<? extends GrantedAuthority> getAuthoritiesFromClaims(Claims claims) {
        List<String> roles = claims.get("roles", List.class);
        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}
