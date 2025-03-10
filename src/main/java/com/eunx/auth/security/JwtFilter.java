package com.eunx.auth.security;

import com.eunx.auth.config.JwtTokenProvider;
import com.eunx.auth.service.BlacklistService;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private BlacklistService blacklistService;

    private final List<AntPathRequestMatcher> publicEndpoints = Arrays.asList(
            new AntPathRequestMatcher("/api/auth/register"),
            new AntPathRequestMatcher("/api/auth/login"),
            new AntPathRequestMatcher("/api/auth/resend-otp"),
            new AntPathRequestMatcher("/api/auth/verify-otp"),
            new AntPathRequestMatcher("/api/auth/forgot-password"),
            new AntPathRequestMatcher("/api/auth/verify-reset-otp"),
            new AntPathRequestMatcher("/api/auth/login-user-reset-password"),
            new AntPathRequestMatcher("/api/auth/reset-forgotten-password")
    );

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod()) ||
                publicEndpoints.stream().anyMatch(matcher -> matcher.matches(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Skip filter for public endpoints and OPTIONS requests
        if (shouldNotFilter(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = jwtTokenProvider.getTokenFromRequest(request);
        System.out.println("Extracted Token: " + token);

        if (token != null) {
            try {
                boolean isBlacklisted = blacklistService.isTokenBlacklisted(token);
                System.out.println("Is Token Blacklisted: " + isBlacklisted);
                if (isBlacklisted) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been invalidated");
                    return;
                }

                boolean isValid = jwtTokenProvider.validateToken(token);
                System.out.println("Is Token Valid: " + isValid);
                if (isValid) {
                    Claims claims = jwtTokenProvider.getClaimsFromToken(token);
                    System.out.println("Claims: " + claims);

                    String username = jwtTokenProvider.getUsernameFromToken(token);
                    System.out.println("Username from Token: " + username);

                    List<String> roles = (List<String>) claims.get("roles");
                    System.out.println("Roles: " + roles);

                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    request.setAttribute("username", username);
                    System.out.println("Authentication set for username: " + username);
                } else {
                    System.err.println("Invalid or expired token");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
                    return;
                }
            } catch (Exception e) {
                System.err.println("Error validating token: " + e.getMessage());
                e.printStackTrace();
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                return;
            }
        } else {
            System.err.println("Token is missing in request");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token is missing");
            return;
        }

        filterChain.doFilter(request, response);
    }
}