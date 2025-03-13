package com.eunx.auth.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long accessTokenExpirationTime;

    @Value("${jwt.refresh.expiration:604800000}") // Default to 7 days in milliseconds
    private long refreshTokenExpirationTime;

    private final long preAuthTokenExpirationTime = 600 * 1000; // 10 minutes for pre-auth tokens

    // Generate full-access token
    public String generateToken(String username, List<String> roles) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessTokenExpirationTime);
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .claim("type", "access")
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, secretKey.getBytes(StandardCharsets.UTF_8))
                .compact();
    }

    // Generate pre-auth token for 2FA
    public String generatePreAuthToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + preAuthTokenExpirationTime);
        return Jwts.builder()
                .setSubject(username)
                .claim("preAuth", true) // Mark as pre-auth token
                .claim("type", "access")
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, secretKey.getBytes(StandardCharsets.UTF_8))
                .compact();
    }

    // Generate refresh token
    public String generateRefreshToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenExpirationTime);
        return Jwts.builder()
                .setSubject(username)
                .claim("type", "refresh")
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, secretKey.getBytes(StandardCharsets.UTF_8))
                .compact();
    }

    public String getUsernameFromToken(String token) {
        return getClaimsFromToken(token).getSubject();
    }

    public Claims getClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = getClaimsFromToken(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            throw new RuntimeException("Invalid or expired token", e);
        }
    }

    public String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean hasRole(String token, String role) {
        Claims claims = getClaimsFromToken(token);
        List<String> roles = claims.get("roles", List.class);
        return roles != null && roles.contains(role);
    }

    // New method to check if token is a pre-auth token
    public boolean isPreAuthToken(String token) {
        Claims claims = getClaimsFromToken(token);
        Boolean preAuth = claims.get("preAuth", Boolean.class);
        return preAuth != null && preAuth;
    }

    // Remove this method since it’s redundant with generateToken
    /*
    public String generateToken(String username, List<String> roles, int expirationInSeconds) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationInSeconds * 1000L);
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .claim("type", "access")
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, secretKey.getBytes(StandardCharsets.UTF_8))
                .compact();
    }
    */
}