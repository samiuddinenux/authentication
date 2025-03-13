package com.eunx.auth.dto;

public class LoginResponse {
    private String token;         // Access token
    private String refreshToken;  // New field for refresh token
    private boolean requires2FA;  // Existing field to indicate if 2FA is required

    // Constructor for basic token response (no 2FA, no refresh token explicitly set)
    public LoginResponse(String token) {
        this.token = token;
        this.refreshToken = null; // Default to null if not provided
        this.requires2FA = false; // Default to false
    }

    // Constructor for token with 2FA (no refresh token yet)
    public LoginResponse(String token, boolean requires2FA) {
        this.token = token;
        this.refreshToken = null; // Default to null if not provided
        this.requires2FA = requires2FA;
    }

    // New constructor including refresh token and 2FA
    public LoginResponse(String token, String refreshToken, boolean requires2FA) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.requires2FA = requires2FA;
    }

    // Getters and Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public boolean isRequires2FA() {
        return requires2FA;
    }

    public void setRequires2FA(boolean requires2FA) {
        this.requires2FA = requires2FA;
    }
}