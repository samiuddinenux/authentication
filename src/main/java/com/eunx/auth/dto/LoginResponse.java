package com.eunx.auth.dto;

public class LoginResponse {
    private String token;         // Access token (pre-auth token or full JWT depending on context)
    private String refreshToken;  // Refresh token (only provided after 2FA verification or if 2FA is not required)
    private boolean requires2FA;  // Indicates if 2FA verification is needed

    // Constructor for pre-auth token after login (2FA required, no refresh token yet)
    public LoginResponse(String token, boolean requires2FA) {
        this.token = token;
        this.refreshToken = null; // No refresh token until 2FA is verified
        this.requires2FA = requires2FA;
    }

    // Constructor for full access (token + refresh token, no 2FA required)
    public LoginResponse(String token, String refreshToken, boolean requires2FA) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.requires2FA = requires2FA;
    }

    // Legacy constructor (for backward compatibility, e.g., no refresh token)
    public LoginResponse(String token) {
        this.token = token;
        this.refreshToken = null;
        this.requires2FA = false;
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