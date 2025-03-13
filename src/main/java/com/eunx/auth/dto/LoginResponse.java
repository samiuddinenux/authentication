package com.eunx.auth.dto;

public class LoginResponse {
    private String token;
    private boolean requires2FA; // New field to indicate if 2FA is required

    // Original constructor
    public LoginResponse(String token) {
        this.token = token;
        this.requires2FA = false; // Default to false
    }

    // New constructor for 2FA
    public LoginResponse(String token, boolean requires2FA) {
        this.token = token;
        this.requires2FA = requires2FA;
    }

    // Getters and Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public boolean isRequires2FA() {
        return requires2FA;
    }

    public void setRequires2FA(boolean requires2FA) {
        this.requires2FA = requires2FA;
    }
}