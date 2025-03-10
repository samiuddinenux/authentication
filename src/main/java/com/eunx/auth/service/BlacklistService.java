package com.eunx.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
@Service
public class BlacklistService {

    private Set<String> blacklistedTokens = new HashSet<>();

    // Simulate a database or cache for blacklisted tokens
    public boolean isTokenBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }

    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }

    public void removeTokenFromBlacklist(String token) {
        blacklistedTokens.remove(token);
    }
}

