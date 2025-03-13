package com.eunx.auth.service;

import com.eunx.auth.config.JwtTokenProvider;
import com.eunx.auth.dto.LoginRequest;
import com.eunx.auth.dto.LoginResponse;
import com.eunx.auth.dto.UserRequest;
import com.eunx.auth.entity.Users;
import com.eunx.auth.exception.CustomException;
import com.eunx.auth.repository.UserRepository;
import com.eunx.auth.util.EmailUtil;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtTokenProvider jwtTokenProvider;
    @Autowired private EmailUtil emailUtil;
    @Autowired private BlacklistService blacklistService;

    private final Map<String, String> otpStore = new HashMap<>();
    private final Map<String, UserRequest> pendingRegistrations = new HashMap<>();
    private final Map<String, String> resetOtpStore = new HashMap<>();
    private final Map<String, String> pending2FALogins = new HashMap<>();
    private final Map<String, DeviceSession> refreshTokenStore = new HashMap<>();
    public void preRegisterUser(UserRequest userRequest) throws MessagingException {
        log.debug("Pre-registering user: {}", userRequest.getUsername());
        if (!EmailUtil.isValidEmail(userRequest.getEmail())) {
            log.warn("Invalid email format: {}", userRequest.getEmail());
            throw new CustomException("Invalid email format.", HttpStatus.BAD_REQUEST);
        }
        if (userRepository.findByUsername(userRequest.getUsername()) != null) {
            log.warn("Username already taken: {}", userRequest.getUsername());
            throw new CustomException("Username is already taken.", HttpStatus.CONFLICT);
        }
        if (userRepository.findByEmail(userRequest.getEmail()) != null) {
            log.warn("Email already taken: {}", userRequest.getEmail());
            throw new CustomException("Email is already taken.", HttpStatus.CONFLICT);
        }
        pendingRegistrations.put(userRequest.getEmail(), userRequest);
        String otp = generateOtp();
        otpStore.put(userRequest.getEmail(), otp);
        emailUtil.sendOtpEmail(userRequest.getEmail(), otp);
        log.info("OTP generated and sent to {}: {}", userRequest.getEmail(), otp);
    }

    public void resendOtp(String email) throws MessagingException {
        log.debug("Resending OTP for email: {}", email);
        if (!pendingRegistrations.containsKey(email)) {
            log.warn("No pending registration found for email: {}", email);
            throw new CustomException("No pending registration found.", HttpStatus.BAD_REQUEST);
        }
        String otp = generateOtp();
        otpStore.put(email, otp);
        emailUtil.sendOtpEmail(email, otp);
        log.info("OTP resent to {}: {}", email, otp);
    }
    private static class DeviceSession {
        private String refreshToken;
        private String deviceInfo; // Could be IP, device ID, or user-agent

        public DeviceSession(String refreshToken, String deviceInfo) {
            this.refreshToken = refreshToken;
            this.deviceInfo = deviceInfo;
        }

        public String getRefreshToken() { return refreshToken; }
        public String getDeviceInfo() { return deviceInfo; }
    }
    public String completeRegistration(String email, String otp) {
        log.debug("Completing registration for email: {} with OTP: {}", email, otp);
        if (otpStore.containsKey(email) && otpStore.get(email).equals(otp)) {
            UserRequest pendingUser = pendingRegistrations.get(email);
            if (pendingUser == null) {
                log.warn("No pending registration found for email: {}", email);
                throw new CustomException("No pending registration found.", HttpStatus.BAD_REQUEST);
            }
            Users user = new Users();
            user.setUsername(pendingUser.getUsername());
            user.setEmail(pendingUser.getEmail());
            user.setPassword(passwordEncoder.encode(pendingUser.getPassword()));
            user.setRoles(Collections.singletonList("ROLE_USER"));
            user.setEmailVerified(true);
            userRepository.save(user);
            pendingRegistrations.remove(email);
            otpStore.remove(email);
            log.info("User registered successfully: {}", pendingUser.getUsername());
            return "User registered successfully!";
        }
        log.warn("Invalid OTP for email: {}", email);
        throw new CustomException("Invalid OTP.", HttpStatus.BAD_REQUEST);
    }

    private String generateOtp() {
        Random random = new Random();
        return String.valueOf(100000 + random.nextInt(900000));
    }

    public LoginResponse authenticateUser(LoginRequest loginRequest, String deviceInfo) {
        log.debug("Authenticating user: {} from device: {}", loginRequest.getUsername(), deviceInfo);
        Users user = userRepository.findByUsername(loginRequest.getUsername());
        if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            log.warn("Invalid credentials for username: {}", loginRequest.getUsername());
            throw new CustomException("Invalid credentials.", HttpStatus.UNAUTHORIZED);
        }
        if (!user.isEmailVerified()) {
            log.warn("Email not verified for username: {}", loginRequest.getUsername());
            throw new CustomException("Email not verified.", HttpStatus.FORBIDDEN);
        }

        String username = user.getUsername();
        String accessToken;
        String refreshToken = generateRefreshToken(username); // Direct call to instance method

        DeviceSession existingSession = refreshTokenStore.get(username);
        if (existingSession != null && !existingSession.getDeviceInfo().equals(deviceInfo)) {
            blacklistService.blacklistToken(existingSession.getRefreshToken());
            refreshTokenStore.remove(username);
            try {
                emailUtil.sendLoginAttemptNotification(user.getEmail(), deviceInfo);
                log.info("Notified user {} of login attempt from new device: {}", username, deviceInfo);
            } catch (MessagingException e) {
                log.error("Failed to send notification to {}: {}", user.getEmail(), e.getMessage());
            }
            log.warn("Login attempt from new device rejected for user: {}", username);
            throw new CustomException("Another device is already logged in. Previous session invalidated.", HttpStatus.CONFLICT);
        }

        refreshTokenStore.put(username, new DeviceSession(refreshToken, deviceInfo));

        if (user.isTwoFactorEnabled()) {
            accessToken = jwtTokenProvider.generateToken(username, Collections.singletonList("TEMP_ROLE"), 600);
            pending2FALogins.put(username, accessToken);
            log.info("2FA required, temp token generated for {}: {}", username, accessToken);
        } else {
            accessToken = jwtTokenProvider.generateToken(username, user.getRoles());
            log.info("User authenticated successfully: {}", username);
        }
        return new LoginResponse(accessToken, refreshToken, user.isTwoFactorEnabled());
    }

    private String generateRefreshToken(String username) {
        return jwtTokenProvider.generateRefreshToken(username);
    }

    public LoginResponse refreshAccessToken(String refreshToken, String deviceInfo) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            log.warn("Invalid or expired refresh token");
            throw new CustomException("Invalid or expired refresh token.", HttpStatus.UNAUTHORIZED);
        }

        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        DeviceSession session = refreshTokenStore.get(username);
        if (session == null || !session.getRefreshToken().equals(refreshToken) || !session.getDeviceInfo().equals(deviceInfo)) {
            log.warn("Refresh token not found, mismatched, or from different device for username: {}", username);
            throw new CustomException("Invalid refresh token or device mismatch.", HttpStatus.UNAUTHORIZED);
        }

        Users user = userRepository.findByUsername(username);
        if (user == null) {
            log.warn("User not found for refresh token: {}", username);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }

        String newAccessToken = jwtTokenProvider.generateToken(user.getUsername(), user.getRoles());
        log.info("Access token refreshed successfully for username: {}", username);
        return new LoginResponse(newAccessToken, refreshToken, false);
    }
    public String verify2FA(String username, String totpCode) {
        log.debug("Verifying 2FA for username: {} with code: {}", username, totpCode);
        totpCode = totpCode.trim().replaceAll("\\s+", "");
        Users user = userRepository.findByUsername(username);
        if (user == null) {
            log.warn("User not found: {}", username);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        if (!user.isTwoFactorEnabled()) {
            log.warn("2FA not enabled for username: {}", username);
            throw new CustomException("2FA not enabled.", HttpStatus.BAD_REQUEST);
        }
        boolean isValidCode = verifyTotpCode(user.getTwoFactorSecret(), totpCode);
        if (!isValidCode) {
            log.warn("Invalid 2FA code for username: {}", username);
            throw new CustomException("Invalid 2FA code.", HttpStatus.UNAUTHORIZED);
        }
        String tempToken = pending2FALogins.remove(username);
        if (tempToken == null || !jwtTokenProvider.validateToken(tempToken)) {
            log.warn("2FA session expired or invalid for username: {}", username);
            throw new CustomException("2FA session expired or invalid.", HttpStatus.UNAUTHORIZED);
        }
        String token = jwtTokenProvider.generateToken(user.getUsername(), user.getRoles());
        log.info("2FA verified successfully for username: {}", username);
        return token;
    }

    public String enable2FA(String username) {
        log.debug("Enabling 2FA for username: {}", username);
        Users user = userRepository.findByUsername(username);
        if (user == null) {
            log.warn("User not found: {}", username);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        if (user.isTwoFactorEnabled()) {
            log.warn("2FA already enabled for username: {}", username);
            throw new CustomException("2FA is already enabled.", HttpStatus.BAD_REQUEST);
        }
        String secret = new DefaultSecretGenerator().generate();
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
        log.info("2FA enabled for username: {} with secret: {}", username, secret);
        return secret;
    }

    public void disable2FA(String username) {
        log.debug("Disabling 2FA for username: {}", username);
        Users user = userRepository.findByUsername(username);
        if (user == null) {
            log.warn("User not found: {}", username);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        if (!user.isTwoFactorEnabled()) {
            log.warn("2FA not enabled for username: {}", username);
            throw new CustomException("2FA is not enabled.", HttpStatus.BAD_REQUEST);
        }
        user.setTwoFactorSecret(null);
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
        log.info("2FA disabled for username: {}", username);
    }

    private boolean verifyTotpCode(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
        long currentTime = timeProvider.getTime() / 30;
        log.debug("Verifying TOTP with secret: {}, code: {}, time step: {}", secret, code, currentTime);
        return verifier.isValidCode(secret, code);
    }

    public void logoutUser(String token) {
        log.debug("Logging out user with token: {}", token);
        if (!jwtTokenProvider.validateToken(token)) {
            log.warn("Invalid token for logout: {}", token);
            throw new CustomException("Invalid token.", HttpStatus.UNAUTHORIZED);
        }
        String username = jwtTokenProvider.getUsernameFromToken(token);
        refreshTokenStore.remove(username);
        blacklistService.blacklistToken(token);
        log.info("User logged out successfully with token: {}", token);
    }

    public void requestPasswordReset(String email) throws MessagingException {
        log.debug("Requesting password reset for email: {}", email);
        Users user = userRepository.findByEmail(email);
        if (user == null) {
            log.warn("User not found for email: {}", email);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        String otp = generateOtp();
        resetOtpStore.put(email, otp);
        emailUtil.sendOtpEmail(email, otp);
        log.info("Password reset OTP sent to {}: {}", email, otp);
    }

    public boolean verifyResetOtp(String email, String otp) {
        log.debug("Verifying reset OTP for email: {} with OTP: {}", email, otp);
        if (resetOtpStore.containsKey(email) && resetOtpStore.get(email).equals(otp)) {
            resetOtpStore.put(email, "VERIFIED");
            log.info("Reset OTP verified successfully for email: {}", email);
            return true;
        }
        log.warn("Invalid reset OTP for email: {}", email);
        return false;
    }

    public void changeUserPassword(String username, String currentPassword, String newPassword, String confirmPassword) {
        log.debug("Changing password for username: {}", username);
        Users user = userRepository.findByUsername(username);
        if (user == null) {
            log.warn("User not found: {}", username);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            log.warn("Incorrect current password for username: {}", username);
            throw new CustomException("Current password is incorrect.", HttpStatus.UNAUTHORIZED);
        }
        if (!newPassword.equals(confirmPassword)) {
            log.warn("New password and confirm password do not match for username: {}", username);
            throw new CustomException("New password and confirm password do not match.", HttpStatus.BAD_REQUEST);
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        log.info("Password changed successfully for username: {}", username);
    }

    public void resetPassword(String email, String newPassword) {
        log.debug("Resetting password for email: {}", email);
        if (!resetOtpStore.containsKey(email) || !resetOtpStore.get(email).equals("VERIFIED")) {
            log.warn("Reset request not verified for email: {}", email);
            throw new CustomException("Reset request not verified.", HttpStatus.BAD_REQUEST);
        }
        Users user = userRepository.findByEmail(email);
        if (user == null) {
            log.warn("User not found for email: {}", email);
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        resetOtpStore.remove(email);
        log.info("Password reset successfully for email: {}", email);
    }

    public Users findByUsername(String username) {
        log.debug("Finding user by username: {}", username);
        return userRepository.findByUsername(username);
    }
}