package com.eunx.auth.controller;

import com.eunx.auth.config.JwtTokenProvider;
import com.eunx.auth.dto.*;
import com.eunx.auth.entity.Users;
import com.eunx.auth.exception.CustomException;
import com.eunx.auth.service.BlacklistService;
import com.eunx.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final BlacklistService blacklistService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RestTemplate restTemplate;

    @Value("${kyc.service.url:http://localhost:8081/api/kyc}")
    private String kycServiceUrl;
    @Autowired
    public AuthController(UserService userService, BlacklistService blacklistService,
                          JwtTokenProvider jwtTokenProvider, RestTemplate restTemplate) {
        this.userService = userService;
        this.blacklistService = blacklistService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.restTemplate = restTemplate;
    }
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(@Valid @RequestBody UserRequest userRequest) {
        try {
            log.info("Registering new user with username: {}", userRequest.getUsername());
            userService.preRegisterUser(userRequest);
            return ResponseEntity.ok(new ApiResponse<>("Registration initiated. OTP sent to email.",
                    "Registration initiated", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Registration failed for username: {}. Error: {}", userRequest.getUsername(), e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(null, e.getMessage(), e.getStatus().value()));
        } catch (Exception e) {
            log.error("Unexpected error during registration for username: {}", userRequest.getUsername(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(null, "Registration failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/disable-2fa/{username}")
    public ResponseEntity<ApiResponse<String>> disableTwoFactorAuth(@PathVariable String username) {
        try {
            log.info("Disabling 2FA for username: {}", username);
            userService.disable2FA(username);
            return ResponseEntity.ok(new ApiResponse<>("2FA disabled successfully for " + username,
                    "2FA disabled", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Failed to disable 2FA for username: {}. Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        } catch (Exception e) {
            log.error("Unexpected error while disabling 2FA for username: {}", username, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("An error occurred while disabling 2FA", HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<String>> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest,
                                                              @RequestHeader("Authorization") String token) {
        try {
            String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
            log.info("Changing password for username: {}", username);
            userService.changeUserPassword(username, changePasswordRequest.getCurrentPassword(),
                    changePasswordRequest.getNewPassword(), changePasswordRequest.getConfirmPassword());
            return ResponseEntity.ok(new ApiResponse<>("Password changed successfully.",
                    "Password changed", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Password change failed for token: {}. Error: {}", token, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        } catch (Exception e) {
            log.error("Unexpected error during password change: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Password change failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/resend-otp")
    public ResponseEntity<ApiResponse<String>> resendOtp(@RequestParam String email) {
        try {
            log.info("Resending OTP to email: {}", email);
            userService.resendOtp(email);
            return ResponseEntity.ok(new ApiResponse<>("OTP resent to email.",
                    "OTP resent", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Failed to resend OTP to email: {}. Error: {}", email, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        } catch (MessagingException e) {
            log.error("Messaging error during OTP resend to email: {}", email, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Failed to resend OTP: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse<String>> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        try {
            log.info("Verifying OTP for email: {}", email);
            String message = userService.completeRegistration(email, otp);
            return ResponseEntity.ok(new ApiResponse<>(message, "OTP verified", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("OTP verification failed for email: {}. Error: {}", email, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest loginRequest,
            @RequestHeader(value = "User-Agent", defaultValue = "unknown") String deviceInfo) {
        log.info("Login attempt with identifier: {}", loginRequest.getIdentifier());
        try {
            LoginResponse response = userService.authenticateUser(loginRequest, deviceInfo);
            return ResponseEntity.ok(new ApiResponse<>(response, "Login initiated", HttpStatus.OK.value()));
        } catch (Exception e) {
            log.error("Login failed for identifier: {}. Error: {}", loginRequest.getIdentifier(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>(null, "Login failed: " + e.getMessage(), HttpStatus.UNAUTHORIZED.value()));
        }
    }
    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest,
                                                                   HttpServletRequest request) {
        try {
            String deviceInfo = getDeviceInfo(request);
            log.info("Refreshing token for request from device: {}", deviceInfo);
            LoginResponse loginResponse = userService.refreshAccessToken(refreshTokenRequest.getRefreshToken(), deviceInfo);
            return ResponseEntity.ok(new ApiResponse<>(loginResponse, "Token refreshed", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Token refresh failed: {}", e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        }
    }

    private String getDeviceInfo(HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        return "IP: " + ipAddress + ", User-Agent: " + (userAgent != null ? userAgent : "Unknown");
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<ApiResponse<LoginResponse>> verify2FA(@RequestParam String username,
                                                                @RequestParam String totpCode,
                                                                @RequestHeader("Authorization") String preAuthToken) {
        try {
            log.info("Verifying 2FA for username: {}", username);
            LoginResponse loginResponse = userService.verify2FA(username, totpCode, preAuthToken.substring(7));
            return ResponseEntity.ok(new ApiResponse<>(loginResponse, "2FA verified, access granted", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("2FA verification failed for username: {}. Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        }
    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<ApiResponse<Map<String, String>>> enable2FA(@RequestHeader("Authorization") String token) {
        try {
            String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
            log.info("Initiating 2FA setup for username: {}", username);
            String secret = userService.enable2FA(username);
            Map<String, String> response = new HashMap<>();
            response.put("secret", secret);
            response.put("qrCodeUrl", generateQrCodeUrl(username, secret));
            return ResponseEntity.ok(new ApiResponse<>(response, "Scan the QR code and verify 2FA", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Failed to initiate 2FA for token: {}. Error: {}", token, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        }
    }
    @PostMapping("/confirm-2fa")
    public ResponseEntity<ApiResponse<String>> confirm2FA(@RequestHeader("Authorization") String token,
                                                          @RequestParam String totpCode) {
        try {
            String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
            log.info("Confirming 2FA setup for username: {}", username);
            userService.confirm2FA(username, totpCode);
            return ResponseEntity.ok(new ApiResponse<>("2FA enabled successfully", "2FA confirmed", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Failed to confirm 2FA for token: {}. Error: {}", token, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        }
    }

    private String generateQrCodeUrl(String username, String secret) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=MyApp", "MyApp", username, secret);
    }

    @GetMapping("/dashboard")
    public ResponseEntity<ApiResponse<String>> dashboard(Authentication authentication) {
        log.info("Dashboard access for user: {}", authentication.getName());
        String message = "Welcome " + authentication.getName() + ", you have access to the dashboard.";
        return ResponseEntity.ok(new ApiResponse<>(message, "Dashboard accessed", HttpStatus.OK.value()));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(@RequestHeader("Authorization") String tokenHeader) {
        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            log.warn("Invalid token format: {}", tokenHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid token format. Please provide a valid Bearer token.", HttpStatus.BAD_REQUEST.value()));
        }
        try {
            String token = tokenHeader.substring(7);
            log.info("Logging out user with token: {}", token);
            userService.logoutUser(token);
            return ResponseEntity.ok(new ApiResponse<>("Logged out successfully.", "Logout successful", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Logout failed for token: {}. Error: {}", tokenHeader, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>("Logout failed: " + e.getMessage(), e.getStatus().value()));
        } catch (Exception e) {
            log.error("Unexpected error during logout: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Logout failed due to server error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<String>> forgotPassword(@RequestParam String email) {
        try {
            log.info("Password reset request for email: {}", email);
            userService.requestPasswordReset(email);
            return ResponseEntity.ok(new ApiResponse<>("Password reset OTP sent to your email.",
                    "Reset OTP sent", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Password reset request failed for email: {}. Error: {}", email, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        } catch (Exception e) {
            log.error("Unexpected error during password reset request: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Failed to send OTP: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping(value = "/verify-reset-otp", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<ApiResponse<String>> verifyResetOtp(@RequestParam String email, @RequestParam String otp) {
        log.info("Verifying reset OTP for email: {}", email);
        if (userService.verifyResetOtp(email, otp)) {
            return ResponseEntity.ok(new ApiResponse<>("OTP verified.", "Reset OTP verified", HttpStatus.OK.value()));
        } else {
            log.warn("Invalid reset OTP for email: {}", email);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid OTP.", HttpStatus.BAD_REQUEST.value()));
        }
    }

    @PostMapping(value = "/reset-forgotten-password", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<ApiResponse<String>> resetForgottenPassword(@RequestParam String email, @RequestParam String newPassword) {
        try {
            log.info("Resetting password for email: {}", email);
            userService.resetPassword(email, newPassword);
            return ResponseEntity.ok(new ApiResponse<>("Password reset successfully.",
                    "Password reset", HttpStatus.OK.value()));
        } catch (CustomException e) {
            log.error("Password reset failed for email: {}. Error: {}", email, e.getMessage(), e);
            return ResponseEntity.status(e.getStatus())
                    .body(new ApiResponse<>(e.getMessage(), e.getStatus().value()));
        }
    }

    @PostMapping("/kyc/initiate")
    public ResponseEntity<ApiResponse<String>> initiateKyc(@RequestHeader("Authorization") String token) {
        String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
        log.info("Initiating KYC for username: {}", username);
        Map<String, String> kycRequest = new HashMap<>();
        kycRequest.put("username", username);
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    kycServiceUrl + "/initiate",
                    new org.springframework.http.HttpEntity<>(kycRequest, createHeaders(token)),
                    String.class
            );
            return ResponseEntity.status(response.getStatusCode())
                    .body(new ApiResponse<>(response.getBody(), "KYC initiated", response.getStatusCode().value()));
        } catch (Exception e) {
            log.error("KYC initiation failed for username: {}. Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("KYC initiation failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @GetMapping("/kyc/status")
    public ResponseEntity<ApiResponse<String>> getKycStatus(@RequestHeader("Authorization") String token) {
        String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
        log.info("Fetching KYC status for username: {}", username);
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(
                    kycServiceUrl + "/status?externalUserId=" + username,
                    String.class
            );
            return ResponseEntity.status(response.getStatusCode())
                    .body(new ApiResponse<>(response.getBody(), "KYC status retrieved", response.getStatusCode().value()));
        } catch (Exception e) {
            log.error("Failed to retrieve KYC status for username: {}. Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>("Failed to retrieve KYC status: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @GetMapping("/user/{username}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getUser(
            @PathVariable String username,
            @RequestHeader("Authorization") String tokenHeader) {
        if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
            log.warn("Invalid token format for getUser request: {}", tokenHeader);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>("Invalid token format. Please provide a valid Bearer token.",
                            HttpStatus.BAD_REQUEST.value()));
        }

        String token = tokenHeader.substring(7);
        try {
            String authenticatedUsername = jwtTokenProvider.getUsernameFromToken(token);
            log.info("Fetching user data for username: {} by authenticated user: {}", username, authenticatedUsername);

            // Optional: Restrict to self-access only (uncomment if needed)
            /*
            if (!authenticatedUsername.equals(username)) {
                log.warn("User {} attempted to access data of user {}", authenticatedUsername, username);
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new ApiResponse<>("You can only access your own user data.",
                                HttpStatus.FORBIDDEN.value()));
            }
            */

            Users user = userService.findByUsername(username);
            if (user == null) {
                log.warn("User not found: {}", username);
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse<>("User not found.", HttpStatus.NOT_FOUND.value()));
            }

            Map<String, Object> userData = new HashMap<>();
            userData.put("username", user.getUsername());
            userData.put("email", user.getEmail());
            return ResponseEntity.ok(new ApiResponse<>(userData, "User data retrieved", HttpStatus.OK.value()));
        } catch (Exception e) {
            log.error("Error fetching user data for username: {}. Error: {}", username, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse<>("Invalid or expired token", HttpStatus.UNAUTHORIZED.value()));
        }
    }

    private org.springframework.http.HttpHeaders createHeaders(String token) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", token);
        return headers;
    }
}