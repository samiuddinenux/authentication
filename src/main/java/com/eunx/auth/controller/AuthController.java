package com.eunx.auth.controller;

import com.eunx.auth.dto.ChangePasswordRequest;
import com.eunx.auth.dto.LoginRequest;
import com.eunx.auth.dto.LoginResponse;
import com.eunx.auth.dto.UserRequest;
import com.eunx.auth.entity.Users;
import com.eunx.auth.exception.CustomException;
import com.eunx.auth.service.BlacklistService;
import com.eunx.auth.service.UserService;
import com.eunx.auth.config.JwtTokenProvider;
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
        public ResponseEntity<String> register(@RequestBody UserRequest userRequest) {
            try {
                log.info("Registering new user with username: {}", userRequest.getUsername());
                userService.preRegisterUser(userRequest);
                return ResponseEntity.ok("Registration initiated. OTP sent to email.");
            } catch (CustomException e) {
                log.error("Registration failed for username: {}. Error: {}", userRequest.getUsername(), e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(e.getMessage());
            } catch (Exception e) {
                log.error("Unexpected error during registration: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Registration failed: " + e.getMessage());
            }
        }

        @PostMapping("/change-password")
        public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest,
                                                     @RequestHeader("Authorization") String token) {
            try {
                String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
                log.info("Changing password for username: {}", username);
                userService.changeUserPassword(username, changePasswordRequest.getCurrentPassword(),
                        changePasswordRequest.getNewPassword(),
                        changePasswordRequest.getConfirmPassword());
                return ResponseEntity.ok("Password changed successfully.");
            } catch (CustomException e) {
                log.error("Password change failed: {}", e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(e.getMessage());
            } catch (Exception e) {
                log.error("Unexpected error during password change: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Password change failed: " + e.getMessage());
            }
        }

        @PostMapping("/resend-otp")
        public ResponseEntity<String> resendOtp(@RequestParam String email) {
            try {
                log.info("Resending OTP to email: {}", email);
                userService.resendOtp(email);
                return ResponseEntity.ok("OTP resent to email.");
            } catch (CustomException e) {
                log.error("Failed to resend OTP to email: {}. Error: {}", email, e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(e.getMessage());
            } catch (MessagingException e) {
                log.error("Messaging error during OTP resend: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Failed to resend OTP: " + e.getMessage());
            }
        }

        @PostMapping("/verify-otp")
        public ResponseEntity<String> verifyOtp(@RequestParam String email, @RequestParam String otp) {
            try {
                log.info("Verifying OTP for email: {}", email);
                String message = userService.completeRegistration(email, otp);
                return ResponseEntity.ok(message);
            } catch (CustomException e) {
                log.error("OTP verification failed for email: {}. Error: {}", email, e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(e.getMessage());
            }
        }

        @PostMapping("/login")
        public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
            try {
                log.info("Login attempt for username: {}", loginRequest.getUsername());
                String token = userService.authenticateUser(loginRequest);
                return ResponseEntity.ok(new LoginResponse(token));
            } catch (CustomException e) {
                log.error("Login failed for username: {}. Error: {}", loginRequest.getUsername(), e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(null);
            }
        }

        @GetMapping("/dashboard")
        public ResponseEntity<String> dashboard(Authentication authentication) {
            log.info("Dashboard access for user: {}", authentication.getName());
            return ResponseEntity.ok("Welcome " + authentication.getName() + ", you have access to the dashboard.");
        }

        @PostMapping("/logout")
        public ResponseEntity<String> logout(@RequestHeader("Authorization") String tokenHeader) {
            if (tokenHeader == null || !tokenHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Invalid token format. Please provide a valid Bearer token.");
            }

            try {
                String token = tokenHeader.substring(7); // Remove "Bearer " prefix
                userService.logoutUser(token);  // Use UserService to blacklist or invalidate the token

                return ResponseEntity.ok("Logged out successfully.");
            } catch (CustomException e) {
                // CustomException is likely for known errors related to your business logic
                return ResponseEntity.status(e.getStatus())
                        .body("Logout failed: " + e.getMessage());
            } catch (Exception e) {
                // Catch any other unexpected errors
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Logout failed due to server error: " + e.getMessage());
            }
        }

        @PostMapping("/forgot-password")
        public ResponseEntity<String> forgotPassword(@RequestParam String email) {
            try {
                log.info("Password reset request for email: {}", email);
                userService.requestPasswordReset(email);
                return ResponseEntity.ok("Password reset OTP sent to your email.");
            } catch (CustomException e) {
                log.error("Password reset request failed for email: {}. Error: {}", email, e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(e.getMessage());
            } catch (Exception e) {
                log.error("Unexpected error during password reset request: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Failed to send OTP: " + e.getMessage());
            }
        }

        @PostMapping(value = "/verify-reset-otp", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        public ResponseEntity<String> verifyResetOtp(@RequestParam String email, @RequestParam String otp) {
            log.info("Verifying reset OTP for email: {}", email);
            if (userService.verifyResetOtp(email, otp)) {
                return ResponseEntity.ok("OTP verified.");
            } else {
                log.warn("Invalid OTP for email: {}", email);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid OTP.");
            }
        }

        @PostMapping(value = "/reset-forgotten-password", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        public ResponseEntity<String> resetForgottenPassword(@RequestParam String email, @RequestParam String newPassword) {
            try {
                log.info("Resetting password for email: {}", email);
                userService.resetPassword(email, newPassword);
                return ResponseEntity.ok("Password reset successfully.");
            } catch (CustomException e) {
                log.error("Password reset failed for email: {}. Error: {}", email, e.getMessage());
                return ResponseEntity.status(e.getStatus()).body(e.getMessage());
            }
        }

    @PostMapping("/kyc/initiate")
    public ResponseEntity<String> initiateKyc(@RequestHeader("Authorization") String token) {
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
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            log.error("KYC initiation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("KYC initiation failed: " + e.getMessage());
        }
    }

    @GetMapping("/kyc/status")
    public ResponseEntity<String> getKycStatus(@RequestHeader("Authorization") String token) {
        String username = jwtTokenProvider.getUsernameFromToken(token.substring(7));
        log.info("Fetching KYC status for externalUserId: {}", username);

        try {
            ResponseEntity<String> response = restTemplate.getForEntity(
                    kycServiceUrl + "/status?externalUserId=" + username,
                    String.class,
                    createHeaders(token)
            );
            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());
        } catch (Exception e) {
            log.error("Failed to retrieve KYC status: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to retrieve KYC status: " + e.getMessage());
        }
    }

    @GetMapping("/user/{username}")
    public ResponseEntity<Map<String, Object>> getUser(@PathVariable String username) {
        log.info("Fetching user data for username: {}", username);
        Users user = userService.findByUsername(username);
        if (user == null) {
            log.warn("User not found: {}", username);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
        Map<String, Object> userData = new HashMap<>();
        userData.put("username", user.getUsername());
        userData.put("email", user.getEmail());
        return ResponseEntity.ok(userData);
    }

    private org.springframework.http.HttpHeaders createHeaders(String token) {
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", token);
        return headers;
    }
}