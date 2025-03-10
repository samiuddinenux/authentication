package com.eunx.auth.service;

import com.eunx.auth.dto.LoginRequest;
import com.eunx.auth.dto.UserRequest;
import com.eunx.auth.entity.Users;
import com.eunx.auth.repository.UserRepository;
import com.eunx.auth.config.JwtTokenProvider;
import com.eunx.auth.exception.CustomException;
import com.eunx.auth.util.EmailUtil;
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

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private EmailUtil emailUtil;

    @Autowired
    private BlacklistService blacklistService;

    private final Map<String, String> otpStore = new HashMap<>();
    private final Map<String, UserRequest> pendingRegistrations = new HashMap<>();
    private final Map<String, String> resetOtpStore = new HashMap<>();

    public void preRegisterUser(UserRequest userRequest) throws MessagingException {
        if (!EmailUtil.isValidEmail(userRequest.getEmail())) {
            throw new CustomException("Invalid email format.", HttpStatus.BAD_REQUEST);
        }
        if (userRepository.findByUsername(userRequest.getUsername()) != null) {
            throw new CustomException("Username is already taken.", HttpStatus.CONFLICT);
        }
        if (userRepository.findByEmail(userRequest.getEmail()) != null) {
            throw new CustomException("Email is already taken.", HttpStatus.CONFLICT);
        }
        pendingRegistrations.put(userRequest.getEmail(), userRequest);
        String otp = generateOtp();
        otpStore.put(userRequest.getEmail(), otp);
        emailUtil.sendOtpEmail(userRequest.getEmail(), otp);
        System.out.println("Generated OTP for registration: " + otp);
    }

    public void resendOtp(String email) throws MessagingException {
        if (!pendingRegistrations.containsKey(email)) {
            throw new CustomException("No pending registration found.", HttpStatus.BAD_REQUEST);
        }
        String otp = generateOtp();
        otpStore.put(email, otp);
        emailUtil.sendOtpEmail(email, otp);
        System.out.println("Resent OTP: " + otp);
    }

    public String completeRegistration(String email, String otp) {
        if (otpStore.containsKey(email) && otpStore.get(email).equals(otp)) {
            UserRequest pendingUser = pendingRegistrations.get(email);
            if (pendingUser == null) {
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
            return "User registered successfully!";
        }
        throw new CustomException("Invalid OTP.", HttpStatus.BAD_REQUEST);
    }

    private String generateOtp() {
        Random random = new Random();
        return String.valueOf(100000 + random.nextInt(900000));
    }

    public String authenticateUser(LoginRequest loginRequest) {
        Users user = userRepository.findByUsername(loginRequest.getUsername());
        if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new CustomException("Invalid credentials.", HttpStatus.UNAUTHORIZED);
        }
        if (!user.isEmailVerified()) {
            throw new CustomException("Email not verified.", HttpStatus.FORBIDDEN);
        }
        return jwtTokenProvider.generateToken(user.getUsername(), user.getRoles());
    }

    public void logoutUser(String token) {
        if (!jwtTokenProvider.validateToken(token)) {
            throw new CustomException("Invalid token.", HttpStatus.UNAUTHORIZED);
        }
        blacklistService.blacklistToken(token);
    }

    public void requestPasswordReset(String email) throws MessagingException {
        Users user = userRepository.findByEmail(email);
        if (user == null) {
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        String otp = generateOtp();
        resetOtpStore.put(email, otp);
        emailUtil.sendOtpEmail(email, otp);
        System.out.println("Generated OTP for password reset: " + otp);
    }

    public boolean verifyResetOtp(String email, String otp) {
        if (resetOtpStore.containsKey(email) && resetOtpStore.get(email).equals(otp)) {
            resetOtpStore.put(email, "VERIFIED");
            System.out.println("OTP verified successfully for: " + email);
            return true;
        }
        System.out.println("OTP verification failed for: " + email);
        return false;
    }

    public void changeUserPassword(String username, String currentPassword, String newPassword, String confirmPassword) {
        Users user = userRepository.findByUsername(username);
        if (user == null) {
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new CustomException("Current password is incorrect.", HttpStatus.UNAUTHORIZED);
        }
        if (!newPassword.equals(confirmPassword)) {
            throw new CustomException("New password and confirm password do not match.", HttpStatus.BAD_REQUEST);
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public void resetPassword(String email, String newPassword) {
        if (!resetOtpStore.containsKey(email) || !resetOtpStore.get(email).equals("VERIFIED")) {
            throw new CustomException("Reset request not verified.", HttpStatus.BAD_REQUEST);
        }
        Users user = userRepository.findByEmail(email);
        if (user == null) {
            throw new CustomException("User not found.", HttpStatus.NOT_FOUND);
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        resetOtpStore.remove(email);
    }

    // Added method to fix compilation error
    public Users findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}