package com.eunx.auth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Component
public class EmailUtil {

    private static final Logger log = LoggerFactory.getLogger(EmailUtil.class);

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public EmailUtil(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public static boolean isValidEmail(String email) {
        // Implement email validation logic
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
    }

    public void sendOtpEmail(String to, String otp) throws MessagingException {
        log.info("Sending OTP email to: {}", to);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Your OTP for Registration");
            helper.setText("Your OTP is: " + otp);
            mailSender.send(message);
            log.info("OTP email sent successfully to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send OTP email to {}: {}", to, e.getMessage(), e);
            throw e;
        }
    }

    public void sendLoginAttemptNotification(String to, String deviceInfo) throws MessagingException {
        log.info("Sending login attempt notification to: {}", to);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("New Login Attempt Detected");
            helper.setText("A new login attempt was detected from: " + deviceInfo);
            mailSender.send(message);
            log.info("Login attempt notification sent successfully to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send login attempt notification to {}: {}", to, e.getMessage(), e);
            throw e;
        }
    }

    public void send2FAEnabledNotification(String to, String username) throws MessagingException {
        log.info("Sending 2FA enabled notification to: {}", to);
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Two-Factor Authentication Enabled");
            helper.setText("Two-Factor Authentication has been enabled for your account: " + username +
                    ". You will need to verify your identity using 2FA for all future logins.");
            mailSender.send(message);
            log.info("2FA enabled notification sent successfully to: {}", to);
        } catch (MessagingException e) {
            log.error("Failed to send 2FA enabled notification to {}: {}", to, e.getMessage(), e);
            throw e;
        }
    }
}