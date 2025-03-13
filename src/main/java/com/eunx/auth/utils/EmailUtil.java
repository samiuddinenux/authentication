package com.eunx.auth.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Date;

@Component
public class EmailUtil {

    @Autowired
    private JavaMailSender mailSender;

    // Basic email format validation
    public static boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
        return email.matches(emailRegex);
    }
    public void sendLoginAttemptNotification(String toEmail, String deviceInfo) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(toEmail);
        helper.setSubject("New Login Attempt Detected");
        helper.setText(
                "Dear User,\n\n" +
                        "We detected a login attempt from a new device:\n" +
                        "Device Info: " + deviceInfo + "\n" +
                        "Time: " + new Date() + "\n\n" +
                        "Your previous session has been invalidated for security reasons. " +
                        "If this was not you, please secure your account immediately.\n\n" +
                        "Regards,\nYour App Team",
                false
        );
        mailSender.send(message);
    }
    // Actual OTP email sending
    public boolean sendOtpEmail(String email, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("samiuddinbirgoshi@gmail.com"); // Set the valid "from" email address
            message.setTo(email);
            message.setSubject("Your OTP for Registration");
            message.setText("Your OTP is: " + otp);
            mailSender.send(message);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
