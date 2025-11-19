package com.ominimie.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.UnsupportedEncodingException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Value("${spring.mail.username}")
    private String senderEmail;

    @Override
    public void sendVerificationEmail(String email, String verificationToken) {
        String verificationUrl = frontendUrl + "/verify-email?token=" + verificationToken;

        String subject = "Verify Your Ominimie Account";
        String htmlContent = buildVerificationEmail(email, verificationUrl);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "UTF-8");
            helper.setFrom(senderEmail, "Ominimie Blog Aggregator");
            helper.setTo(email);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Verification email sent to {}", email);

        } catch (MessagingException e) {
            log.error("Failed to send email to {}", email, e);
        } catch (UnsupportedEncodingException e) {
            log.error("Failed to send email to {}", email, e);
        }
    }

    private String buildVerificationEmail(String email, String verificationUrl) {
        return """
        <div style="font-family: Arial, sans-serif; background-color:#f4f6f8; padding:40px;">
            <div style="max-width:600px; margin:auto; background:white; padding:30px; border-radius:10px; 
                 box-shadow:0 4px 10px rgba(0,0,0,0.1);">
                
                <h2 style="text-align:center; color:#333;">Welcome to <span style="color:#4B7BEC;">Ominimie</span></h2>
                
                <p style="font-size:15px; color:#555;">
                    Hello <b>%s</b>,<br><br>
                    Thank you for signing up for <b>Ominimie</b> — your personal blog aggregator.
                </p>
                
                <p style="font-size:15px; color:#555;">
                    Please verify your email address by clicking the button below:
                </p>
                
                <div style="text-align:center; margin:30px 0;">
                    <a href="%s" 
                       style="background:#4B7BEC; color:white; padding:12px 25px; text-decoration:none; 
                              border-radius:5px; display:inline-block; font-size:16px;">
                       Verify Email
                    </a>
                </div>

                <p style="font-size:14px; color:#888;">
                    If you did not create this account, you can safely ignore this email.
                </p>
                
                <hr style="margin:30px 0;">
                
                <p style="font-size:12px; text-align:center; color:#aaa;">
                    &copy; %d Ominimie Blog Aggregator. All rights reserved.
                </p>
            </div>
        </div>
        """.formatted(email, verificationUrl, java.time.Year.now().getValue());
    }
}
