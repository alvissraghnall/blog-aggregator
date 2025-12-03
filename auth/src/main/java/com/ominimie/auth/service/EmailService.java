package com.ominimie.auth.service;

public interface EmailService {
    void sendVerificationEmail(String email, String verificationToken);
}
