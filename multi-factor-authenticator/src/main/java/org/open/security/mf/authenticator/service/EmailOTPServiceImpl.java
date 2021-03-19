/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.open.security.mf.authenticator.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.open.security.mf.authenticator.constant.Constants;
import org.open.security.mf.authenticator.exception.OpenSecurityMfException;
import org.open.security.mf.authenticator.model.EmailOTPProperties;
import org.open.security.mf.authenticator.model.OTP;
import org.open.security.mf.authenticator.model.SMTPProperties;
import org.open.security.mf.authenticator.repository.OTPRepository;
import org.open.security.mf.authenticator.util.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.Random;

import static org.open.security.mf.authenticator.constant.Constants.EMAIL_OTP_PLACE_HOLDER;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_001;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_002;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_003;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_004;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_005;

/**
 * This class implements the {@link EmailOTPService} interface.
 */
@Service
public class EmailOTPServiceImpl implements EmailOTPService {

    private final Log log = LogFactory.getLog(EmailOTPServiceImpl.class);

    @Autowired
    private OTPRepository otpRepository;

    @Autowired
    private EmailOTPProperties emailOTPProperties;

    @Autowired
    private SMTPProperties smtpProperties;

    @Override
    public String generateOTP(int length, char[] charset) {

        Random rand = new Random();
        char[] otpSeq = new char[length];
        for (int i = 0; i < length; i++) {
            otpSeq[i] = charset[rand.nextInt(charset.length - 1)];
        }
        return new String(otpSeq);
    }

    @Override
    public void sendEmailOTP(String email) throws OpenSecurityMfException {

        String otp = generateOTP(emailOTPProperties.getLength(), emailOTPProperties.getCharset().toCharArray());
        // Persist generated OTP.
        otpRepository.save(new OTP(email, otp, Constants.OTPStatus.ACTIVE.toString(), calculateExpiry()));
        // Prepare email body.
        String body = emailOTPProperties.getBody().replace(EMAIL_OTP_PLACE_HOLDER, otp);
        sendMail(email, emailOTPProperties.getSubject(), body);
    }

    @Override
    public boolean validateOTP(String otp) throws OpenSecurityMfException {

        OTP otpEntity = otpRepository.findByOTP(otp);
        // Invalid OTP.
        if (otpEntity == null) {
            throw Utils.handleException(OPEN_SEC_MF_002, null);
        }
        // Expired OTP.
        if (System.currentTimeMillis() > otpEntity.getExpiryTime()) {
            throw Utils.handleException(OPEN_SEC_MF_003, null);
        }
        // Used OTP.
        if (Constants.OTPStatus.USED.toString().equals(otpEntity.getStatus())) {
            throw Utils.handleException(OPEN_SEC_MF_004, null);
        }
        // Revoked OTP.
        if (Constants.OTPStatus.REVOKED.toString().equals(otpEntity.getStatus())) {
            throw Utils.handleException(OPEN_SEC_MF_005, null);
        }
        return true;
    }

    private void sendMail(String receiver, String subject, String body) throws OpenSecurityMfException {

        // Set SMTP server configurations.
        Properties prop = new Properties();
        prop.put("mail.smtp.auth", smtpProperties.isAuth());
        prop.put("mail.smtp.starttls.enable", smtpProperties.isStarttls());
        prop.put("mail.smtp.host", smtpProperties.getHost());
        prop.put("mail.smtp.port", smtpProperties.getPort());

        // Whether the SMTP server requires authentication or not.
        Session session = smtpProperties.isAuth() ? Session.getInstance(prop, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtpProperties.getUsername(), smtpProperties.getPassword());
            }
        }) : Session.getInstance(prop);

        // Send email
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(smtpProperties.getUsername()));
            message.setRecipient(Message.RecipientType.TO, new InternetAddress(receiver));
            message.setSubject(subject);
            message.setText(body);
            Transport.send(message);
        } catch (AddressException e) {
            log.error("Error while sending the email to : " + receiver);
            throw Utils.handleException(OPEN_SEC_MF_001, receiver, e);
        } catch (MessagingException e) {
            log.error("Error while sending the email to : " + receiver);
            throw Utils.handleException(OPEN_SEC_MF_001, receiver, e);
        }
    }

    private Long calculateExpiry() {

        return System.currentTimeMillis() + emailOTPProperties.getExpiry() * 1000;
    }
}
