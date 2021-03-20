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

package com.open.security.mf.demo.service;

import com.open.security.mf.demo.exception.DemoAppException;
import com.open.security.mf.demo.model.Credential;
import com.open.security.mf.demo.util.Utils;
import org.apache.commons.lang3.StringUtils;
import org.open.security.mf.authenticator.exception.OpenSecurityMfException;
import org.open.security.mf.authenticator.service.EmailOTPServiceImpl;
import com.open.security.mf.demo.constant.Constants;
import com.open.security.mf.demo.model.User;
import com.open.security.mf.demo.repository.UserRepository;
import org.open.security.mf.authenticator.service.TOTPServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.UUID;

import static com.open.security.mf.demo.constant.Constants.ACTIVE;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_AUTHENTICATION_REQUIRED_PARAMS;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_AUTHENTICATION_TOTP_CODE_INVALID;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_AUTHENTICATION_TOTP_CODE_VALIDATION;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_AUTHENTICATION_TOTP_REQUIRED_PARAMS;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_AUTHENTICATION_UNVERIFIED_ACCOUNT;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_AUTHENTICATION_WRONG_CRED;
import static com.open.security.mf.demo.constant.Constants.Error.DEMO_ERROR_GENERATING_TOTP_SECRET;

@Service
public class UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    EmailOTPServiceImpl emailOTPService;

    @Autowired
    TOTPServiceImpl totpService;

    public void createUser(User user) {

        user.setId(UUID.randomUUID().toString());
        user.setStatus(Constants.INACTIVE);
        try {
            user.setSecret(totpService.generateSecret());
            userRepository.save(user);
            emailOTPService.sendEmailOTP(user.getEmail());
        } catch (OpenSecurityMfException e) {
            e.printStackTrace();
        }
    }

    public String confirmAccount(String otp, String email) throws DemoAppException {

        try {
            emailOTPService.validateOTP(otp, email);
            userRepository.updateStatus(ACTIVE, email);
        } catch (OpenSecurityMfException e) {
            throw Utils.handleException(Constants.Error.DEMO_INVALID_OTP);
        }
        try {
            return totpService.generateSecret();
        } catch (OpenSecurityMfException e) {
            e.printStackTrace();
            throw Utils.handleException(DEMO_ERROR_GENERATING_TOTP_SECRET);
        }
    }

    public String authenticate(Credential cred) throws DemoAppException {

        if (cred == null || StringUtils.isBlank(cred.getEmail()) || StringUtils.isBlank(cred.getPassword())) {
            throw Utils.handleException(DEMO_ERROR_AUTHENTICATION_REQUIRED_PARAMS);
        }
        User user = userRepository.authenticate(cred.getEmail(), cred.getPassword());
        if (user == null) {
            throw Utils.handleException(DEMO_ERROR_AUTHENTICATION_WRONG_CRED);
        }
        if (!ACTIVE.equals(user.getStatus())) {
            throw Utils.handleException(DEMO_ERROR_AUTHENTICATION_UNVERIFIED_ACCOUNT);
        }
        return user.getEmail();
    }

    public String validateTOTPCode(String email, String code) throws DemoAppException {

        if (StringUtils.isBlank(email) || StringUtils.isBlank(code)) {
            throw Utils.handleException(DEMO_ERROR_AUTHENTICATION_TOTP_REQUIRED_PARAMS);
        }
        User user = userRepository.findByEmail(email);
        boolean isValid;
        try {
            isValid = totpService.validateCode(user.getSecret(), Integer.valueOf(code));
        } catch (OpenSecurityMfException e) {
            throw Utils.handleException(DEMO_ERROR_AUTHENTICATION_TOTP_CODE_VALIDATION);
        }
        if (isValid) {
            throw Utils.handleException(DEMO_ERROR_AUTHENTICATION_TOTP_CODE_INVALID);
        }
        return email;
    }
}
