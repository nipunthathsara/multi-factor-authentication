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

import org.open.security.mf.authenticator.exception.OpenSecurityMfException;

/**
 * This interface defines set of functions
 * for email based OTP validation.
 */
public interface EmailOTPService {

    /**
     * Generate a random number according to the given character length.
     *
     * @param length
     * @param charset
     * @return
     */
    String generateOTP(int length, char[] charset);

    /**
     * Send an email OTP notification to the given email address.
     *
     * @param email
     * @throws OpenSecurityMfException
     */
    void sendEmailOTP(String email) throws OpenSecurityMfException;

    /**
     * Validate if the given OTP is valid.
     *
     * @param otp
     * @param email
     * @return true if valid.
     * @throws OpenSecurityMfException
     */
    boolean validateOTP(String otp, String email) throws OpenSecurityMfException;
}
