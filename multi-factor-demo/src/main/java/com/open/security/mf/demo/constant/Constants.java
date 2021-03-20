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

package com.open.security.mf.demo.constant;

public class Constants {

    public static final String ACTIVE = "ACTIVE";
    public static final String INACTIVE = "INACTIVE";
    public static final String LOCKED = "LOCKED";


    public enum Error {

        DEMO_INVALID_OTP("001", "Invalid OTP"),
        DEMO_ERROR_VALIDATING_OTP("002", "Error while validating the OTP."),
        DEMO_ERROR_GENERATING_TOTP_SECRET("003", "Error while generating TOTP secret."),
        DEMO_ERROR_AUTHENTICATION_REQUIRED_PARAMS("004", "Required parameters blank."),
        DEMO_ERROR_AUTHENTICATION_WRONG_CRED("005", "Wrong credentials."),
        DEMO_ERROR_AUTHENTICATION_UNVERIFIED_ACCOUNT("006", "Unverified account."),
        DEMO_ERROR_AUTHENTICATION_TOTP_REQUIRED_PARAMS("007", "One time password required."),
        DEMO_ERROR_AUTHENTICATION_TOTP_CODE_VALIDATION("008", "Error while validating TOTP code."),
        DEMO_ERROR_AUTHENTICATION_TOTP_CODE_INVALID("009", "Invalid TOTP code.");

        private final String code;
        private final String message;

        Error(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }
    }
}
