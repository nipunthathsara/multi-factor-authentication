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

package org.open.security.mf.authenticator.constant;

public class Constants {

    public static final String EMAIL_OTP_PLACE_HOLDER = "{{email.otp}}";
    public static final String EMAIL_ADDRESS_PACE_HOLDER = "{{email.address}}";

    public enum Error {

        OPEN_SEC_MF_001("001", "Error sending the email OTP.",
                "Error while sending the email OTP to : %s."),
        OPEN_SEC_MF_002("002", "Invalid OTP",
                "Provided OTP is invalid."),
        OPEN_SEC_MF_003("003", "Expired OTP",
                "Provided OTP is expired already."),
        OPEN_SEC_MF_004("004", "Used OTP",
                "Provided OTP is already used."),
        OPEN_SEC_MF_005("005", "Revoked OTP",
                "Provided OTP is already revoked."),
        OPEN_SEC_MF_006("006", "Invalid TOTP algorithm",
                "Invalid TOTP algorithm : %s."),
        OPEN_SEC_MF_007("007", "Invalid TOTP provider",
                "Invalid TOTP provider : %s."),
        OPEN_SEC_MF_008("008", "Couldn't find algorithm",
                "Couldn't find algorithm."),
        OPEN_SEC_MF_009("009", "Error initializing the algorithm",
                "Error initializing the algorithm.."),
        OPEN_SEC_MF_010("010", "Invalid TOTP secret",
                "Invalid TOTP secret. %s");

        private final String code;
        private final String message;
        private final String description;

        Error(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }

    public enum OTPStatus {

        ACTIVE, EXPIRED, USED, REVOKED;
    }
}
