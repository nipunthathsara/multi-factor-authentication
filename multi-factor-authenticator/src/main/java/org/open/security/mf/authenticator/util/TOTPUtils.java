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

package org.open.security.mf.authenticator.util;

import org.open.security.mf.authenticator.exception.OpenSecurityMfException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.Base64;
import org.open.security.mf.authenticator.model.TOTPProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_008;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_009;

@Component
public class TOTPUtils {

    @Autowired
    TOTPProperties totpProperties;

    private static final int SECRET_BITS = 80;
    private static final int SCRATCH_CODES = 5;
    private static final int SCRATCH_CODE_LENGTH = 8;
    private static final int BYTES_PER_SCRATCH_CODE = 4;
    private static final String HMAC_HASH_FUNCTION = "HmacSHA1";
    private int codeDigits = 6;
    private int keyModulus = (int) Math.pow(10.0D, codeDigits);
    private long timeStepSizeInMillis = TimeUnit.SECONDS.toMillis(30L);
    private int windowSize = 3;
    private TOTPSecureRandom secureRandom;

    public TOTPUtils(TOTPProperties totpProperties) throws OpenSecurityMfException {

        this.totpProperties = totpProperties;
        secureRandom = new TOTPSecureRandom(totpProperties.getAlgorithm(), totpProperties.getProvider());
    }

    public int getKeyModulus() {

        return keyModulus;
    }

    public int getWindowSize() {

        return windowSize;
    }

    public String createCredentials() throws OpenSecurityMfException {

        byte[] buffer = new byte[30];
        secureRandom.nextBytes(buffer);
        byte[] secretKey = Arrays.copyOf(buffer, 10);
//        String generatedKey = this.calculateSecretKey(secretKey);
//        int validationCode = this.calculateValidationCode(secretKey);
//        return new TOTPAuthenticatorKey(generatedKey, validationCode);
        return calculateSecretKey(secretKey);
    }

    private String calculateSecretKey(byte[] secretKey) {

        return (new Base64()).encodeToString(secretKey);
    }

    private int calculateValidationCode(byte[] secretKey) throws OpenSecurityMfException {

        return calculateCode(secretKey, 0L);
    }

    private int calculateCode(byte[] key, long tm) throws OpenSecurityMfException {

        // Allocating an array of bytes to represent the specified instant
        // of time.
        byte[] data = new byte[8];
        long value = tm;

        // Converting the instant of time from the long representation to a
        // big-endian array of bytes (RFC4226, 5.2. Description).
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        // Building the secret key specification for the HmacSHA1 algorithm.
        SecretKeySpec signKey = new SecretKeySpec(key, HMAC_HASH_FUNCTION);

        try {
            // Getting an HmacSHA1 algorithm implementation from the Java Cryptography Extension(JCE).
            Mac mac = Mac.getInstance(HMAC_HASH_FUNCTION);

            // Initializing the MAC algorithm.
            mac.init(signKey);

            // Processing the instant of time and getting the encrypted data.
            byte[] hash = mac.doFinal(data);

            // Building the validation code performing dynamic truncation
            // (RFC4226, 5.3. Generating an HOTP value)
            int offset = hash[hash.length - 1] & 0xF;

            // We are using a long because Java hasn't got an unsigned integer type
            // and we need 32 unsigned bits).
            long truncatedHash = 0;

            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;

                // Java bytes are signed but we need an unsigned integer:
                // cleaning off all but the LSB.
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            // Clean bits higher than the 32nd (inclusive) and calculate the
            // module with the maximum validation code value.
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= keyModulus;

            // Returning the validation code to the caller.
            return (int) truncatedHash;
        } catch (NoSuchAlgorithmException e) {
            throw Utils.handleException(OPEN_SEC_MF_008, null, e);
        } catch (InvalidKeyException e) {
            throw Utils.handleException(OPEN_SEC_MF_009, null, e);
        }
    }

    public boolean checkCode(String secret, long code, long timestamp) throws OpenSecurityMfException {

        byte[] decodedKey = this.decodeSecret(secret);
        long timeWindow = this.getTimeWindowFromTime(timestamp);

        for(int i = -((windowSize - 1) / 2); i <= windowSize / 2; ++i) {
            long hash = calculateCode(decodedKey, timeWindow + (long)i);
            if (hash == code) {
                return true;
            }
        }
        return false;
    }

    private byte[] decodeSecret(String secret) {

        Base64 codec64 = new Base64();
        return codec64.decode(secret);
    }

    private long getTimeWindowFromTime(long time) {

        return time / timeStepSizeInMillis;
    }
}
