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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_006;
import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_007;

public class TOTPSecureRandom {

    private static final int MAX_OPERATIONS = 1_000_000;
    private final String provider;
    private final String algorithm;
    private final AtomicInteger count = new AtomicInteger(0);
    private SecureRandom secureRandom;

    TOTPSecureRandom(String algorithm, String provider) throws OpenSecurityMfException {

        if (algorithm == null) {
            throw Utils.handleException(OPEN_SEC_MF_006, null);
        } else if (provider == null) {
            throw Utils.handleException(OPEN_SEC_MF_007, null);
        } else {
            this.algorithm = algorithm;
            this.provider = provider;
            this.buildSecureRandom();
        }
    }

    /**
     * Build secure random.
     */
    private void buildSecureRandom() throws OpenSecurityMfException{
        try {
            if (this.algorithm == null && this.provider == null) {
                this.secureRandom = new SecureRandom();
            } else if (this.provider == null) {
                this.secureRandom = SecureRandom.getInstance(this.algorithm);
            } else {
                this.secureRandom = SecureRandom.getInstance(this.algorithm, this.provider);
            }
        } catch (NoSuchAlgorithmException e) {
            throw Utils.handleException(OPEN_SEC_MF_006,
                    String.format("Could not initialise SecureRandom with the specified algorithm : %s. Change "
                                    + "algorithm by system property 'com.wso2.rng.algorithm'.", this.algorithm), e);
        } catch (NoSuchProviderException e) {
            throw Utils.handleException(OPEN_SEC_MF_007,
                    String.format("Could not initialise SecureRandom with the specified provider : %s. Change "
                            + "algorithm by system property 'com.wso2.rng.algorithmProvider'.", this.provider), e);
        }
    }

    /**
     * Generate a user-specified number of random bytes.
     *
     * @param bytes The array to be filled in with random bytes
     */
    void nextBytes(byte[] bytes) throws OpenSecurityMfException {
        if (count.incrementAndGet() > MAX_OPERATIONS) {
            synchronized (this) {
                if (count.get() > MAX_OPERATIONS) {
                    buildSecureRandom();
                    count.set(0);
                }
            }
        }
        this.secureRandom.nextBytes(bytes);
    }
}
