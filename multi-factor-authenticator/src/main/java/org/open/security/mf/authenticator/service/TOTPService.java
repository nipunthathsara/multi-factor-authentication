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
 * This interface defines a set of functions to provide TOTP authentication.
 *
 */
public interface TOTPService {

    /**
     * Generate secret key for user.
     *
     * @return
     * @throws OpenSecurityMfException
     */
    String generateSecret() throws OpenSecurityMfException;

    /**
     * Validates a given totp token against its secret.
     *
     * @param secret
     * @param totp
     * @return
     * @throws OpenSecurityMfException
     */
    boolean validateCode(String secret, int totp) throws OpenSecurityMfException;
}
