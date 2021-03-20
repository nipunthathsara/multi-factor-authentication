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
import org.open.security.mf.authenticator.util.TOTPUtils;
import org.open.security.mf.authenticator.util.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

import static org.open.security.mf.authenticator.constant.Constants.Error.OPEN_SEC_MF_010;

/**
 * This class implements the {@link TOTPService} interface.
 */
@Service
public class TOTPServiceImpl implements TOTPService {

    @Autowired
    TOTPUtils totpUtils;

    @Override
    public String generateSecret() throws OpenSecurityMfException {

        return totpUtils.createCredentials();
    }

    @Override
    public boolean validateCode(String secret, int code) throws OpenSecurityMfException {

        if (secret == null) {
            throw Utils.handleException(OPEN_SEC_MF_010, "Secret null");
        }
        return (code > 0 && code < totpUtils.getKeyModulus()) && totpUtils
                .checkCode(secret, code, (new Date()).getTime());
    }
}
